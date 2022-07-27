/**
* Copyright (C) 2022, NVIDIA CORPORATION & AFFILIATES. ALL RIGHTS RESERVED.
* See file LICENSE for terms.
*/

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "sig.h"

#include <uct/base/uct_iface.h>
#include <uct/base/uct_md.h>
#include <uct/ib/rc/accel/rc_mlx5.inl>
#include <uct/ib/mlx5/dv/ib_mlx5_ifc.h>

typedef struct {
    uct_alloc_method_t     method;
    size_t                 length;
    uct_mem_h              memh;
    struct mlx5dv_devx_obj *sig_mr;
    uint32_t               sig_key;
    size_t                 num_elems;
} uct_ib_mlx5_sig_mp_chunk_hdr_t;


typedef struct {
    uint32_t               hdr_key;
    uint32_t               sig_key;
    void                   *base;
    unsigned               num_elems;
} UCS_S_PACKED uct_ib_mlx5_sig_recv_desc_t;


typedef struct {
    uct_ib_mlx5_sig_t      *sig;
} uct_ib_mlx5_sig_mp_priv_t;


enum {
    MLX5_DIF_SIZE          = 8,
    MLX5_STRIDE_BLOCK_OP   = 0x400,
    MLX5_CPY_GRD_MASK      = 0xc0,
    MLX5_CPY_APP_MASK      = 0x30,
    MLX5_CPY_REF_MASK      = 0x0f,
    MLX5_BSF_INC_REFTAG    = 1 << 6,
    MLX5_BSF_INL_VALID     = 1 << 15,
    MLX5_BSF_REFRESH_DIF   = 1 << 14,
    MLX5_BSF_REPEAT_BLOCK  = 1 << 7,
    MLX5_BSF_APPTAG_ESCAPE = 0x1,
    MLX5_BSF_APPREF_ESCAPE = 0x2,
    MLX5_BSF_OCTO_SIZE     = 4,
    MLX5_UMR_XLT_ALIGNMENT = 64,
    MLX5_UMR_OCTOWORD      = 16,
    MLX5_DIF_CRC           = 0x1,
    MLX5_DIF_IPCS          = 0x2,
    MLX5_MKEY_BSF_EN       = 1 << 30,
    //MLX5_WQE_UMR_CTRL_MKEY_MASK_BSF_ENABLE = 1 << 12,
};


struct uct_ib_mlx5_bsf_inl {
    uint16_t                vld_refresh;
    uint16_t                dif_apptag;
    uint32_t                dif_reftag;
    uint8_t                 sig_type;
    uint8_t                 rp_inv_seed;
    uint8_t                 rsvd[3];
    uint8_t                 dif_inc_ref_guard_check;
    uint16_t                dif_app_bitmask_check;
};


struct uct_ib_mlx5_bsf {
    struct uct_ib_mlx5_bsf_basic {
        uint8_t         bsf_size_sbs;
        uint8_t         check_byte_mask;
        union {
            uint8_t copy_byte_mask;
            uint8_t bs_selector;
            uint8_t rsvd_wflags;
        } wire;
        union {
            uint8_t bs_selector;
            uint8_t rsvd_mflags;
        } mem;
        uint32_t        raw_data_size;
        uint32_t        w_bfs_psv;
        uint32_t        m_bfs_psv;
    } basic;
    struct uct_ib_mlx5_bsf_ext {
        uint32_t        t_init_gen_pro_size;
        uint32_t        rsvd_epi_size;
        uint32_t                w_tfs_psv;
        uint32_t        m_tfs_psv;
    } ext;
    struct uct_ib_mlx5_bsf_inl     w_inl;
    struct uct_ib_mlx5_bsf_inl     m_inl;
};


struct uct_ib_mlx5_seg_repeat_ent {
    uint16_t    stride;
    uint16_t    byte_count;
    uint32_t    memkey;
    uint64_t    va;
};


struct uct_ib_mlx5_seg_repeat_block {
    uint32_t                    byte_count;
    uint32_t                    const_0x400;
    uint32_t                    repeat_count;
    uint16_t                    reserved;
    uint16_t                    num_ent;
};


ucs_status_t uct_ib_mlx5_create_psv(struct ibv_pd *pd, struct mlx5dv_devx_obj **psv_p,
                         uint32_t *index_p)
{
    char out[UCT_IB_MLX5DV_ST_SZ_BYTES(create_psv_out)] = {};
    char in[UCT_IB_MLX5DV_ST_SZ_BYTES(create_psv_in)] = {};
    struct mlx5dv_devx_obj *psv;
    struct mlx5dv_pd dvpd                                = {};
    struct mlx5dv_obj dv                                 = {};

    dv.pd.in   = pd;
    dv.pd.out  = &dvpd;
    mlx5dv_init_obj(&dv, MLX5DV_OBJ_PD);

    UCT_IB_MLX5DV_SET(create_psv_in, in, opcode, UCT_IB_MLX5_CMD_OP_CREATE_PSV);
    UCT_IB_MLX5DV_SET(create_psv_in, in, pd, dvpd.pdn);
    UCT_IB_MLX5DV_SET(create_psv_in, in, num_psv, 1);

    psv = mlx5dv_devx_obj_create(pd->context, in, sizeof(in), out, sizeof(out));
    if (!psv) {
        ucs_debug("mlx5dv_devx_obj_create(PSV) failed, syndrome %x: %m",
                  UCT_IB_MLX5DV_GET(create_psv_out, out, syndrome));
        return UCS_ERR_IO_ERROR;
    }

    *index_p = UCT_IB_MLX5DV_GET(create_psv_out, out, psv0_index);
    *psv_p   = psv;

    return UCS_OK;
}

void uct_ib_mlx5_destroy_psv(struct mlx5dv_devx_obj *psv)
{
    int ret;

    ret = mlx5dv_devx_obj_destroy(psv);
    if (ret) {
        ucs_warn("mlx5dv_devx_obj_destroy(PSV) failed");
    }
}

void uct_ib_mlx5_dump_mr(struct mlx5dv_devx_obj *mr, uint32_t mkey)
{
    char in[UCT_IB_MLX5DV_ST_SZ_BYTES(query_mkey_in)]   = {};
    char out[UCT_IB_MLX5DV_ST_SZ_BYTES(query_mkey_out)] = {};
    int ret;

    UCT_IB_MLX5DV_SET(query_mkey_in, in, opcode, UCT_IB_MLX5_CMD_OP_QUERY_MKEY);
    UCT_IB_MLX5DV_SET(query_mkey_in, in, mkey_index, mkey >> 8);

    ret = mlx5dv_devx_obj_query(mr, in, sizeof(in), out, sizeof(out));
    ucs_assert_always(ret == 0);
    ucs_log_dump_hex_buf_lvl(out, sizeof(out), UCS_LOG_LEVEL_PRINT);
}

ucs_status_t uct_ib_mlx5_reg_mr(uct_ib_mlx5_md_t *md, int list_size,
                                struct mlx5dv_devx_obj **mr_p,
                                uint32_t *mkey)
{
    char in[UCT_IB_MLX5DV_ST_SZ_BYTES(create_mkey_in)]   = {};
    char out[UCT_IB_MLX5DV_ST_SZ_BYTES(create_mkey_out)] = {};
    struct mlx5dv_pd dvpd                                = {};
    struct mlx5dv_obj dv                                 = {};
    struct mlx5dv_devx_obj *mr;
    void *mkc;

    dv.pd.in   = md->super.pd;
    dv.pd.out  = &dvpd;
    mlx5dv_init_obj(&dv, MLX5DV_OBJ_PD);

    UCT_IB_MLX5DV_SET(create_mkey_in, in, opcode, UCT_IB_MLX5_CMD_OP_CREATE_MKEY);
    mkc = UCT_IB_MLX5DV_ADDR_OF(create_mkey_in, in, memory_key_mkey_entry);
    UCT_IB_MLX5DV_SET(mkc, mkc, access_mode_1_0, UCT_IB_MLX5_MKC_ACCESS_MODE_KLMS);
    UCT_IB_MLX5DV_SET(mkc, mkc, free, 1);
    UCT_IB_MLX5DV_SET(mkc, mkc, rw, 1);
    UCT_IB_MLX5DV_SET(mkc, mkc, rr, 1);
    UCT_IB_MLX5DV_SET(mkc, mkc, lw, 1);
    UCT_IB_MLX5DV_SET(mkc, mkc, lr, 1);
    UCT_IB_MLX5DV_SET(mkc, mkc, lr, 1);
    UCT_IB_MLX5DV_SET(mkc, mkc, umr_en, 1);
    UCT_IB_MLX5DV_SET(mkc, mkc, pd, dvpd.pdn);
    UCT_IB_MLX5DV_SET(mkc, mkc, bsf_octword_size, 8);
    UCT_IB_MLX5DV_SET(mkc, mkc, translations_octword_size, list_size);
    UCT_IB_MLX5DV_SET(mkc, mkc, qpn, 0xffffff);

    mr = mlx5dv_devx_obj_create(md->super.dev.ibv_context, in,
                                sizeof(in), out, sizeof(out));
    if (mr == NULL) {
        ucs_debug("mlx5dv_devx_obj_create(CREATE_MKEY, mode=KSM) failed, syndrome %x: %m",
                  UCT_IB_MLX5DV_GET(create_mkey_out, out, syndrome));
        return UCS_ERR_UNSUPPORTED;
    }

    *mr_p = mr;
    *mkey = (UCT_IB_MLX5DV_GET(create_mkey_out, out, mkey_index) << 8);

    return UCS_OK;
}

static uint8_t bs_selector(int block_size)
{
    switch (block_size) {
        case 512:           return 0x1;
        case 520:           return 0x2;
        case 4096:          return 0x3;
        case 4160:          return 0x4;
        case 1073741824:    return 0x5;
        default:            return 0;
    }
}

void*
uct_ib_mlx5_set_bsf(void *seg, uint32_t data_size, uint32_t psv_idx)
{
    struct uct_ib_mlx5_bsf *bsf = seg;
    struct uct_ib_mlx5_bsf_basic *basic = &bsf->basic;
    struct uct_ib_mlx5_bsf_inl *inl;

    memset(bsf, 0, sizeof(*bsf));

    basic->bsf_size_sbs = 1 << 7;
    basic->raw_data_size = htonl(data_size);

    basic->mem.bs_selector = bs_selector(512);
    basic->m_bfs_psv = htonl(psv_idx);

    inl = &bsf->m_inl;
    inl->vld_refresh = htons(MLX5_BSF_INL_VALID);
    inl->rp_inv_seed = MLX5_BSF_REPEAT_BLOCK;
    inl->sig_type = MLX5_DIF_IPCS;

    return UCS_PTR_TYPE_OFFSET(seg, (*bsf));
}

void*
uct_ib_mlx5_set_nobsf(void *seg, uint32_t data_size)
{
    struct uct_ib_mlx5_bsf *bsf = seg;
    struct uct_ib_mlx5_bsf_basic *basic = &bsf->basic;

    memset(bsf, 0, sizeof(*bsf));

    basic->bsf_size_sbs = 1 << 7;
    basic->raw_data_size = htonl(data_size);

    return UCS_PTR_TYPE_OFFSET(seg, (*bsf));
}

void*
uct_ib_mlx5_set_stride_ctrl(void* seg, size_t count, size_t size, size_t num)
{
    struct uct_ib_mlx5_seg_repeat_block *sctrl = seg;

    sctrl->byte_count = htonl(size);
    sctrl->const_0x400 = htonl(MLX5_STRIDE_BLOCK_OP);
    sctrl->repeat_count = htonl(count);
    sctrl->num_ent = htons(num);

    return UCS_PTR_TYPE_OFFSET(seg, (*sctrl));
}

void*
uct_ib_mlx5_set_stride(void* seg, uint32_t lkey, size_t size, void* buff)
{
    struct uct_ib_mlx5_seg_repeat_ent *sentry = seg;

    sentry->byte_count = htons(size);
    sentry->memkey = htonl(lkey);
    sentry->va = htobe64((uintptr_t)buff);
    sentry->stride = htons(size);

    return UCS_PTR_TYPE_OFFSET(seg, (*sentry));
}

void*
uct_ib_mlx5_set_klm(void* seg, uint32_t lkey, size_t size, void* buff)
{
    struct mlx5_wqe_umr_klm_seg *klm = seg;

    klm->byte_count = htonl(size);
    klm->mkey = htonl(lkey);
    klm->address = htobe64((uintptr_t)buff);

    return UCS_PTR_TYPE_OFFSET(seg, (*klm));
}

void* uct_ib_mlx5_sig_umr_round_bb(void *seg)
{
    void *next = (void *)ucs_align_up((uintptr_t)seg, 64);
    memset(seg, 0, UCS_PTR_BYTE_DIFF(seg, next));
    return next;
}

void*
uct_ib_mlx5_sig_umr_start(uct_ib_mlx5_md_t *md, size_t xlt_size,
                          size_t bsf_size, size_t len)
{
    uct_ib_mlx5_txwq_t               *txwq = &md->umr.txwq;
    struct mlx5_wqe_umr_ctrl_seg     *umr_ctrl;
    struct mlx5_wqe_mkey_context_seg *mkey_seg;

    umr_ctrl = UCS_PTR_BYTE_OFFSET(txwq->curr, sizeof(struct mlx5_wqe_ctrl_seg));
    memset(umr_ctrl, 0, sizeof(*umr_ctrl));
    umr_ctrl->flags     = MLX5_WQE_UMR_CTRL_FLAG_INLINE;
    umr_ctrl->mkey_mask = htobe64(MLX5_WQE_UMR_CTRL_MKEY_MASK_FREE |
                                  MLX5_WQE_UMR_CTRL_MKEY_MASK_MKEY |
                                  MLX5_WQE_UMR_CTRL_MKEY_MASK_START_ADDR |
                                  MLX5_WQE_UMR_CTRL_MKEY_MASK_BSF_ENABLE |
                                  MLX5_WQE_UMR_CTRL_MKEY_MASK_LEN);
    umr_ctrl->klm_octowords      = htobe16(xlt_size);
    umr_ctrl->translation_offset = htobe16(bsf_size);

    mkey_seg = UCS_PTR_TYPE_OFFSET(umr_ctrl, (*umr_ctrl));
    mkey_seg = uct_ib_mlx5_txwq_wrap_exact(txwq, mkey_seg);
    memset(mkey_seg, 0, sizeof(*mkey_seg));
    mkey_seg->translations_octword_size = htonl(xlt_size);
    mkey_seg->bsf_octword_size          = htonl(bsf_size);
    mkey_seg->len                       = htobe64(len);
    if (bsf_size > 0) {
        mkey_seg->flags_pd = htonl(MLX5_MKEY_BSF_EN);
    }

    return UCS_PTR_TYPE_OFFSET(mkey_seg, (*mkey_seg));
}

ucs_status_t
uct_ib_mlx5_sig_umr_send(uct_ib_mlx5_md_t *md, void* wqe, uint32_t lkey)
{
    uct_ib_mlx5_txwq_t               *txwq = &md->umr.txwq;
    size_t wqe_size = UCS_PTR_BYTE_DIFF(txwq->curr, wqe);
    struct mlx5_cqe64 *cqe;
    struct mlx5_wqe_ctrl_seg         *ctrl;
    uint16_t hw_ci;
    int err = 0;

    ctrl     = txwq->curr;
    wqe_size = uct_ib_mlx5_txwq_diff(txwq, ctrl, wqe);
    uct_ib_mlx5_set_ctrl_seg_with_imm(ctrl, txwq->sw_pi, MLX5_OPCODE_UMR, 0,
            txwq->super.qp_num, MLX5_WQE_CTRL_CQ_UPDATE, wqe_size, htobe32(lkey));

    uct_ib_mlx5_post_send(txwq, ctrl, wqe_size, 1);
    txwq->sig_pi = txwq->prev_sw_pi;

    do {
        ucs_memory_cpu_load_fence();
        cqe = uct_ib_mlx5_peek_cq(&md->umr.cq.mlx5, &err);
        if (err) {
            ucs_log_dump_hex_buf_lvl(cqe, sizeof(*cqe), UCS_LOG_LEVEL_WARN);
            ucs_log_dump_hex_buf_lvl(ctrl, wqe_size, UCS_LOG_LEVEL_WARN);
            ucs_warn("UMR failed");
            return UCS_ERR_IO_ERROR;
        }
    } while (cqe == NULL);

    hw_ci = ntohs(cqe->wqe_counter);
    ucs_assert(txwq->sig_pi == hw_ci);
    uct_ib_mlx5_txwq_update_bb(&md->umr.txwq, hw_ci);
    uct_ib_mlx5_update_db_cq_ci(&md->umr.cq.mlx5);

    return UCS_OK;
}

ucs_status_t uct_ib_mlx5_sig_mp_chunk_alloc(ucs_mpool_t *mp, size_t *size_p,
                                            void **chunk_p)
{
    uct_ib_mlx5_sig_mp_priv_t *priv = ucs_mpool_priv(mp);
    uct_ib_mlx5_sig_t *sig = priv->sig;
    uct_ib_mlx5_md_t *md = sig->md;
    uct_ib_mlx5_txwq_t *txwq = &md->umr.txwq;
    uct_ib_mlx5_sig_mp_chunk_hdr_t *hdr;
    unsigned num_elems;
    ucs_status_t status;
    size_t length;
    uct_allocated_memory_t mem;
    size_t desc_len = sig->payload_offset;
    void *wqe, *buff;
    uint32_t buff_mkey;

    num_elems = *size_p / desc_len;
    length = (desc_len + 520 * 16) * num_elems + sizeof(*hdr) + sizeof(ucs_mpool_chunk_t);
    status = uct_mem_alloc_reg(&md->super.super, length,
                               UCT_MD_MEM_ACCESS_ALL | UCT_MD_MEM_FLAG_LOCK,
                               sig->num_alloc_methods, sig->alloc_methods,
                               ucs_mpool_name(mp), &mem);
    if (status != UCS_OK) {
        return status;
    }

    hdr            = mem.address;
    hdr->method    = mem.method;
    hdr->length    = mem.length;
    hdr->memh      = mem.memh;
    hdr->num_elems = num_elems;
    *chunk_p       = UCS_PTR_TYPE_OFFSET(hdr, (*hdr));
    buff_mkey      = uct_ib_memh_get_lkey(hdr->memh);
    buff           = UCS_PTR_TYPE_OFFSET(*chunk_p, ucs_mpool_chunk_t);

    status = uct_ib_mlx5_reg_mr(md, 4, &hdr->sig_mr, &hdr->sig_key);
    if (status != UCS_OK) {
        ucs_warn("");
        goto err;
    }


    wqe = uct_ib_mlx5_sig_umr_start(md, 4, 4, 520 * 16 * num_elems);
    wqe = uct_ib_mlx5_txwq_wrap_exact(txwq, wqe);
    wqe = uct_ib_mlx5_set_stride_ctrl(wqe, 16 * num_elems, 520, 2);
    buff = UCS_PTR_BYTE_OFFSET(buff, num_elems * desc_len);
    wqe = uct_ib_mlx5_set_stride(wqe, buff_mkey, 512, buff);
    buff = UCS_PTR_BYTE_OFFSET(buff, num_elems * 512 * 16);
    wqe = uct_ib_mlx5_set_stride(wqe, buff_mkey, 8, buff);
    wqe = uct_ib_mlx5_sig_umr_round_bb(wqe);
    wqe = uct_ib_mlx5_txwq_wrap_exact(txwq, wqe);
    wqe = uct_ib_mlx5_set_bsf(wqe, 512 * 16 * num_elems, sig->psv_idx);
    status = uct_ib_mlx5_sig_umr_send(md, wqe, hdr->sig_key);
    if (status != UCS_OK) {
        ucs_warn("");
        goto err;
    }

    return UCS_OK;

err:
    return status;
}

void uct_ib_mlx5_sig_mp_chunk_release(ucs_mpool_t *mp, void *chunk)
{
    uct_ib_mlx5_sig_mp_priv_t *priv = ucs_mpool_priv(mp);
    uct_ib_mlx5_sig_t *sig = priv->sig;
    uct_ib_mlx5_sig_mp_chunk_hdr_t *hdr;
    uct_allocated_memory_t mem;

    hdr = UCS_PTR_BYTE_OFFSET(chunk, -sizeof(*hdr));

    mem.address = hdr;
    mem.method  = hdr->method;
    mem.memh    = hdr->memh;
    mem.length  = hdr->length;
    mem.md      = &sig->md->super.super;

    uct_iface_mem_free(&mem);
}

static void uct_ib_mlx5_sig_mp_obj_init(ucs_mpool_t *mp, void *obj, void *chunk)
{
    uct_ib_mlx5_sig_mp_chunk_hdr_t *hdr = UCS_PTR_BYTE_OFFSET(chunk, -sizeof(*hdr));
    uct_ib_mlx5_sig_recv_desc_t *desc   = obj;

    desc->base = chunk + sizeof(ucs_mpool_chunk_t);
    desc->num_elems = hdr->num_elems;
    desc->hdr_key = uct_ib_memh_get_lkey(hdr->memh);
    desc->sig_key = hdr->sig_key;
}

static void uct_ib_mlx5_sig_mp_obj_cleanup(ucs_mpool_t *mp, void *obj)
{
}

static ucs_mpool_ops_t uct_ib_mlx5_sig_mpool_ops = {
    .chunk_alloc   = uct_ib_mlx5_sig_mp_chunk_alloc,
    .chunk_release = uct_ib_mlx5_sig_mp_chunk_release,
    .obj_init      = uct_ib_mlx5_sig_mp_obj_init,
    .obj_cleanup   = uct_ib_mlx5_sig_mp_obj_cleanup,
    .obj_str       = NULL
};

unsigned uct_ib_mlx5_sig_post_recv(uct_ib_mlx5_sig_t *sig)
{
    uct_ib_mlx5_srq_t *srq   = sig->srq;
    uct_ib_mlx5_sig_recv_desc_t *desc = NULL;
    uct_ib_mlx5_srq_seg_t *seg;
    uint16_t count = 0, wqe_index, next_index;
    size_t desc_len = sig->payload_offset;
    size_t UCS_V_UNUSED hdr_size = desc_len - sig->hdr_offset;
    void *hdr, UCS_V_UNUSED *data, UCS_V_UNUSED *sign;
    unsigned idx;

    wqe_index = srq->ready_idx;
#if 0
    for (;;) {
        next_index = wqe_index + 1;
        seg = uct_ib_mlx5_srq_get_wqe(srq, next_index);
        if (UCS_CIRCULAR_COMPARE16(next_index, >, srq->free_idx)) {
            if (!seg->srq.free) {
                break;
            }

            ucs_assert(next_index == (uint16_t)(srq->free_idx + 1));
            seg->srq.free  = 0;
            srq->free_idx  = next_index;
        }
#else
    seg = uct_ib_mlx5_srq_get_wqe(srq, wqe_index);
    for (;;) {
        next_index = ntohs(seg->srq.next_wqe_index);
        if (next_index == (srq->free_idx & srq->mask)) {
            break;
        }
        seg = uct_ib_mlx5_srq_get_wqe(srq, next_index);
#endif

        UCT_TL_IFACE_GET_RX_DESC(NULL, sig->mp, desc, break);

        idx = UCS_PTR_BYTE_DIFF(desc->base, desc) / desc_len;
        hdr = UCS_PTR_BYTE_OFFSET(desc, sig->hdr_offset - sizeof(ucs_mpool_elem_t));
        data = UCS_PTR_BYTE_OFFSET(desc->base,  desc->num_elems * desc_len + idx * 512 * 16);
        sign = UCS_PTR_BYTE_OFFSET(desc->base, desc->num_elems * (desc_len + 512 * 16) + idx * 8 * 16);

        VALGRIND_MAKE_MEM_NOACCESS(hdr, hdr_size);
        VALGRIND_MAKE_MEM_NOACCESS(data, 16 * 512);
        VALGRIND_MAKE_MEM_NOACCESS(sign, 16 * 8);

        seg->srq.desc_v    = desc;
        seg->dptr[0].lkey  = htonl(desc->hdr_key);
        seg->dptr[0].addr  = htobe64((uintptr_t)hdr);
        seg->dptr[1].lkey  = htonl(desc->sig_key);
        seg->dptr[1].addr  = htobe64(idx * 512 * 16);

        wqe_index = next_index;
        count++;
    }

    //count = wqe_index - srq->sw_pi;

    uct_ib_mlx5_iface_update_srq_res(srq, wqe_index, count);
    return count;
}

void uct_ib_mlx5_sig_srq_buff_init(uct_ib_mlx5_srq_t *srq, uint32_t head,
                                   uint32_t tail, size_t hdr_size, size_t size)
{
    uct_ib_mlx5_srq_seg_t *seg;
    unsigned i;

    srq->free_idx  = tail;
    srq->ready_idx = UINT16_MAX;
    srq->sw_pi     = UINT16_MAX;
    srq->mask      = tail;
    srq->stride    = uct_ib_mlx5_srq_stride(2);

    for (i = head; i <= tail; ++i) {
        seg = uct_ib_mlx5_srq_get_wqe(srq, i);
        seg->srq.next_wqe_index = htons((i + 1) & tail);
        seg->srq.ptr_mask       = 0;
        seg->srq.free           = 0;
        seg->srq.desc           = NULL;
        seg->dptr[0].byte_count = htonl(hdr_size);
        seg->dptr[1].byte_count = htonl(size);
    }
}

ucs_status_t uct_ib_mlx5_sig_init(uct_ib_mlx5_md_t *md,
                                  const uct_iface_params_t *params,
                                  const uct_ib_iface_config_t *config,
                                  uct_ib_mlx5_srq_t *srq,
                                  ucs_mpool_t *mp,
                                  uct_ib_mlx5_cq_t *cq,
                                  uct_ib_mlx5_sig_t **sig_p)
{
    size_t rx_headroom   = UCT_IFACE_PARAM_VALUE(params, rx_headroom,
                                                 RX_HEADROOM, 0);
    uct_sig_type_t type  = UCT_IFACE_PARAM_VALUE(params, sig.type,
                                                 SIG, UCT_SIG_LAST);
    uct_ib_mlx5_sig_mp_priv_t *priv;
    ucs_status_t status;
    uct_ib_mlx5_srq_attr_t attr          = {};
    size_t grow;
    uct_ib_mlx5_sig_t *sig;

    if (type == UCT_SIG_LAST) {
        *sig_p = NULL;
        return UCS_OK;
    }

    sig = ucs_malloc(sizeof(*sig), "sig");
    if (sig == NULL) {
        status = UCS_ERR_NO_MEMORY;
        goto out;
    }

    sig->md  = md;
    sig->srq = srq;
    sig->mp  = mp;
    sig->cq  = cq;

    attr.sge_num   = 2;
    attr.queue_len = uct_ib_mlx5_srq_max_wrs(config->rx.queue_len, 1);

    if (attr.queue_len < 1024) {
        grow = 1024;
    } else {
        grow = ucs_min((int)(1.1 * attr.queue_len + 0.5),
                       config->rx.mp.max_bufs);
    }

    sig->hdr_offset        = sizeof(ucs_mpool_elem_t) +
                             sizeof(uct_ib_mlx5_sig_recv_desc_t) +
                             sizeof(uct_recv_desc_t) +
                             rx_headroom; //TODO union
    sig->payload_offset    = sig->hdr_offset +
                             sizeof(uct_rc_mlx5_hdr_t) +
                             params->sig.am_header_size;

    sig->max_batch         = config->rx.max_batch;
    sig->num_alloc_methods = config->super.alloc_methods.count;
    sig->alloc_methods     = ucs_malloc(sizeof(uct_alloc_method_t) * sig->num_alloc_methods, "");
    memcpy(sig->alloc_methods, config->super.alloc_methods.methods,
           sizeof(uct_alloc_method_t) * sig->num_alloc_methods);

    sig->desc.super.cb     = uct_ib_mlx5_release_desc;
    sig->desc.offset       = sizeof(uct_ib_mlx5_sig_recv_desc_t) +
                                    sizeof(uct_recv_desc_t) +
                                    sizeof(uct_rc_mlx5_hdr_t);

    status = uct_ib_mlx5_devx_init_rx(md, srq, &attr);
    if (status != UCS_OK) {
        return status;
    }

    uct_ib_mlx5_sig_srq_buff_init(sig->srq, 0, attr.queue_len - 1,
                                  sig->payload_offset -
                                  sig->hdr_offset, 512 * 16);

    status = ucs_mpool_init(mp, sizeof(uct_ib_mlx5_sig_mp_priv_t),
                            sig->payload_offset - sizeof(ucs_mpool_elem_t),
                            0, 1, grow, UINT_MAX,
                            &uct_ib_mlx5_sig_mpool_ops, "sig rx");
    if (status != UCS_OK) {
        return status;
    }

    priv = ucs_mpool_priv(mp);
    priv->sig = sig;

    status = uct_ib_mlx5_create_psv(md->super.pd, &sig->psv, &sig->psv_idx);
    if (status != UCS_OK) {
        return status;
    }

    srq->super.available = srq->super.quota;
    srq->super.quota     = 0;
    uct_ib_mlx5_sig_post_recv(sig);

out:
    *sig_p = sig;
    return status;
}

void uct_ib_mlx5_sig_cleanup(uct_ib_mlx5_sig_t *sig)
{
    uct_ib_mlx5_destroy_psv(sig->psv);
}

static UCS_F_ALWAYS_INLINE ucs_status_t
uct_ib_mlx5_sig_am_handler(uct_ib_iface_t *iface, uct_ib_mlx5_sig_t *sig,
                           struct mlx5_cqe64 *cqe, uct_ib_mlx5_srq_seg_t *seg,
                           uct_rc_mlx5_hdr_t *hdr, void *data, void *sign,
                           unsigned length)
{
    uct_am_handler_t *handler;
    void *buff, *p;
    size_t hdr_size;

    handler = &iface->super.am[hdr->rc_hdr.am_id];

    if (handler->flags & UCT_CB_FLAG_SIG) {
        return handler->cb_sig(handler->arg, hdr + 1, data, sign,
                               length - sizeof(*hdr), UCT_CB_PARAM_FLAG_DESC);
    } else {
        buff = alloca(length);
        p = buff;
        hdr_size = sig->payload_offset - sig->hdr_offset - sizeof(*hdr);

        memcpy(p, hdr + 1, hdr_size);
        p = UCS_PTR_BYTE_OFFSET(p, hdr_size);
        memcpy(p, data, length - hdr_size);
        return handler->cb(handler->arg, buff, length - sizeof(*hdr),
                           UCT_CB_PARAM_FLAG_DESC);
    }
}

unsigned uct_ib_mlx5_poll_sig(uct_ib_iface_t *iface, uct_ib_mlx5_sig_t *sig)
{
    struct mlx5_cqe64 *cqe;
    uct_ib_mlx5_srq_seg_t *seg;
    uct_ib_mlx5_sig_recv_desc_t *desc;
    void *hdr, *data, *sign;
    unsigned idx, byte_len, UCS_V_UNUSED block_num;
    size_t desc_len = sig->payload_offset;
    size_t hdr_size = desc_len - sig->hdr_offset;
    uint16_t wqe_ctr;
    ucs_status_t status;
    int err = 0;
    void *inl;

    cqe = uct_ib_mlx5_peek_cq(sig->cq, &err);
    if (cqe == NULL) {
        return 0;
    }

    ucs_memory_cpu_load_fence();

    wqe_ctr = ntohs(cqe->wqe_counter);

    if (err) {
        ucs_warn("sig poll failure");
        ucs_log_dump_hex_buf_lvl(cqe, sizeof(*cqe), UCS_LOG_LEVEL_WARN);
        seg = uct_ib_mlx5_srq_get_wqe(sig->srq, wqe_ctr);
        ucs_log_dump_hex_buf_lvl(seg, sizeof(*seg) + sizeof(seg->dptr[0]), UCS_LOG_LEVEL_WARN);
        return 0;
    }


    byte_len = ntohl(cqe->byte_cnt) & UCT_IB_MLX5_MP_RQ_BYTE_CNT_MASK;
    seg  = uct_ib_mlx5_srq_get_wqe(sig->srq, wqe_ctr);
    desc = seg->srq.desc_v;
    block_num = (byte_len + sig->hdr_offset - desc_len) / 512;

    idx = UCS_PTR_BYTE_DIFF(desc->base, desc) / desc_len;
    //printf("%s:%d %p %p %d %p\n", __func__, __LINE__, iface, sig->srq, idx, desc->base);
    ucs_assert(desc == UCS_PTR_BYTE_OFFSET(desc->base, idx * desc_len + sizeof(ucs_mpool_elem_t)));
    hdr = UCS_PTR_BYTE_OFFSET(desc, sig->hdr_offset - sizeof(ucs_mpool_elem_t));
    sign = UCS_PTR_BYTE_OFFSET(desc->base, desc->num_elems * (desc_len + 512 * 16) + idx * 8 * 16);
    data = UCS_PTR_BYTE_OFFSET(desc->base,  desc->num_elems * desc_len + idx * 512 * 16);

    VALGRIND_MAKE_MEM_DEFINED(hdr, sizeof(uct_rc_mlx5_hdr_t));
    VALGRIND_MAKE_MEM_DEFINED(sign, block_num * 8);
    VALGRIND_MAKE_MEM_DEFINED(data, block_num * 512);

    if (cqe->op_own & MLX5_INLINE_SCATTER_32) {
        inl = cqe;
    } else if (cqe->op_own & MLX5_INLINE_SCATTER_64) {
        inl = cqe - 1;
    } else {
        inl = NULL;
    }

    if (inl) {
        if (byte_len > hdr_size) {
            memcpy(hdr, inl, hdr_size);
            inl = UCS_PTR_BYTE_OFFSET(inl, hdr_size);
            memcpy(data, inl, byte_len - hdr_size);
        } else {
            memcpy(hdr, inl, byte_len);
        }
    }

    if (0) {
        printf("%s:%d %p %p %d %p\n", __func__, __LINE__, iface, sig->srq, idx, desc->base);
        //ucs_log_dump_hex_buf_lvl(cqe, sizeof(struct mlx5_cqe64), UCS_LOG_LEVEL_PRINT);
        //ucs_log_dump_hex_buf_lvl(seg, 48, UCS_LOG_LEVEL_PRINT);

       // printf("%s:%d %p %p %p %d %d\n", __func__, __LINE__, desc, hdr, data, desc->num_elems, idx);
        ucs_log_dump_hex_buf_lvl(hdr, 16, UCS_LOG_LEVEL_PRINT);
        ucs_log_dump_hex_buf_lvl(data, 64, UCS_LOG_LEVEL_PRINT);
        ucs_log_dump_hex_buf_lvl(sign, 80, UCS_LOG_LEVEL_PRINT);
    }

    status = uct_ib_mlx5_sig_am_handler(iface, sig, cqe, seg, hdr, data, sign,
                                        byte_len);

    uct_ib_mlx5_iface_release_srq_seg(sig->srq, seg, cqe, wqe_ctr, status,
                                      sizeof(uct_ib_mlx5_sig_recv_desc_t) +
                                      sizeof(uct_recv_desc_t) +
                                      sizeof(uct_rc_mlx5_hdr_t),
                                      &sig->desc.super,
                                      UCT_IB_MLX5_POLL_FLAG_LINKED_LIST);

    uct_ib_mlx5_update_db_cq_ci(sig->cq);

    if (ucs_unlikely(sig->srq->super.available >= sig->max_batch)) {
        uct_ib_mlx5_sig_post_recv(sig);
    }

    return 1;
}
