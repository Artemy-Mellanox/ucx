/**
* Copyright (C) 2022, NVIDIA CORPORATION & AFFILIATES. ALL RIGHTS RESERVED.
* See file LICENSE for terms.
*/

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "sig.h"
#include "ib_mlx5_def.h"

#include <uct/base/uct_iface.h>
#include <uct/base/uct_md.h>
#include <uct/ib/mlx5/dv/ib_mlx5_ifc.h>
#include <uct/ib/mlx5/ib_mlx5.inl>

enum {
    UCT_IB_MLX5_STRIDE_BLOCK_OP   = 0x400,
    UCT_IB_MLX5_BSF_INL_VALID     = 1 << 15,
    UCT_IB_MLX5_BSF_REPEAT_BLOCK  = 1 << 7,
    UCT_IB_MLX5_DIF_IPCS          = 0x2,
    UCT_IB_MLX5_MKEY_BSF_EN       = 1 << 30,
    UCT_IB_MLX5_WQE_UMR_CTRL_MKEY_MASK_BSF_ENABLE = 1 << 12,
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
    inl->vld_refresh = htons(UCT_IB_MLX5_BSF_INL_VALID);
    inl->rp_inv_seed = UCT_IB_MLX5_BSF_REPEAT_BLOCK;
    inl->sig_type = UCT_IB_MLX5_DIF_IPCS;

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
    sctrl->const_0x400 = htonl(UCT_IB_MLX5_STRIDE_BLOCK_OP);
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
                                  UCT_IB_MLX5_WQE_UMR_CTRL_MKEY_MASK_BSF_ENABLE |
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
        mkey_seg->flags_pd = htonl(UCT_IB_MLX5_MKEY_BSF_EN);
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

ucs_status_t uct_ib_mlx5_sig_mr_init(uct_ib_mlx5_md_t *md,
                                     uct_ib_mlx5_mem_t *memh)
{
    uct_ib_mlx5_txwq_t *txwq = &md->umr.txwq;
    uct_ib_mlx5_sig_t *sig;
    ucs_status_t status;
    size_t length;
    void *wqe;
    unsigned num_elems;

    sig = ucs_malloc(sizeof(*sig), "sig");
    if (sig == NULL) {
        status = UCS_ERR_NO_MEMORY;
        ucs_warn("");
        goto err;
    }

    sig->mr = memh->mrs[UCT_IB_MR_DEFAULT].super.ib;
    length = sig->mr->length;
    num_elems = length / 512;

    sig->dif = ucs_mmap(NULL, num_elems * 8, PROT_READ|PROT_WRITE,
                        MAP_PRIVATE|MAP_ANONYMOUS, -1, 0, "sig dif");
    if (sig->dif == NULL) {
        status = UCS_ERR_NO_MEMORY;
        ucs_warn("");
        goto err;
    }

    status = uct_ib_reg_mr(md->super.pd, sig->dif, num_elems * 8, UCT_IB_MEM_ACCESS_FLAGS,
            &sig->dif_mr, 0);
    if (status != UCS_OK) {
        goto err;
    }

    status = uct_ib_mlx5_reg_mr(md, 4, &sig->sig_mr, &sig->sig_key);
    if (status != UCS_OK) {
        goto err;
    }

    wqe = uct_ib_mlx5_sig_umr_start(md, 4, 4, 520 * num_elems);
    wqe = uct_ib_mlx5_txwq_wrap_exact(txwq, wqe);
    wqe = uct_ib_mlx5_set_stride_ctrl(wqe, num_elems, 520, 2);
    wqe = uct_ib_mlx5_set_stride(wqe, sig->mr->lkey, 512, sig->mr->addr);
    wqe = uct_ib_mlx5_set_stride(wqe, sig->dif_mr->lkey, 8, sig->dif);
    wqe = uct_ib_mlx5_sig_umr_round_bb(wqe);
    wqe = uct_ib_mlx5_txwq_wrap_exact(txwq, wqe);
    wqe = uct_ib_mlx5_set_bsf(wqe, 512 * num_elems, md->umr.psv.idx);
    status = uct_ib_mlx5_sig_umr_send(md, wqe, sig->sig_key);
    if (status != UCS_OK) {
        ucs_warn("");
        goto err;
    }

    memh->mrs[UCT_IB_MR_SIG].sig_ctx = sig;
    memh->super.flags |= UCT_IB_MEM_SIG;
    printf("%s:%d %x %p %d\n", __func__, __LINE__, sig->sig_key, sig->mr->addr, num_elems);
    return UCS_OK;

err:
    return status;
}

