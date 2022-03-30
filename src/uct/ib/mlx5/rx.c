/**
* Copyright (C) 2022, NVIDIA CORPORATION & AFFILIATES. ALL RIGHTS RESERVED.
* See file LICENSE for terms.
*/

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "rx.inl"

#include <uct/base/uct_iface.h>
#include <uct/base/uct_md.h>
#include <uct/ib/mlx5/dv/ib_mlx5_ifc.h>

ucs_status_t
uct_ib_mlx5_devx_init_rx_common(uct_ib_mlx5_md_t *md, uct_ib_mlx5_srq_t *srq,
                                uct_ib_mlx5_srq_attr_t *attr, void *wq)
{
    ucs_status_t status  = UCS_ERR_NO_MEMORY;
    int len, stride, log_num_of_strides, wq_type;

    stride = uct_ib_mlx5_srq_stride(attr->sge_num);
    len    = attr->queue_len * stride;

    status = uct_ib_mlx5_md_buf_alloc(md, len, 0, &srq->buf,
                                      &srq->devx.mem, "srq buf");
    if (status != UCS_OK) {
        return status;
    }

    srq->devx.dbrec = uct_ib_mlx5_get_dbrec(md);
    if (!srq->devx.dbrec) {
        goto err_free_mem;
    }

    srq->db = &srq->devx.dbrec->db[MLX5_RCV_DBR];

    if (attr->topo == UCT_IB_MLX5_SRQ_TOPO_CYCLIC) {
        wq_type = attr->mp ? UCT_IB_MLX5_WQ_TYPE_CYCLIC_MP :
                             UCT_IB_MLX5_WQ_TYPE_CYCLIC;
    } else {
        wq_type = attr->mp ? UCT_IB_MLX5_WQ_TYPE_LINKED_LIST_MP :
                             UCT_IB_MLX5_WQ_TYPE_LINKED_LIST;
    }

    UCT_IB_MLX5DV_SET  (wq, wq, wq_type,       wq_type);
    UCT_IB_MLX5DV_SET  (wq, wq, log_wq_sz,     ucs_ilog2(attr->queue_len));
    UCT_IB_MLX5DV_SET  (wq, wq, log_wq_stride, ucs_ilog2(stride));
    UCT_IB_MLX5DV_SET  (wq, wq, pd,            attr->pdn);
    UCT_IB_MLX5DV_SET  (wq, wq, dbr_umem_id,   srq->devx.dbrec->mem_id);
    UCT_IB_MLX5DV_SET64(wq, wq, dbr_addr,      srq->devx.dbrec->offset);
    UCT_IB_MLX5DV_SET  (wq, wq, wq_umem_id,    srq->devx.mem.mem->umem_id);

    if (attr->mp) {
        /* Normalize to device's interface values (range of (-6) - 7) */
        /* cppcheck-suppress internalAstError */
        log_num_of_strides = ucs_ilog2(attr->sge_num) - 9;

        UCT_IB_MLX5DV_SET(wq, wq, log_wqe_num_of_strides,
                          log_num_of_strides & 0xF);
        UCT_IB_MLX5DV_SET(wq, wq, log_wqe_stride_size,
                          ucs_ilog2(attr->seg_size) - 6);
    }

    srq->super.available = 0;
    srq->super.quota     = attr->queue_len;
    srq->type            = UCT_IB_MLX5_OBJ_TYPE_DEVX;

    return UCS_OK;

err_free_mem:
    uct_ib_mlx5_md_buf_free(md, srq->buf, &srq->devx.mem);
    return status;
}

ucs_status_t
uct_ib_mlx5_devx_init_rx(uct_ib_mlx5_md_t *md, uct_ib_mlx5_srq_t *srq,
                         uct_ib_mlx5_srq_attr_t *attr)
{
    uct_ib_device_t *dev  = &md->super.dev;
    struct mlx5dv_pd dvpd = {};
    struct mlx5dv_obj dv  = {};
    char in[UCT_IB_MLX5DV_ST_SZ_BYTES(create_rmp_in)]   = {};
    char out[UCT_IB_MLX5DV_ST_SZ_BYTES(create_rmp_out)] = {};
    ucs_status_t status;
    void *rmpc;

    dv.pd.in  = md->super.pd;
    dv.pd.out = &dvpd;
    mlx5dv_init_obj(&dv, MLX5DV_OBJ_PD);
    attr->pdn = dvpd.pdn;

    UCT_IB_MLX5DV_SET(create_rmp_in, in, opcode, UCT_IB_MLX5_CMD_OP_CREATE_RMP);
    rmpc = UCT_IB_MLX5DV_ADDR_OF(create_rmp_in, in, rmp_context);

    UCT_IB_MLX5DV_SET(rmpc, rmpc, state, UCT_IB_MLX5_RMPC_STATE_RDY);

    status = uct_ib_mlx5_devx_init_rx_common(md, srq, attr,
                                             UCT_IB_MLX5DV_ADDR_OF(rmpc, rmpc, wq));
    if (status != UCS_OK) {
        return status;
    }

    srq->devx.obj = mlx5dv_devx_obj_create(dev->ibv_context, in, sizeof(in),
                                           out, sizeof(out));
    if (srq->devx.obj == NULL) {
        ucs_error("mlx5dv_devx_obj_create(RMP) failed, syndrome %x: %m",
                  UCT_IB_MLX5DV_GET(create_rmp_out, out, syndrome));
        status = UCS_ERR_IO_ERROR;
        goto err_cleanup_srq;
    }

    srq->srq_num = UCT_IB_MLX5DV_GET(create_rmp_out, out, rmpn);

    return UCS_OK;

err_cleanup_srq:
    uct_ib_mlx5_devx_cleanup_srq(md, srq);
    return status;
}

void uct_ib_mlx5_devx_cleanup_srq(uct_ib_mlx5_md_t *md, uct_ib_mlx5_srq_t *srq)
{
    uct_ib_mlx5_put_dbrec(srq->devx.dbrec);
    uct_ib_mlx5_md_buf_free(md, srq->buf, &srq->devx.mem);
}

ucs_status_t
uct_ib_mlx5_verbs_srq_init(uct_ib_mlx5_srq_t *srq, struct ibv_srq *verbs_srq,
                           size_t sg_byte_count, int sge_num)
{
    uct_ib_mlx5dv_srq_t srq_info = {};
    uct_ib_mlx5dv_t obj          = {};
    uct_ib_mlx5_srq_attr_t attr  = {};
    ucs_status_t status;
    uint16_t stride;

    obj.dv.srq.in         = verbs_srq;
    obj.dv.srq.out        = &srq_info.dv;
#if HAVE_DEVX
    srq_info.dv.comp_mask = MLX5DV_SRQ_MASK_SRQN;
#endif

    status = uct_ib_mlx5dv_init_obj(&obj, MLX5DV_OBJ_SRQ);
    if (status != UCS_OK) {
        return status;
    }

#if HAVE_DEVX
    srq->srq_num = srq_info.dv.srqn;
#else
    srq->srq_num = 0;
#endif

    if (srq_info.dv.head != 0) {
        ucs_error("SRQ head is not 0 (%d)", srq_info.dv.head);
        return UCS_ERR_NO_DEVICE;
    }

    stride = uct_ib_mlx5_srq_stride(sge_num);
    if (srq_info.dv.stride != stride) {
        ucs_error("SRQ stride is not %u (%d), sgenum %d",
                  stride, srq_info.dv.stride, sge_num);
        return UCS_ERR_NO_DEVICE;
    }

    if (!ucs_is_pow2(srq_info.dv.tail + 1)) {
        ucs_error("SRQ length is not power of 2 (%d)", srq_info.dv.tail + 1);
        return UCS_ERR_NO_DEVICE;
    }

    srq->buf       = srq_info.dv.buf;
    srq->db        = srq_info.dv.dbrec;
    attr.seg_size  = sg_byte_count;
    attr.sge_num   = sge_num;
    attr.queue_len = srq_info.dv.tail + 1;
    uct_ib_mlx5_srq_buff_init(srq, &attr);

    return UCS_OK;
}

void uct_ib_mlx5_srq_buff_init(uct_ib_mlx5_srq_t *srq,
                               uct_ib_mlx5_srq_attr_t *attr)
{
    uct_ib_mlx5_srq_seg_t *seg;
    unsigned i, j;

    srq->free_idx  = attr->queue_len - 1;
    srq->ready_idx = UINT16_MAX;
    srq->sw_pi     = UINT16_MAX;
    srq->mask      = attr->queue_len - 1;
    srq->stride    = uct_ib_mlx5_srq_stride(attr->sge_num);

    for (i = 0; i < attr->queue_len; ++i) {
        seg = uct_ib_mlx5_srq_get_wqe(srq, i);
        seg->srq.next_wqe_index = htons((i + 1) & (attr->queue_len - 1));
        seg->srq.ptr_mask       = 0;
        seg->srq.free           = 0;
        seg->srq.desc           = NULL;
        seg->srq.strides        = attr->sge_num;
        for (j = 0; j < attr->sge_num; ++j) {
            seg->dptr[j].byte_count = htonl(attr->seg_size);
        }
    }
}

void uct_ib_mlx5_release_desc(uct_recv_desc_t *self, void *desc)
{
    uct_ib_mlx5_release_desc_t *release = ucs_derived_of(self,
                                                         uct_ib_mlx5_release_desc_t);
    void *ib_desc = (char*)desc - release->offset;
    ucs_mpool_put_inline(ib_desc);
}

