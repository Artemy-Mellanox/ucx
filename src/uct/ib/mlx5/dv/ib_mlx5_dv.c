/**
* Copyright (C) Mellanox Technologies Ltd. 2001-2018.  ALL RIGHTS RESERVED.
*
* See file LICENSE for terms.
*/

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "ib_mlx5_ifc.h"

#include <uct/ib/mlx5/ib_mlx5.h>
#include <ucs/arch/bitops.h>

#if HAVE_DECL_MLX5DV_INIT_OBJ
ucs_status_t uct_ib_mlx5dv_init_obj(uct_ib_mlx5dv_t *obj, uint64_t type)
{
    int ret;

    ret = mlx5dv_init_obj(&obj->dv, type);
#ifdef HAVE_IBV_EXP_DM
    if (!ret && (type & MLX5DV_OBJ_DM)) {
        ret = uct_ib_mlx5_get_dm_info(obj->dv_dm.in, obj->dv_dm.out);
    }
#endif
    if (ret != 0) {
        ucs_error("DV failed to get mlx5 information. Type %lx.", type);
        return UCS_ERR_NO_DEVICE;
    }

    return UCS_OK;
}
#endif

#if HAVE_DEVX


enum {
    UCT_IB_MLX5_DEVX_RQ_TYPE_REGULAR = 0x0,
    UCT_IB_MLX5_DEVX_RQ_TYPE_XRQ     = 0x1,
    UCT_IB_MLX5_DEVX_RQ_TYPE_NO_RQ   = 0x3
};


static uint32_t uct_ib_mlx5_devx_get_rq_type(const uct_ib_mlx5_qp_attr_t *attr)
{
    if (attr->super.srq_num > 0) {
        return UCT_IB_MLX5_DEVX_RQ_TYPE_XRQ;
    } else if (attr->super.cap.max_recv_wr == 0) {
        return UCT_IB_MLX5_DEVX_RQ_TYPE_NO_RQ;
    } else {
        return UCT_IB_MLX5_DEVX_RQ_TYPE_REGULAR;
    }
}

ucs_status_t uct_ib_mlx5_devx_create_qp(uct_ib_mlx5_md_t *md,
                                        uct_ib_mlx5_qp_t *qp,
                                        uct_ib_mlx5_txwq_t *tx,
                                        uct_ib_mlx5_qp_attr_t *attr)
{
    uct_ib_device_t *dev   = &md->super.dev;
    struct mlx5dv_pd dvpd  = {};
    struct mlx5dv_cq dvscq = {};
    struct mlx5dv_cq dvrcq = {};
    struct mlx5dv_obj dv   = {};
    char in[UCT_IB_MLX5DV_ST_SZ_BYTES(create_qp_in)]           = {};
    char out[UCT_IB_MLX5DV_ST_SZ_BYTES(create_qp_out)]         = {};
    char in_2init[UCT_IB_MLX5DV_ST_SZ_BYTES(rst2init_qp_in)]   = {};
    char out_2init[UCT_IB_MLX5DV_ST_SZ_BYTES(rst2init_qp_out)] = {};
    int max_tx, max_rx, len_tx, len;
    ucs_status_t status;
    int wqe_size;
    int dvflags;
    void *qpc;
    int ret;

    wqe_size = sizeof(struct mlx5_wqe_ctrl_seg) +
               sizeof(struct mlx5_wqe_umr_ctrl_seg) +
               sizeof(struct mlx5_wqe_mkey_context_seg) +
               ucs_max(sizeof(struct mlx5_wqe_umr_klm_seg), 64) +
               ucs_max(attr->super.cap.max_send_sge * sizeof(struct mlx5_wqe_data_seg),
                       ucs_align_up(sizeof(struct mlx5_wqe_inl_data_seg) +
                                    attr->super.cap.max_inline_data, 16));
    len_tx = ucs_roundup_pow2_or0(attr->super.cap.max_send_wr * wqe_size);
    max_tx = len_tx / MLX5_SEND_WQE_BB;
    max_rx = ucs_roundup_pow2_or0(attr->super.cap.max_recv_wr);
    len    = len_tx + max_rx * UCT_IB_MLX5_MAX_BB * UCT_IB_MLX5_WQE_SEG_SIZE;

    if (tx != NULL) {
        status = uct_ib_mlx5_md_buf_alloc(md, len, 0, &qp->devx.wq_buf,
                                          &qp->devx.mem, "qp umem");
        if (status != UCS_OK) {
            goto err;
        }
    } else {
        qp->devx.wq_buf = NULL;
    }

    qp->devx.dbrec = uct_ib_mlx5_get_dbrec(md);
    if (!qp->devx.dbrec) {
        status = UCS_ERR_NO_MEMORY;
        goto err_free_mem;
    }

    dv.pd.in  = attr->super.ibv.pd;
    dv.pd.out = &dvpd;
    dv.cq.in  = attr->super.ibv.send_cq;
    dv.cq.out = &dvscq;
    dvflags   = MLX5DV_OBJ_PD | MLX5DV_OBJ_CQ;
    mlx5dv_init_obj(&dv, dvflags);
    dv.cq.in  = attr->super.ibv.recv_cq;
    dv.cq.out = &dvrcq;
    mlx5dv_init_obj(&dv, MLX5DV_OBJ_CQ);

    UCT_IB_MLX5DV_SET(create_qp_in, in, opcode, UCT_IB_MLX5_CMD_OP_CREATE_QP);
    qpc = UCT_IB_MLX5DV_ADDR_OF(create_qp_in, in, qpc);
    if (attr->super.qp_type == UCT_IB_QPT_DCI) {
        UCT_IB_MLX5DV_SET(qpc, qpc, st, UCT_IB_MLX5_QPC_ST_DCI);
        UCT_IB_MLX5DV_SET(qpc, qpc, full_handshake, !!attr->full_handshake);
    } else if (attr->super.qp_type == IBV_QPT_RC) {
        UCT_IB_MLX5DV_SET(qpc, qpc, st, UCT_IB_MLX5_QPC_ST_RC);
    } else {
        ucs_error("create qp failed: unknown type %d", attr->super.qp_type);
        status = UCS_ERR_UNSUPPORTED;
        goto err_free_db;
    }
    UCT_IB_MLX5DV_SET(qpc, qpc, pm_state, UCT_IB_MLX5_QPC_PM_STATE_MIGRATED);
    UCT_IB_MLX5DV_SET(qpc, qpc, pd, dvpd.pdn);
    UCT_IB_MLX5DV_SET(qpc, qpc, uar_page, attr->uar->uar->page_id);
    ucs_assert((attr->super.srq == NULL) || (attr->super.srq_num != 0));
    UCT_IB_MLX5DV_SET(qpc, qpc, rq_type, uct_ib_mlx5_devx_get_rq_type(attr));
    UCT_IB_MLX5DV_SET(qpc, qpc, srqn_rmpn_xrqn, attr->super.srq_num);
    UCT_IB_MLX5DV_SET(qpc, qpc, cqn_snd, dvscq.cqn);
    UCT_IB_MLX5DV_SET(qpc, qpc, cqn_rcv, dvrcq.cqn);
    /* cppcheck-suppress internalAstError */
    UCT_IB_MLX5DV_SET(qpc, qpc, log_sq_size, ucs_ilog2_or0(max_tx));
    UCT_IB_MLX5DV_SET(qpc, qpc, log_rq_size, ucs_ilog2_or0(max_rx));
    UCT_IB_MLX5DV_SET(qpc, qpc, cs_req,
            uct_ib_mlx5_qpc_cs_req(attr->super.max_inl_cqe[UCT_IB_DIR_TX]));
    UCT_IB_MLX5DV_SET(qpc, qpc, cs_res,
            uct_ib_mlx5_qpc_cs_res(attr->super.max_inl_cqe[UCT_IB_DIR_RX], 0));
    UCT_IB_MLX5DV_SET64(qpc, qpc, dbr_addr, qp->devx.dbrec->offset);
    UCT_IB_MLX5DV_SET(qpc, qpc, dbr_umem_id, qp->devx.dbrec->mem_id);
    UCT_IB_MLX5DV_SET(qpc, qpc, user_index, attr->uidx);

    if (qp->devx.wq_buf == NULL) {
        UCT_IB_MLX5DV_SET(qpc, qpc, no_sq, true);
        UCT_IB_MLX5DV_SET(qpc, qpc, offload_type, true);
        UCT_IB_MLX5DV_SET(create_qp_in, in, wq_umem_id, md->zero_mem.mem->umem_id);
    } else {
        UCT_IB_MLX5DV_SET(create_qp_in, in, wq_umem_id, qp->devx.mem.mem->umem_id);
    }

    qp->devx.obj = mlx5dv_devx_obj_create(dev->ibv_context, in, sizeof(in),
                                          out, sizeof(out));
    if (!qp->devx.obj) {
        ucs_error("mlx5dv_devx_obj_create(QP) failed, syndrome %x: %m",
                  UCT_IB_MLX5DV_GET(create_qp_out, out, syndrome));
        status = UCS_ERR_IO_ERROR;
        goto err_free_db;
    }

    qp->qp_num = UCT_IB_MLX5DV_GET(create_qp_out, out, qpn);

    if (attr->super.qp_type == IBV_QPT_RC) {
        qpc = UCT_IB_MLX5DV_ADDR_OF(rst2init_qp_in, in_2init, qpc);
        UCT_IB_MLX5DV_SET(rst2init_qp_in, in_2init, opcode, UCT_IB_MLX5_CMD_OP_RST2INIT_QP);
        UCT_IB_MLX5DV_SET(rst2init_qp_in, in_2init, qpn, qp->qp_num);
        UCT_IB_MLX5DV_SET(qpc, qpc, pm_state, UCT_IB_MLX5_QPC_PM_STATE_MIGRATED);
        UCT_IB_MLX5DV_SET(qpc, qpc, primary_address_path.vhca_port_num, attr->super.port);
        if (!attr->is_roce_dev) {
            UCT_IB_MLX5DV_SET(qpc, qpc, primary_address_path.pkey_index,
                              attr->pkey_index);
        }
        UCT_IB_MLX5DV_SET(qpc, qpc, rwe, true);

        ret = mlx5dv_devx_obj_modify(qp->devx.obj, in_2init, sizeof(in_2init),
                out_2init, sizeof(out_2init));
        if (ret) {
            ucs_error("mlx5dv_devx_obj_modify(2INIT_QP) failed, syndrome %x: %m",
                    UCT_IB_MLX5DV_GET(rst2init_qp_out, out_2init, syndrome));
            status = UCS_ERR_IO_ERROR;
            goto err_free;
        }
    }

    qp->type = UCT_IB_MLX5_OBJ_TYPE_DEVX;

    attr->super.cap.max_send_wr = max_tx;
    attr->super.cap.max_recv_wr = max_rx;

    if (tx != NULL) {
        ucs_assert(qp->devx.wq_buf != NULL);
        tx->reg    = &attr->uar->super;
        tx->qstart = qp->devx.wq_buf;
        tx->qend   = UCS_PTR_BYTE_OFFSET(qp->devx.wq_buf, len_tx);
        tx->dbrec  = &qp->devx.dbrec->db[MLX5_SND_DBR];
        tx->bb_max = max_tx - 2 * UCT_IB_MLX5_MAX_BB;
        ucs_assert(*tx->dbrec == 0);
        uct_ib_mlx5_txwq_reset(tx);
    } else {
        ucs_assert(qp->devx.wq_buf == NULL);
        uct_worker_tl_data_put(attr->uar, uct_ib_mlx5_devx_uar_cleanup);
    }

    return UCS_OK;

err_free:
    mlx5dv_devx_obj_destroy(qp->devx.obj);
err_free_db:
    uct_ib_mlx5_put_dbrec(qp->devx.dbrec);
err_free_mem:
    uct_ib_mlx5_md_buf_free(md, qp->devx.wq_buf, &qp->devx.mem);
err:
    return status;
}

ucs_status_t uct_ib_mlx5_devx_modify_qp(uct_ib_mlx5_qp_t *qp,
                                        const void *in, size_t inlen,
                                        void *out, size_t outlen)
{
    int ret;

    switch (qp->type) {
    case UCT_IB_MLX5_OBJ_TYPE_VERBS:
        ret = mlx5dv_devx_qp_modify(qp->verbs.qp, in, inlen, out, outlen);
        if (ret) {
            ucs_error("mlx5dv_devx_qp_modify(%x) failed, syndrome %x: %m",
                      UCT_IB_MLX5DV_GET(modify_qp_in, in, opcode),
                      UCT_IB_MLX5DV_GET(modify_qp_out, out, syndrome));
            return UCS_ERR_IO_ERROR;
        }
        break;
    case UCT_IB_MLX5_OBJ_TYPE_DEVX:
        ret = mlx5dv_devx_obj_modify(qp->devx.obj, in, inlen, out, outlen);
        if (ret) {
            ucs_error("mlx5dv_devx_obj_modify(%x) failed, syndrome %x: %m",
                      UCT_IB_MLX5DV_GET(modify_qp_in, in, opcode),
                      UCT_IB_MLX5DV_GET(modify_qp_out, out, syndrome));
            return UCS_ERR_IO_ERROR;
        }
        break;
    case UCT_IB_MLX5_OBJ_TYPE_LAST:
        return UCS_ERR_UNSUPPORTED;
    }

    return UCS_OK;
}

static ucs_status_t
uct_ib_mlx5_devx_query_qp(uct_ib_mlx5_qp_t *qp, void *in, size_t inlen,
                          void *out, size_t outlen)
{
    int ret;

    UCT_IB_MLX5DV_SET(query_qp_in, in, opcode, UCT_IB_MLX5_CMD_OP_QUERY_QP);
    UCT_IB_MLX5DV_SET(query_qp_in, in, qpn, qp->qp_num);

    switch (qp->type) {
    case UCT_IB_MLX5_OBJ_TYPE_VERBS:
        ret = mlx5dv_devx_qp_query(qp->verbs.qp, in, inlen, out, outlen);
        if (ret) {
            ucs_error("mlx5dv_devx_qp_query(%x) failed, syndrome %x: %m",
                      UCT_IB_MLX5_CMD_OP_QUERY_QP,
                      UCT_IB_MLX5DV_GET(query_qp_out, out, syndrome));
            return UCS_ERR_IO_ERROR;
        }
        break;
    case UCT_IB_MLX5_OBJ_TYPE_DEVX:
        ret = mlx5dv_devx_obj_query(qp->devx.obj, in, inlen, out, outlen);
        if (ret) {
            ucs_error("mlx5dv_devx_obj_query(%x) failed, syndrome %x: %m",
                      UCT_IB_MLX5_CMD_OP_QUERY_QP,
                      UCT_IB_MLX5DV_GET(query_qp_out, out, syndrome));
            return UCS_ERR_IO_ERROR;
        }
        break;
    case UCT_IB_MLX5_OBJ_TYPE_LAST:
        return UCS_ERR_UNSUPPORTED;
    }

    return UCS_OK;
}

ucs_status_t uct_ib_mlx5_devx_modify_qp_state(uct_ib_mlx5_qp_t *qp,
                                              enum ibv_qp_state state)
{
    char in[UCT_IB_MLX5DV_ST_SZ_BYTES(modify_qp_in)]   = {};
    char out[UCT_IB_MLX5DV_ST_SZ_BYTES(modify_qp_out)] = {};

    switch (state) {
    case IBV_QPS_ERR:
        UCT_IB_MLX5DV_SET(modify_qp_in, in, opcode, UCT_IB_MLX5_CMD_OP_2ERR_QP);
        break;
    case IBV_QPS_RESET:
        UCT_IB_MLX5DV_SET(modify_qp_in, in, opcode, UCT_IB_MLX5_CMD_OP_2RST_QP);
        break;
    default:
        return UCS_ERR_UNSUPPORTED;
    }

    UCT_IB_MLX5DV_SET(modify_qp_in, in, qpn, qp->qp_num);
    return uct_ib_mlx5_devx_modify_qp(qp, in, sizeof(in), out, sizeof(out));
}

ucs_status_t
uct_ib_mlx5_devx_connect_rc_qp(uct_ib_mlx5_md_t *md, uct_ib_mlx5_qp_t *qp,
                               const uct_ib_mlx5_qp_connect_attr_t *attr)
{
    uct_ib_device_t *dev = &md->super.dev;
    struct ibv_ah_attr*ah_attr = attr->ah_attr;
    char in_2rtr[UCT_IB_MLX5DV_ST_SZ_BYTES(init2rtr_qp_in)]   = {};
    char out_2rtr[UCT_IB_MLX5DV_ST_SZ_BYTES(init2rtr_qp_out)] = {};
    char in_2rts[UCT_IB_MLX5DV_ST_SZ_BYTES(rtr2rts_qp_in)]    = {};
    char out_2rts[UCT_IB_MLX5DV_ST_SZ_BYTES(rtr2rts_qp_out)]  = {};
    uint32_t opt_param_mask = UCT_IB_MLX5_QP_OPTPAR_RRE |
                              UCT_IB_MLX5_QP_OPTPAR_RAE |
                              UCT_IB_MLX5_QP_OPTPAR_RWE;
    struct mlx5_wqe_av mlx5_av;
    ucs_status_t status;
    struct ibv_ah *ah;
    void *qpc;

    UCT_IB_MLX5DV_SET(init2rtr_qp_in, in_2rtr, opcode,
                      UCT_IB_MLX5_CMD_OP_INIT2RTR_QP);
    UCT_IB_MLX5DV_SET(init2rtr_qp_in, in_2rtr, qpn, qp->qp_num);

    qpc = UCT_IB_MLX5DV_ADDR_OF(init2rtr_qp_in, in_2rtr, qpc);
    UCT_IB_MLX5DV_SET(qpc, qpc, mtu, attr->path_mtu);
    UCT_IB_MLX5DV_SET(qpc, qpc, log_msg_max, UCT_IB_MLX5_LOG_MAX_MSG_SIZE);
    UCT_IB_MLX5DV_SET(qpc, qpc, remote_qpn, attr->dest_qp_num);

    if (attr->is_roce_dev) {
        status = uct_ib_device_create_ah_cached(dev, ah_attr, md->super.pd,
                                                "RC DevX QP connect", &ah);
        if (status != UCS_OK) {
            return status;
        }

        uct_ib_mlx5_get_av(ah, &mlx5_av);
        memcpy(UCT_IB_MLX5DV_ADDR_OF(qpc, qpc, primary_address_path.rmac_47_32),
               &mlx5_av.rmac, sizeof(mlx5_av.rmac));
        memcpy(UCT_IB_MLX5DV_ADDR_OF(qpc, qpc, primary_address_path.rgid_rip),
               &mlx5_av.rgid, sizeof(mlx5_av.rgid));
        UCT_IB_MLX5DV_SET(qpc, qpc, primary_address_path.hop_limit,
                          mlx5_av.hop_limit);
        UCT_IB_MLX5DV_SET(qpc, qpc, primary_address_path.src_addr_index,
                          ah_attr->grh.sgid_index);
        UCT_IB_MLX5DV_SET(qpc, qpc, primary_address_path.eth_prio, attr->sl);
        if (attr->is_roce_dev && (attr->roce_ver == UCT_IB_DEVICE_ROCE_V2)) {
            ucs_assert(ah_attr->dlid >= UCT_IB_ROCE_UDP_SRC_PORT_BASE);
            UCT_IB_MLX5DV_SET(qpc, qpc, primary_address_path.udp_sport,
                              ah_attr->dlid);
            UCT_IB_MLX5DV_SET(qpc, qpc, primary_address_path.dscp,
                              uct_ib_device_roce_dscp(attr->traffic_class));
        }

        uct_ib_mlx5_devx_set_qpc_port_affinity(md, attr->path_index, qpc,
                                               &opt_param_mask);
    } else {
        UCT_IB_MLX5DV_SET(qpc, qpc, primary_address_path.grh, ah_attr->is_global);
        UCT_IB_MLX5DV_SET(qpc, qpc, primary_address_path.rlid, ah_attr->dlid);
        UCT_IB_MLX5DV_SET(qpc, qpc, primary_address_path.mlid,
                          ah_attr->src_path_bits & 0x7f);
        UCT_IB_MLX5DV_SET(qpc, qpc, primary_address_path.sl, attr->sl);

        if (ah_attr->is_global) {
            UCT_IB_MLX5DV_SET(qpc, qpc, primary_address_path.hop_limit,
                              ah_attr->grh.hop_limit);
            memcpy(UCT_IB_MLX5DV_ADDR_OF(qpc, qpc, primary_address_path.rgid_rip),
                   &ah_attr->grh.dgid,
                   UCT_IB_MLX5DV_FLD_SZ_BYTES(qpc, primary_address_path.rgid_rip));
            /* TODO add flow_label support */
            UCT_IB_MLX5DV_SET(qpc, qpc, primary_address_path.tclass,
                              attr->traffic_class);
        }
    }

    UCT_IB_MLX5DV_SET(qpc, qpc, primary_address_path.vhca_port_num, ah_attr->port_num);
    UCT_IB_MLX5DV_SET(qpc, qpc, log_rra_max,
                      ucs_ilog2_or0(attr->max_rd_atomic));
    UCT_IB_MLX5DV_SET(qpc, qpc, atomic_mode, UCT_IB_MLX5_ATOMIC_MODE);
    UCT_IB_MLX5DV_SET(qpc, qpc, rre, true);
    UCT_IB_MLX5DV_SET(qpc, qpc, rwe, true);
    UCT_IB_MLX5DV_SET(qpc, qpc, rae, true);
    UCT_IB_MLX5DV_SET(qpc, qpc, min_rnr_nak, attr->min_rnr_timer);

    UCT_IB_MLX5DV_SET(init2rtr_qp_in, in_2rtr, opt_param_mask, opt_param_mask);

    status = uct_ib_mlx5_devx_modify_qp(qp, in_2rtr, sizeof(in_2rtr),
                                        out_2rtr, sizeof(out_2rtr));
    if (status != UCS_OK) {
        return status;
    }

    UCT_IB_MLX5DV_SET(rtr2rts_qp_in, in_2rts, opcode,
                      UCT_IB_MLX5_CMD_OP_RTR2RTS_QP);
    UCT_IB_MLX5DV_SET(rtr2rts_qp_in, in_2rts, qpn, qp->qp_num);

    qpc = UCT_IB_MLX5DV_ADDR_OF(rtr2rts_qp_in, in_2rts, qpc);
    UCT_IB_MLX5DV_SET(qpc, qpc, log_sra_max,
                      ucs_ilog2_or0(attr->max_rd_atomic));
    UCT_IB_MLX5DV_SET(qpc, qpc, retry_count, attr->retry_cnt);
    UCT_IB_MLX5DV_SET(qpc, qpc, rnr_retry, attr->rnr_retry);
    UCT_IB_MLX5DV_SET(qpc, qpc, primary_address_path.ack_timeout,
                      attr->timeout);
    UCT_IB_MLX5DV_SET(qpc, qpc, primary_address_path.log_rtm,
                      attr->exp_backoff);
    UCT_IB_MLX5DV_SET(qpc, qpc, log_ack_req_freq,
                      attr->log_ack_req_freq);

    status = uct_ib_mlx5_devx_modify_qp(qp, in_2rts, sizeof(in_2rts),
                                        out_2rts, sizeof(out_2rts));
    if (status != UCS_OK) {
        return status;
    }

    ucs_debug("connected rc devx qp 0x%x on %s:%d to lid %d(+%d) sl %d "
              "remote_qp 0x%x mtu %zu timer %dx%d rnr %dx%d rd_atom %d",
              qp->qp_num, uct_ib_device_name(dev), ah_attr->port_num,
              ah_attr->dlid, ah_attr->src_path_bits, ah_attr->sl,
              attr->dest_qp_num, uct_ib_mtu_value(attr->path_mtu),
              attr->timeout, attr->retry_cnt, attr->min_rnr_timer,
              attr->rnr_retry, attr->max_rd_atomic);
    return UCS_OK;
}

void uct_ib_mlx5_devx_destroy_qp(uct_ib_mlx5_md_t *md, uct_ib_mlx5_qp_t *qp)
{
    int ret = mlx5dv_devx_obj_destroy(qp->devx.obj);
    if (ret) {
        ucs_error("mlx5dv_devx_obj_destroy(QP) failed: %m");
    }
    uct_ib_mlx5_put_dbrec(qp->devx.dbrec);
    uct_ib_mlx5_md_buf_free(md, qp->devx.wq_buf, &qp->devx.mem);
}

ucs_status_t uct_ib_mlx5_devx_query_ooo_sl_mask(uct_ib_mlx5_md_t *md,
                                                uint8_t port_num,
                                                uint16_t *ooo_sl_mask_p)
{
    char in[UCT_IB_MLX5DV_ST_SZ_BYTES(query_hca_vport_context_in)]   = {};
    char out[UCT_IB_MLX5DV_ST_SZ_BYTES(query_hca_vport_context_out)] = {};
    void *ctx;
    int ret;

    if (!(md->flags & UCT_IB_MLX5_MD_FLAG_OOO_SL_MASK)) {
        return UCS_ERR_UNSUPPORTED;
    }

    UCT_IB_MLX5DV_SET(query_hca_vport_context_in, in, opcode,
                      UCT_IB_MLX5_CMD_OP_QUERY_HCA_VPORT_CONTEXT);
    UCT_IB_MLX5DV_SET(query_hca_vport_context_in, in, port_num, port_num);

    ret = mlx5dv_devx_general_cmd(md->super.dev.ibv_context, in, sizeof(in),
                                  out, sizeof(out));
    if (ret != 0) {
        ucs_error("mlx5dv_devx_general_cmd(QUERY_HCA_VPORT_CONTEXT) failed,"
                  " syndrome %x: %m",
                  UCT_IB_MLX5DV_GET(query_hca_vport_context_out, out,
                                    syndrome));
        return UCS_ERR_IO_ERROR;
    }

    ctx = UCT_IB_MLX5DV_ADDR_OF(query_hca_vport_context_out, out,
                                hca_vport_context);

    *ooo_sl_mask_p = UCT_IB_MLX5DV_GET(hca_vport_context, ctx, ooo_sl_mask);

    return UCS_OK;
}

void uct_ib_mlx5_devx_set_qpc_port_affinity(uct_ib_mlx5_md_t *md,
                                            uint8_t path_index, void *qpc,
                                            uint32_t *opt_param_mask)
{
    uct_ib_device_t *dev = &md->super.dev;
    uint8_t tx_port      = dev->first_port;

    if (!(md->flags & UCT_IB_MLX5_MD_FLAG_LAG)) {
        return;
    }

    *opt_param_mask |= UCT_IB_MLX5_QP_OPTPAR_LAG_TX_AFF;
    if (dev->lag_level > 0) {
        tx_port += path_index % dev->lag_level;
    }
    UCT_IB_MLX5DV_SET(qpc, qpc, lag_tx_port_affinity, tx_port);
}

ucs_status_t
uct_ib_mlx5_devx_query_qp_peer_info(uct_ib_iface_t *iface, uct_ib_mlx5_qp_t *qp,
                                    struct ibv_ah_attr *ah_attr,
                                    uint32_t *dest_qpn)
{
    char in[UCT_IB_MLX5DV_ST_SZ_BYTES(query_qp_in)]   = {};
    char out[UCT_IB_MLX5DV_ST_SZ_BYTES(query_qp_out)] = {};
    void *ctx;
    ucs_status_t status;

    status = uct_ib_mlx5_devx_query_qp(qp, in, sizeof(in), out, sizeof(out));
    if (status != UCS_OK) {
        return UCS_ERR_IO_ERROR;
    }

    ctx                        = UCT_IB_MLX5DV_ADDR_OF(query_qp_out, out, qpc);
    *dest_qpn                  = UCT_IB_MLX5DV_GET(qpc, ctx, remote_qpn);
    ah_attr->dlid              = UCT_IB_MLX5DV_GET(qpc, ctx,
                                                   primary_address_path.rlid);
    ah_attr->sl                = UCT_IB_MLX5DV_GET(qpc, ctx,
                                                   primary_address_path.sl);
    ah_attr->port_num          = UCT_IB_MLX5DV_GET(qpc, ctx,
                                            primary_address_path.vhca_port_num);
    ah_attr->static_rate       = UCT_IB_MLX5DV_GET(qpc, ctx,
                                                primary_address_path.stat_rate);
    ah_attr->src_path_bits     = UCT_IB_MLX5DV_GET(qpc, ctx,
                                                     primary_address_path.mlid);
    ah_attr->is_global         = UCT_IB_MLX5DV_GET(qpc, ctx,
                                                   primary_address_path.grh) ||
                                                   uct_ib_iface_is_roce(iface);
    ah_attr->grh.sgid_index    = UCT_IB_MLX5DV_GET(qpc, ctx,
                                           primary_address_path.src_addr_index);
    ah_attr->grh.traffic_class = UCT_IB_MLX5DV_GET(qpc, ctx,
                                                   primary_address_path.tclass);
    ah_attr->grh.flow_label    = UCT_IB_MLX5DV_GET(qpc, ctx,
                                               primary_address_path.flow_label);
    ah_attr->grh.hop_limit     = UCT_IB_MLX5DV_GET(qpc, ctx,
                                                primary_address_path.hop_limit);

    if (ah_attr->is_global) {
        memcpy(ah_attr->grh.dgid.raw,
               UCT_IB_MLX5DV_ADDR_OF(qpc, ctx, primary_address_path.rgid_rip),
               sizeof(ah_attr->grh.dgid.raw));
    }

    return UCS_OK;
}

#endif

ucs_status_t uct_ib_mlx5dv_arm_cq(uct_ib_mlx5_cq_t *cq, int solicited)
{
    uint64_t doorbell, sn_ci_cmd;
    uint32_t sn, ci, cmd;

    sn  = cq->cq_sn & 3;
    ci  = cq->cq_ci & 0xffffff;
    cmd = solicited ? MLX5_CQ_DB_REQ_NOT_SOL : MLX5_CQ_DB_REQ_NOT;
    sn_ci_cmd = (sn << 28) | cmd | ci;

    cq->dbrec[UCT_IB_MLX5_CQ_ARM_DB] = htobe32(sn_ci_cmd);

    ucs_memory_cpu_fence();

    doorbell = (sn_ci_cmd << 32) | cq->cq_num;

    *(uint64_t *)((uint8_t *)cq->uar + MLX5_CQ_DOORBELL) = htobe64(doorbell);

    ucs_memory_bus_store_fence();

    return UCS_OK;
}

#if HAVE_DECL_MLX5DV_OBJ_AH
void uct_ib_mlx5_get_av(struct ibv_ah *ah, struct mlx5_wqe_av *av)
{
    struct mlx5dv_obj  dv;
    struct mlx5dv_ah   dah;

    dv.ah.in = ah;
    dv.ah.out = &dah;
    mlx5dv_init_obj(&dv, MLX5DV_OBJ_AH);

    *av = *(dah.av);
    av->dqp_dct |= UCT_IB_MLX5_EXTENDED_UD_AV;
}
#elif !defined (HAVE_INFINIBAND_MLX5_HW_H)
void uct_ib_mlx5_get_av(struct ibv_ah *ah, struct mlx5_wqe_av *av)
{
    ucs_bug("MLX5DV_OBJ_AH not supported");
}
#endif

#if HAVE_DEVX
ucs_status_t uct_ib_mlx5_get_compact_av(uct_ib_iface_t *iface, int *compact_av)
{
    *compact_av = !!(uct_ib_iface_device(iface)->flags & UCT_IB_DEVICE_FLAG_AV);
    return UCS_OK;
}
#endif
