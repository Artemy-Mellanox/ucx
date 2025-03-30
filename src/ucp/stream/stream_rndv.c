/**
 * Copyright (C) 2024, NVIDIA CORPORATION & AFFILIATES. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "stream.h"
#include <ucp/rndv/proto_rndv.inl>


typedef struct {
    uint64_t address;
    size_t   length;
    uint64_t stream_id;
    uint64_t ep_id;
    uint64_t req_id;
    uint64_t ack;
} UCS_S_PACKED ucp_stream_ctrl_hdr_t;


typedef struct {
    ucp_recv_desc_t rdesc;
    ucp_rkey_h      rkey;
    uint64_t req_id;
    uint64_t address;
} ucp_stream_ctrl_desc_t;


enum {
    UCP_STREAM_PUT_STAGE_SEND = UCP_PROTO_STAGE_START,
    UCP_STREAM_PUT_STAGE_ACK,
};


static size_t ucp_stream_pmpy_ctrl_pack(void *dest, void *arg)
{
    ucp_stream_ctrl_hdr_t *ctrl             = dest;
    ucp_request_t *req                      = arg;
    const ucp_proto_rndv_ctrl_priv_t *rpriv = req->send.proto_config->priv;
    void *rkey_buffer                       = ctrl + 1;
    ucp_datatype_iter_t *dt                 = &req->send.state.dt_iter;
    size_t rkey_size;

    ctrl->ep_id     = ucp_send_request_get_ep_remote_id(req);
    ctrl->stream_id = req->send.stream.s->stream_id;
    ctrl->length    = dt->length - dt->offset;
    ctrl->address   = (uintptr_t)dt->type.contig.buffer + dt->offset;
    ctrl->ack       = req->send.stream.s->remote_seq;
    ctrl->req_id    = ucp_send_request_get_id(req);
    rkey_size       = ucp_proto_request_pack_rkey(req, rpriv->md_map,
                                                  rpriv->sys_dev_map,
                                                  rpriv->sys_dev_distance,
                                                  rkey_buffer);
    return sizeof(*ctrl) + rkey_size;
}

static ucs_status_t ucp_stream_pmpy_ctrl_complete(ucp_request_t *req)
{
    size_t length = req->send.state.dt_iter.length - req->send.state.dt_iter.offset;
    ucp_stream_t *stream = req->send.stream.s;

    stream->local_seq += length;
#if 0
    if (stream->flags & UCP_STREAM_FLAG_TRANSITION) {
        stream->flags &= ~(UCP_STREAM_FLAG_ACTIVE | UCP_STREAM_FLAG_TRANSITION);
    } else if (stream->flags & UCP_STREAM_FLAG_ACTIVE) {
        stream->flags |= UCP_STREAM_FLAG_TRANSITION;
    }
#endif

    return UCS_OK;
}

static ucs_status_t ucp_stream_pmpy_ctrl_progress(uct_pending_req_t *self)
{
    ucp_request_t *req   = ucs_container_of(self, ucp_request_t, send.uct);
    ucp_worker_t *worker = req->send.ep->worker;
    ucp_stream_t *stream = req->send.stream.s;
    const ucp_proto_rndv_ctrl_priv_t *rpriv = req->send.proto_config->priv;
    ucs_status_t status;
    size_t max_rtr_size;
    ucp_am_id_t am_id;

    if (!(req->flags & UCP_REQUEST_FLAG_PROTO_INITIALIZED)) {
        status = ucp_ep_resolve_remote_id(req->send.ep, rpriv->lane);
        if (status != UCS_OK) {
            goto err;
        }

        status = ucp_datatype_iter_mem_reg(worker->context,
                                           &req->send.state.dt_iter,
                                           rpriv->md_map,
                                           UCT_MD_MEM_ACCESS_REMOTE_PUT |
                                           UCT_MD_MEM_FLAG_HIDE_ERRORS,
                                           UCP_DT_MASK_ALL);
        if (status != UCS_OK) {
            goto err;
        }

        ucp_send_request_id_alloc(req);
        ucp_stream_req_enqueue(req);
        req->flags |= UCP_REQUEST_FLAG_PROTO_INITIALIZED;
    }

    if (req->flags & UCP_REQUEST_FLAG_COMPLETED) {
        return UCS_OK;
    }

    am_id = stream->flags & UCP_STREAM_FLAG_SEND ? UCP_AM_ID_PMPY_RTS : UCP_AM_ID_PMPY_RTR;
    max_rtr_size = sizeof(ucp_stream_ctrl_hdr_t) + rpriv->packed_rkey_size;
    status  = ucp_proto_am_bcopy_single_progress(req, am_id, rpriv->lane,
            ucp_stream_pmpy_ctrl_pack, req, max_rtr_size,
            ucp_stream_pmpy_ctrl_complete, 0);
    return status;

err:
    ucp_proto_request_abort(req, status);
    return UCS_OK;
}

static ucs_status_t
ucp_stream_pmpy_send_zcopy(ucp_request_t *buf_req, ucp_operation_id_t op_id,
                           uint64_t address, size_t length, ucp_rkey_h rkey,
                           uint64_t req_id)
{
    ucp_ep_h ep = buf_req->send.ep;
    ucp_worker_h worker = ep->worker;
    ucp_proto_select_param_t sel_param;
    ucs_status_t status;
    ucp_request_t *req;

    req = ucp_request_get(worker);
    if (req == NULL) {
        ucs_error("failed to allocate rendezvous reply");
        return UCS_ERR_NO_MEMORY;
    }

    ucp_proto_request_send_init(req, ep, 0);
    req->send.rndv.remote_address = address;
    req->send.rndv.offset         = 0;
    req->send.rndv.rkey           = rkey;
    req->send.rndv.stream.s       = buf_req->send.stream.s;
    req->send.rndv.remote_req_id  = req_id;
    ucp_request_set_super(req, buf_req);
    ucp_datatype_iter_slice(&buf_req->send.state.dt_iter,
                            buf_req->send.state.dt_iter.offset,
                            length, &req->send.state.dt_iter);

    ucp_proto_select_param_init(&sel_param, op_id, 0,
                                UCP_PROTO_SELECT_OP_FLAG_STREAM_ACTIVE,
                                req->send.state.dt_iter.dt_class,
                                &req->send.state.dt_iter.mem_info, 1);

    status = ucp_proto_request_lookup_proto(worker, ep, req,
            &ucp_rkey_config(worker, rkey)->proto_select,
            rkey->cfg_index, &sel_param, length);

    if (status != UCS_OK) {
        ucp_datatype_iter_cleanup(&req->send.state.dt_iter, 1, UCP_DT_MASK_ALL);
        ucs_mpool_put(req);
        return status;
    }
    ucp_request_send(req);
    ucp_request_release(req + 1);
    buf_req->send.state.dt_iter.offset += length;
    buf_req->send.stream.pending++;
    return UCS_OK;
}

void ucp_stream_rndv_desc_release(ucp_recv_desc_t *rdesc)
{
    ucp_stream_ctrl_desc_t *cdesc = (ucp_stream_ctrl_desc_t *)rdesc;
    ucp_rkey_destroy(cdesc->rkey);
    ucs_free(cdesc);
}

ucs_status_t
ucp_stream_rndv_process_rdesc(ucp_recv_desc_t *rdesc, ucp_request_t *req,
                              ucp_stream_t *stream, ucp_operation_id_t op_id)
{
    ucp_stream_ctrl_desc_t *cdesc = (ucp_stream_ctrl_desc_t *)rdesc;
    ucs_status_t status;
    size_t length;

    length = ucs_min(cdesc->rdesc.length, req->send.state.dt_iter.length  -
                                         req->send.state.dt_iter.offset);
    status = ucp_stream_pmpy_send_zcopy(req, op_id, cdesc->address,
                                        length, cdesc->rkey, cdesc->req_id);
    if (status != UCS_OK) {
        return status;
    }

    if (length == cdesc->rdesc.length) {
        ucp_stream_rdesc_dequeue(stream);
        ucp_rkey_destroy(cdesc->rkey);
        ucs_free(cdesc);
    } else {
        cdesc->address += length;
        cdesc->rdesc.length -= length;
    }

    return UCS_OK;
}

static ucs_status_t
ucp_stream_pmpy_ctrl(ucp_worker_h worker, ucp_ep_h ep, ucp_request_t *req,
                     ucp_operation_id_t op_id)
{
    ucp_proto_select_param_t sel_param;
    ucs_status_t status;
    size_t length;

    ucp_proto_select_param_init(&sel_param, op_id, 0, 0,
                                req->send.state.dt_iter.dt_class,
                                &req->send.state.dt_iter.mem_info, 1);
    length = req->send.state.dt_iter.length - req->send.state.dt_iter.offset;
    status = ucp_proto_request_lookup_proto(worker, ep, req,
                              &ucp_ep_config(ep)->proto_select,
                              UCP_WORKER_CFG_INDEX_NULL, &sel_param, length);
    if (status != UCS_OK) {
        // TODO release req
        return status;
    }

    ucp_request_send(req);
    return UCS_OK;
}

ucs_status_ptr_t
ucp_stream_pmpy_send(ucp_ep_h ep, ucp_request_t *req, const void *buffer,
                     size_t count, ucp_datatype_t datatype,
                     size_t contig_length, const ucp_request_param_t *param)
{
    ucp_worker_h worker = ep->worker;
    ucp_stream_t *stream = req->send.stream.s;
    ucs_status_t status;
    uint8_t sg_count;

    ucp_proto_request_send_init(req, ep, 0);
    req->send.stream.pending = 0;
    status = ucp_datatype_iter_init(worker->context,
                              (void*)buffer, count, datatype, contig_length, 1,
                              &req->send.state.dt_iter, &sg_count, param);
    if (status != UCS_OK) {
        ucp_request_put_param(param, req);
        return UCS_STATUS_PTR(status);
    }

    while ((req->send.state.dt_iter.offset < req->send.state.dt_iter.length) &&
           ucp_stream_has_data(stream)) {
        ucp_stream_rndv_process_rdesc(ucp_stream_rdesc_get(stream),
                                      req, stream, UCP_OP_ID_STREAM_SEND);
    }

    if (req->send.stream.pending > 0) {
        goto set_param;
    }

    if (req->send.state.dt_iter.offset == req->send.state.dt_iter.length) {
        ucp_request_imm_cmpl_param(param, req, send);
        /* unreachable */
    }

    status = ucp_stream_pmpy_ctrl(ep->worker, ep, req, UCP_OP_ID_STREAM_SEND);
    if (status != UCS_OK) {
        ucp_request_put_param(param, req);
        return UCS_STATUS_PTR(status);
    }

    if (req->flags & UCP_REQUEST_FLAG_COMPLETED) {
        ucp_request_put_param(param, req);
        return UCS_OK;
    }

set_param:
    if (param->op_attr_mask & UCP_OP_ATTR_FIELD_CALLBACK) {
        req->flags    |= UCP_REQUEST_FLAG_CALLBACK;
        req->send.cb   = param->cb.send;
        req->user_data = ucp_request_param_user_data(param);
    }
    return req + 1;
}

ucs_status_t ucp_stream_pmpy_handle(void *am_arg, void *am_hdr,
                                    size_t am_length, unsigned am_flags,
                                    int dir)
{
    ucp_worker_h worker    = am_arg;
    ucp_stream_ctrl_hdr_t *ctrl = am_hdr;
    ucp_ep_h             ep;
    ucs_status_t         status;
    ucp_operation_id_t op_id;
    ucp_stream_t *stream;
    ucp_stream_ctrl_desc_t *cdesc;
    ucp_request_t *req;
    uint64_t remote_address;
    size_t remote_length;
    ucp_rkey_h rkey;
    size_t length;

    status = ucp_stream_get(worker, ctrl->ep_id, ctrl->stream_id, dir, &stream);
    if (status != UCS_OK) {
        return UCS_OK;
    }

    ep             = stream->ep;
    ucs_assert(dir == !!(stream->flags & UCP_STREAM_FLAG_SEND));
    stream->remote_seq += ctrl->length;
    stream->flags &= ~UCP_STREAM_FLAG_TRANSITION;
    if ((ctrl->ack != stream->local_seq) &&
        !(stream->flags & UCP_STREAM_FLAG_ACTIVE)) {
        return UCS_OK;
    }

    stream->flags |= UCP_STREAM_FLAG_ACTIVE;
    op_id          = dir ? UCP_OP_ID_STREAM_SEND : UCP_OP_ID_STREAM_RECV;


    if (stream->unexp_eager_count > 0) {
        if (ctrl->length <= stream->unexp_eager_count) {
            stream->unexp_eager_count -= ctrl->length;
            return UCS_OK;
        }

        remote_address = ctrl->address + stream->unexp_eager_count;
        remote_length  = ctrl->length - stream->unexp_eager_count;
        stream->unexp_eager_count = 0;
    } else {
        remote_address = ctrl->address;
        remote_length  = ctrl->length;
    }

    status = ucp_ep_rkey_unpack_internal(ep, ctrl + 1, am_length -
            sizeof(*ctrl), ucp_ep_config(ep)->key.reachable_md_map,
            ucp_ep_config(ep)->rndv.proto_rndv_rkey_skip_mds, &rkey);
    if (status != UCS_OK) {
        ucs_error("unable unpack rkey");
        return UCS_OK;
    }

    if (!ucp_stream_has_data(stream)) {
        while (!ucs_queue_is_empty(&stream->q) && (remote_length > 0)) {
            req = ucs_queue_head_elem_non_empty(&stream->q, ucp_request_t,
                                                send.stream.queue);
            length = ucs_min(ctrl->length, req->send.state.dt_iter.length -
                                           req->send.state.dt_iter.offset);
            status = ucp_stream_pmpy_send_zcopy(req, op_id, remote_address,
                                                length, rkey, ctrl->req_id);
            if (status != UCS_OK) {
                return UCS_OK;
            }

            if (req->send.state.dt_iter.offset ==
                req->send.state.dt_iter.length) {
                ucp_stream_request_dequeue_and_complete(req, UCS_OK);
            }

            remote_address += length;
            remote_length -= length;
        }

        if (remote_length == 0) {
            if (stream->remote_seq == stream->local_seq) {
                stream->flags = 0;
                stream->remote_seq = 0;
                stream->local_seq = 0;
            }

            ucp_rkey_destroy(rkey);
            return UCS_OK;
        }

        ucp_stream_enqueue(stream, worker);
    }

    cdesc = ucs_malloc(sizeof(*cdesc), "rndv remote desc");
    cdesc->rdesc.length         = remote_length;
    cdesc->address = remote_address;
    cdesc->rkey                 = rkey;
    cdesc->rdesc.flags          = UCP_RECV_DESC_FLAG_RNDV;
    cdesc->req_id               = ctrl->req_id;

    //ucp_stream_enqueue(stream, worker);
    ucp_stream_rdesc_enqueue(stream, &cdesc->rdesc);
    return UCS_OK;
}

ucs_status_ptr_t ucp_stream_pmpy_recv(ucp_request_t *req)
{
    ucp_ep_h ep = req->send.ep;
    ucs_status_t status;

    if ((ep->worker->context->config.ext.rndv_mode != UCP_RNDV_MODE_PUT_ZCOPY) ||
        !(req->flags & UCP_REQUEST_FLAG_STREAM_RECV_WAITALL) ||
        !UCP_DT_IS_CONTIG(req->send.state.dt_iter.dt_class)) {
        ucp_stream_req_enqueue(req);
        return req + 1;
    }

    status = ucp_stream_pmpy_ctrl(ep->worker, ep, req, UCP_OP_ID_STREAM_RECV);
    if (status != UCS_OK) {
        return UCS_STATUS_PTR(status);
    }

    return req + 1;
}

static void
ucp_stream_rndv_rtr_probe(const ucp_proto_init_params_t *init_params)
{
    ucp_context_h context                   = init_params->worker->context;
    ucp_proto_rndv_ctrl_init_params_t params = {
        .super.super         = *init_params,
        .super.latency       = 0,
        .super.overhead      = context->config.ext.proto_overhead_rndv_rtr,
        .super.cfg_thresh    = ucp_proto_rndv_cfg_thresh(context,
                               UCS_BIT(UCP_RNDV_MODE_GET_ZCOPY)),
        .super.cfg_priority  = 80,
        .super.min_length    = 1,
        .super.max_length    = SIZE_MAX,
        .super.min_frag_offs = UCP_PROTO_COMMON_OFFSET_INVALID,
        .super.max_frag_offs = ucs_offsetof(uct_iface_attr_t, cap.am.max_bcopy),
        .super.max_iov_offs  = UCP_PROTO_COMMON_OFFSET_INVALID,
        .super.hdr_size      = sizeof(ucp_rndv_rtr_hdr_t),
        .super.send_op       = UCT_EP_OP_AM_BCOPY,
        .super.memtype_op    = UCT_EP_OP_LAST,
        .super.flags         = UCP_PROTO_COMMON_INIT_FLAG_ERR_HANDLING,
        .super.exclude_map   = 0,
        .super.reg_mem_info  = ucp_proto_common_select_param_mem_info(
                                                     init_params->select_param),
        .remote_op_id        = UCP_OP_ID_RNDV_SEND,
        .lane                = ucp_proto_rndv_find_ctrl_lane(init_params),
        .perf_bias           = 0.0,
        .ctrl_msg_name       = UCP_PROTO_RNDV_RTR_NAME,
        .md_map              = 0
    };
    ucp_proto_rndv_ctrl_priv_t priv;

    if (!ucp_proto_init_check_op(init_params, UCS_BIT(UCP_OP_ID_STREAM_RECV))) {
        return;
    }

    if (ucp_proto_select_op_flags(init_params->select_param) &
        UCP_PROTO_SELECT_OP_FLAG_STREAM_ACTIVE) {
        return;
    }

    if (!UCP_DT_IS_CONTIG(init_params->select_param->dt_class)) {
        return;
    }

    ucp_proto_rndv_ctrl_probe(&params, &priv, sizeof(priv));
}

void ucp_stream_pmpy_ctrl_abort(ucp_request_t *req, ucs_status_t status)
{
    ucp_send_request_id_release(req);
    ucp_datatype_iter_mem_dereg(&req->send.state.dt_iter, UCP_DT_MASK_ALL);
    ucp_request_complete_send(req, status);
}

ucs_status_t ucp_stream_pmpy_ctrl_reset(ucp_request_t *req)
{
    if (req->flags & UCP_REQUEST_FLAG_PROTO_INITIALIZED) {
        ucp_send_request_id_release(req);
        ucp_proto_request_zcopy_clean(req, UCP_DT_MASK_ALL);
    }

    return UCS_OK;
}

ucp_proto_t ucp_stream_rndv_rtr_proto = {
    .name     = "rndv/rtr",
    .desc     = "rndv rtr",
    .flags    = 0,
    .probe    = ucp_stream_rndv_rtr_probe,
    .query    = ucp_proto_default_query,
    .progress = {ucp_stream_pmpy_ctrl_progress},
    .abort    = ucp_stream_pmpy_ctrl_abort,
    .reset    = ucp_stream_pmpy_ctrl_reset
};

ucs_status_t ucp_stream_rndv_handle_rtr(void *am_arg, void *am_hdr,
                                    size_t am_length, unsigned am_flags)
{
    return ucp_stream_pmpy_handle(am_arg, am_hdr, am_length, am_flags, 1);
}

ucs_status_t ucp_stream_rndv_handle_rts(void *am_arg, void *am_hdr,
                                    size_t am_length, unsigned am_flags)
{
    return ucp_stream_pmpy_handle(am_arg, am_hdr, am_length, am_flags, 0);
}

UCP_DEFINE_AM_WITH_PROXY(UCP_FEATURE_STREAM, UCP_AM_ID_PMPY_RTR,
                         ucp_stream_rndv_handle_rtr, NULL, 0);

UCP_DEFINE_AM_WITH_PROXY(UCP_FEATURE_STREAM, UCP_AM_ID_PMPY_RTS,
                         ucp_stream_rndv_handle_rts, NULL, 0);

static void
ucp_stream_rndv_rts_probe(const ucp_proto_init_params_t *init_params)
{
    if (!ucp_proto_init_check_op(init_params, UCS_BIT(UCP_OP_ID_STREAM_SEND))) {
        return;
    }

    if (ucp_proto_select_op_flags(init_params->select_param) &
        UCP_PROTO_SELECT_OP_FLAG_STREAM_ACTIVE) {
        return;
    }

    if (!UCP_DT_IS_CONTIG(init_params->select_param->dt_class)) {
        return;
    }

    ucp_proto_rndv_rts_probe(init_params);
}

ucp_proto_t ucp_stream_rndv_rts_proto = {
    .name     = "stream/rndv/rts",
    .desc     = "rndv rts",
    .flags    = 0,
    .probe    = ucp_stream_rndv_rts_probe,
    .query    = ucp_proto_default_query,
    .progress = {ucp_stream_pmpy_ctrl_progress},
    .abort    = ucp_stream_pmpy_ctrl_abort,
    .reset    = ucp_stream_pmpy_ctrl_reset,
};

static ucs_status_t ucp_stream_rndv_zcopy_send_func(
        ucp_request_t *req, const ucp_proto_multi_lane_priv_t *lpriv,
        ucp_datatype_iter_t *next_iter, ucp_lane_index_t *lane_shift, int put)
{
    uct_rkey_t tl_rkey      = ucp_rkey_get_tl_rkey(req->send.rndv.rkey,
                                                   lpriv->super.rkey_index);
    uint64_t remote_address = req->send.rndv.remote_address +
                              req->send.state.dt_iter.offset;
    uct_ep_h lane;
    uct_iov_t iov;

    ucp_datatype_iter_next_iov(&req->send.state.dt_iter, SIZE_MAX,
                               lpriv->super.md_index,
                               UCS_BIT(UCP_DATATYPE_CONTIG), next_iter, &iov,
                               1);
    lane = ucp_ep_get_lane(req->send.ep, lpriv->super.lane);
    if (put) {
        return uct_ep_put_zcopy(lane, &iov, 1, remote_address, tl_rkey,
                                &req->send.state.uct_comp);
    } else {
        return uct_ep_get_zcopy(lane, &iov, 1, remote_address, tl_rkey,
                                &req->send.state.uct_comp);
    }
}

static void
ucp_stream_rndv_zcopy_complete(uct_completion_t *uct_comp)
{
    ucp_request_t *req = ucs_container_of(uct_comp, ucp_request_t,
                                          send.state.uct_comp);

    ucp_datatype_iter_mem_dereg(&req->send.state.dt_iter,
                                UCS_BIT(UCP_DATATYPE_CONTIG));
    if (ucs_unlikely(uct_comp->status != UCS_OK)) {
        ucp_request_complete_send(req, uct_comp->status);
        return;
    }

    ++req->send.state.uct_comp.count;
    ucp_proto_request_set_stage(req, UCP_STREAM_PUT_STAGE_ACK);
    ucp_request_send(req);
}

static ucs_status_t
ucp_stream_rndv_zcopy_progress(uct_pending_req_t *self, unsigned uct_mem_flags,
                               ucp_proto_send_multi_cb_t send_func)
{
    ucp_request_t *req = ucs_container_of(self, ucp_request_t, send.uct);

    return ucp_proto_multi_zcopy_progress(
            req, req->send.proto_config->priv, NULL, uct_mem_flags,
            UCS_BIT(UCP_DATATYPE_CONTIG), send_func,
            ucp_request_invoke_uct_completion_success,
            ucp_stream_rndv_zcopy_complete);
}

static void
ucp_stream_rndv_zcopy_probe(const ucp_proto_init_params_t *init_params,
                            uct_ep_operation_t send_op, uint64_t tl_cap_flags,
                            ptrdiff_t opt_align_offs, ucp_operation_id_t op_id)
{
    ucp_context_h context                = init_params->worker->context;
    ucp_proto_multi_init_params_t params = {
        .super.super         = *init_params,
        .super.overhead      = 0,
        .super.latency       = 0,
        .super.cfg_thresh    = ucp_proto_rndv_cfg_thresh(context,
                               UCS_BIT(UCP_RNDV_MODE_PUT_ZCOPY)),
        .super.cfg_priority  = 30,
        .super.min_length    = 0,
        .super.max_length    = SIZE_MAX,
        .super.min_iov       = 1,
        .super.min_frag_offs = ucs_offsetof(uct_iface_attr_t,
                                            cap.put.min_zcopy),
        .super.max_frag_offs = ucs_offsetof(uct_iface_attr_t,
                                            cap.put.max_zcopy),
        .super.max_iov_offs  = ucs_offsetof(uct_iface_attr_t, cap.put.max_iov),
        .super.hdr_size      = 0,
        .super.send_op       = send_op,
        .super.memtype_op    = UCT_EP_OP_LAST,
        .super.flags         = UCP_PROTO_COMMON_INIT_FLAG_SEND_ZCOPY |
                               UCP_PROTO_COMMON_INIT_FLAG_RECV_ZCOPY |
                               UCP_PROTO_COMMON_INIT_FLAG_ERR_HANDLING|
                               UCP_PROTO_COMMON_INIT_FLAG_REMOTE_ACCESS |
                               UCP_PROTO_COMMON_INIT_FLAG_RESPONSE |
                               UCP_PROTO_COMMON_INIT_FLAG_MIN_FRAG,
        .super.exclude_map   = 0,
        .super.reg_mem_info  = ucp_proto_common_select_param_mem_info(
                                                     init_params->select_param),
        .max_lanes           = context->config.ext.max_rndv_lanes,
        .initial_reg_md_map  = 0,
        .first.tl_cap_flags  = tl_cap_flags,
        .first.lane_type     = UCP_LANE_TYPE_RMA_BW,
        .middle.tl_cap_flags = tl_cap_flags,
        .middle.lane_type    = UCP_LANE_TYPE_RMA_BW,
        .opt_align_offs      = opt_align_offs
    };
    const char *proto_name = ucp_proto_id_field(init_params->proto_id, name);
    ucp_proto_multi_priv_t mpriv;
    ucp_proto_perf_t *perf;
    ucs_status_t status;

    if (!ucp_proto_init_check_op(init_params, UCS_BIT(op_id))) {
        return;
    }

    if (!(ucp_proto_select_op_flags(init_params->select_param) &
          UCP_PROTO_SELECT_OP_FLAG_STREAM_ACTIVE)) {
        return;
    }

    status = ucp_proto_multi_init(&params, proto_name, &perf, &mpriv);
    if (status != UCS_OK) {
        return;
    }

    ucp_proto_select_add_proto(&params.super.super, params.super.cfg_thresh,
                               params.super.cfg_priority, perf, &mpriv,
                               ucp_proto_multi_priv_size(&mpriv));
}

static ucs_status_t ucp_stream_rndv_put_send_func(
        ucp_request_t *req, const ucp_proto_multi_lane_priv_t *priv,
        ucp_datatype_iter_t *next_iter, ucp_lane_index_t *lane_shift)
{
    return ucp_stream_rndv_zcopy_send_func(req, priv, next_iter, lane_shift, 1);
}

static ucs_status_t ucp_stream_rndv_put_progress(uct_pending_req_t *self)
{
    return ucp_stream_rndv_zcopy_progress(self, UCT_MD_MEM_ACCESS_LOCAL_READ,
                                          ucp_stream_rndv_put_send_func);
}

ucs_status_t ucp_stream_rndv_handle_ack(void *arg, void *data, size_t length,
                                        unsigned flags)
{
    ucp_worker_h worker     = arg;
    ucp_rndv_ack_hdr_t *atp = data;
    ucp_request_t *req;

    UCP_SEND_REQUEST_GET_BY_ID(&req, worker, atp->super.req_id, 0,
                               return UCS_OK, "ATP %p", atp);

    req->send.stream.s->flags &= ~UCP_STREAM_FLAG_ACTIVE;
    req->send.state.dt_iter.offset += atp->size;
    if (req->send.state.dt_iter.offset < req->send.state.dt_iter.length) {
        return UCS_OK;
    }

    ucp_send_request_id_release(req);
    ucp_stream_request_dequeue_and_complete(req, UCS_OK); // TODO why dequeue
    return UCS_OK;
}

UCP_DEFINE_AM_WITH_PROXY(UCP_FEATURE_STREAM, UCP_AM_ID_PMPY_ACK,
                         ucp_stream_rndv_handle_ack, NULL, 0);

typedef struct {
    ucp_request_t *req;
    size_t        ack_size;
} ucp_stream_rndv_ack_pack_ctx_t;

static size_t ucp_stream_rndv_ack_pack(void *dest, void *arg)
{
    ucp_stream_rndv_ack_pack_ctx_t *pack_ctx = arg;
    ucs_status_t status;

    status = ucp_proto_rndv_pack_ack(pack_ctx->req, dest, pack_ctx->ack_size);
    return status;
}

static UCS_F_ALWAYS_INLINE ucs_status_t
ucp_stream_rndv_ack_complete(ucp_request_t *req)
{
    ucp_request_t *buf_req = ucp_request_get_super(req);
    ucp_operation_id_t op_id;
    ucp_stream_t *stream;
    ucp_worker_h worker;

    ucs_assert(buf_req->send.stream.pending > 0);
    ucp_request_put(req);

    if (--buf_req->send.stream.pending > 0) {
        return UCS_OK;
    }

    stream = buf_req->send.stream.s;
    if (buf_req->send.state.dt_iter.offset == buf_req->send.state.dt_iter.length) {
        ucp_stream_request_complete(buf_req, UCS_OK);
        return UCS_OK;
    }

    worker = stream->ep->worker;
    op_id = stream->flags & UCP_STREAM_FLAG_SEND ?  UCP_OP_ID_STREAM_SEND :
                                                    UCP_OP_ID_STREAM_RECV;

    if ((op_id == UCP_OP_ID_STREAM_RECV) &&
        (worker->context->config.ext.rndv_mode != UCP_RNDV_MODE_PUT_ZCOPY)) {
       return UCS_OK;
    }

    ucp_stream_pmpy_ctrl(worker, buf_req->send.ep, buf_req, op_id);
    return UCS_OK;
}

static UCS_F_ALWAYS_INLINE ucs_status_t
ucp_stream_rndv_atp_send(ucp_request_t *req, ucp_lane_index_t lane)
{
    const ucp_proto_multi_priv_t *mpriv = req->send.proto_config->priv;
    ucp_stream_rndv_ack_pack_ctx_t pack_ctx;
    ucs_status_t status;
    size_t atp_num_lanes = ucs_popcount(mpriv->lane_map);
    ucp_proto_complete_cb_t comp_cb;

    if (req->send.rndv.put.atp_count == req->send.state.dt_iter.length) {
        return UCS_OK;
    }

    if (ucs_unlikely((req->send.state.dt_iter.length < atp_num_lanes) &&
                     (lane < req->send.multi_lane_idx))) {
        return UCS_OK;
    }

    pack_ctx.req = req;

    if (req->send.rndv.put.atp_count == (atp_num_lanes - 1)) {
        pack_ctx.ack_size = req->send.state.dt_iter.length -
                            req->send.rndv.put.atp_count;
        comp_cb = ucp_stream_rndv_ack_complete;
    } else {
        pack_ctx.ack_size = 1;
        comp_cb = NULL;
    }

    status = ucp_proto_am_bcopy_single_progress(req, UCP_AM_ID_PMPY_ACK, lane,
                                            ucp_stream_rndv_ack_pack,
                                            &pack_ctx,
                                            sizeof(ucp_rndv_ack_hdr_t),
                                            comp_cb, 0);
    if (status != UCS_OK) {
        return status;
    }

    ++req->send.rndv.put.atp_count;
    return UCS_OK;
}

static ucs_status_t ucp_stream_rndv_atp_progress(uct_pending_req_t *self)
{
    ucp_request_t *req = ucs_container_of(self, ucp_request_t, send.uct);
    const ucp_proto_multi_priv_t *mpriv = req->send.proto_config->priv;

    return ucp_proto_multi_lane_map_progress(req, &req->send.rndv.stream.atp_lane,
                                             mpriv->lane_map,
                                             ucp_stream_rndv_atp_send);
}

static void
ucp_stream_rndv_put_probe(const ucp_proto_init_params_t *init_params)
{
    ucp_stream_rndv_zcopy_probe(init_params, UCT_EP_OP_PUT_ZCOPY,
                                UCT_IFACE_FLAG_PUT_ZCOPY,
                                ucs_offsetof(uct_iface_attr_t,
                                             cap.put.opt_zcopy_align),
                                UCP_OP_ID_STREAM_SEND);
}

ucp_proto_t ucp_stream_rndv_put_proto = {
    .name     = "stream/rndv/put",
    .desc     = "rndv put",
    .flags    = 0,
    .probe    = ucp_stream_rndv_put_probe,
    .query    = ucp_proto_default_query,
    .progress = {
        [UCP_STREAM_PUT_STAGE_SEND] = ucp_stream_rndv_put_progress,
        [UCP_STREAM_PUT_STAGE_ACK]  = ucp_stream_rndv_atp_progress,
    },
    .abort    = ucp_proto_request_bcopy_abort,
    .reset    = ucp_proto_request_bcopy_reset
};

static ucs_status_t ucp_stream_rndv_get_send_func(
        ucp_request_t *req, const ucp_proto_multi_lane_priv_t *priv,
        ucp_datatype_iter_t *next_iter, ucp_lane_index_t *lane_shift)
{
    return ucp_stream_rndv_zcopy_send_func(req, priv, next_iter, lane_shift, 0);
}

static ucs_status_t ucp_stream_rndv_get_progress(uct_pending_req_t *self)
{
    return ucp_stream_rndv_zcopy_progress(self, UCT_MD_MEM_ACCESS_LOCAL_WRITE,
                                          ucp_stream_rndv_get_send_func);
}

ucs_status_t ucp_stream_rndv_ats_progress(uct_pending_req_t *self)
{
    ucp_request_t *req = ucs_container_of(self, ucp_request_t, send.uct);
    const ucp_proto_multi_priv_t *mpriv = req->send.proto_config->priv;
    ucp_stream_rndv_ack_pack_ctx_t pack_ctx;

    pack_ctx.req = req;
    pack_ctx.ack_size = req->send.state.dt_iter.length;

    return ucp_proto_am_bcopy_single_progress(req, UCP_AM_ID_PMPY_ACK,
                                              ucs_ffs64(mpriv->lane_map),
                                              ucp_stream_rndv_ack_pack, &pack_ctx,
                                              sizeof(ucp_rndv_ack_hdr_t),
                                              ucp_stream_rndv_ack_complete, 0);
}

static void
ucp_stream_rndv_get_probe(const ucp_proto_init_params_t *init_params)
{
    ucp_stream_rndv_zcopy_probe(init_params, UCT_EP_OP_GET_ZCOPY,
                                UCT_IFACE_FLAG_GET_ZCOPY,
                                UCP_PROTO_COMMON_OFFSET_INVALID,
                                UCP_OP_ID_STREAM_RECV);
}

ucp_proto_t ucp_stream_rndv_get_proto = {
    .name     = "stream/rndv/get",
    .desc     = "rndv get",
    .flags    = 0,
    .probe    = ucp_stream_rndv_get_probe,
    .query    = ucp_proto_default_query,
    .progress = {
        [UCP_STREAM_PUT_STAGE_SEND] = ucp_stream_rndv_get_progress,
        [UCP_STREAM_PUT_STAGE_ACK]  = ucp_stream_rndv_ats_progress,
    },
    .abort    = ucp_proto_request_bcopy_abort,
    .reset    = ucp_proto_request_bcopy_reset
};
