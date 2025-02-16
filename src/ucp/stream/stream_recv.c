/**
 * Copyright (c) NVIDIA CORPORATION & AFFILIATES, 2001-2017. ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "stream.h"
#include <ucp/core/ucp_ep.h>
#include <ucp/core/ucp_worker.h>
#include <ucp/core/ucp_context.h>
#include <ucp/core/ucp_request.h>
#include <ucp/stream/stream.h>

#include <ucs/datastruct/mpool.inl>
#include <ucs/profile/profile.h>


/* @verbatim
 * Data layout within Stream AM
 * |---------------------------------------------------------------------------------------------------------------------------|
 * | ucp_recv_desc_t                                                 | \    / | ucp_stream_am_data_t | payload                 |
 * |-----------------------------------------------------------------|  \  /  |----------------------|-------------------------|
 * | stream_queue        | length         | payload_offset | flags   |   \/   | am_header            |                         |
 * | tag_list (not used) |                |                |         |   /\   | rdesc                |                         |
 * |---------------------|----------------|----------------|---------|  /  \  |----------------------|-------------------------|
 * | 4 * sizeof(ptr)     | 32 bits        | 32 bits        | 16 bits | /    \ | 64 bits              | up to TL AM buffer size |
 * |---------------------------------------------------------------------------------------------------------------------------|
 * @endverbatim
 *
 * stream_queue   is an entry link in the "unexpected" queue per endpoint
 * length         is an actual size of 'payload'
 * payload_offset is a distance between 'ucp_recv_desc_t *' and 'payload *'
 * X              is an optional empty space which is a result of partial
 *                handled payload in case when 'length' greater than user's
 *                buffer size passed to @ref ucp_stream_recv_nb
 * am_header      is an active message header, not actual after ucp_recv_desc_t
 *                initialization and setup of offsets
 * rdesc          pointer to 'ucp_recv_desc_t *', it's needed to get access to
 *                'ucp_recv_desc_t *' inside @ref ucp_stream_release_data after
 *                the buffer was returned to user by
 *                @ref ucp_stream_recv_data_nb as a pointer to 'payload'
 */


#define ucp_stream_rdesc_payload(_rdesc)                                      \
    (UCS_PTR_BYTE_OFFSET((_rdesc), (_rdesc)->payload_offset))


#define ucp_stream_rdesc_am_data(_rdesc)                                      \
    ((ucp_stream_am_data_t *)                                                 \
     UCS_PTR_BYTE_OFFSET(ucp_stream_rdesc_payload(_rdesc),                    \
                         -sizeof(ucp_stream_am_data_t)))


#define ucp_stream_rdesc_from_data(_data)                                     \
    ((ucp_stream_am_data_t *)_data - 1)->rdesc


static UCS_F_ALWAYS_INLINE ucs_status_ptr_t
ucp_stream_recv_data_nb_nolock(ucp_stream_t *stream, size_t *length)
{
    ucp_recv_desc_t      *rdesc;
    ucp_stream_am_data_t *am_data;

    if (ucs_unlikely(!ucp_stream_has_data(stream))) {
        return UCS_STATUS_PTR(UCS_OK);
    }

    rdesc = ucp_stream_rdesc_dequeue(stream);

    *length         = rdesc->length;
    am_data         = ucp_stream_rdesc_am_data(rdesc);
    am_data->rdesc  = rdesc;
    return am_data + 1;
}

UCS_PROFILE_FUNC(ucs_status_ptr_t, ucp_stream_recv_data_nb, (ep, length),
                 ucp_ep_h ep, size_t *length)
{
    ucp_stream_t *stream;
    ucs_status_ptr_t ret;
    ucs_status_t status;

    UCP_CONTEXT_CHECK_FEATURE_FLAGS(ep->worker->context, UCP_FEATURE_STREAM,
                                    return UCS_STATUS_PTR(UCS_ERR_INVALID_PARAM));

    UCP_WORKER_THREAD_CS_ENTER_CONDITIONAL(ep->worker);
    status = ucp_stream_get(ep->worker, ep->ext->local_ep_id, -1ULL, 0, &stream);
    if (status != UCS_OK) {
        ret = UCS_STATUS_PTR(status);
        goto out;
    }

    ret = ucp_stream_recv_data_nb_nolock(stream, length);

out:
    UCP_WORKER_THREAD_CS_EXIT_CONDITIONAL(ep->worker);
    return ret;
}

static UCS_F_ALWAYS_INLINE void
ucp_stream_rdesc_dequeue_and_release(ucp_recv_desc_t *rdesc,
                                     ucp_stream_t *stream)
{
    ucs_assert(ucp_stream_has_data(stream));
    ucs_assert(rdesc == ucs_queue_head_elem_non_empty(&stream->q,
                                                      ucp_recv_desc_t,
                                                      stream_queue));
    ucp_stream_rdesc_dequeue(stream);
    ucp_recv_desc_release(rdesc);
}

UCS_PROFILE_FUNC_VOID(ucp_stream_data_release, (ep, data),
                      ucp_ep_h ep, void *data)
{
    ucp_recv_desc_t *rdesc = ucp_stream_rdesc_from_data(data);

    UCP_WORKER_THREAD_CS_ENTER_CONDITIONAL(ep->worker);

    ucp_recv_desc_release(rdesc);

    UCP_WORKER_THREAD_CS_EXIT_CONDITIONAL(ep->worker);
}


static UCS_F_ALWAYS_INLINE int
ucp_request_can_complete_stream_recv(ucp_request_t *req)
{
    /* NOTE: first check is needed to avoid heavy "%" operation if request is
     *       completely filled */
    if (req->send.state.dt_iter.offset == req->send.state.dt_iter.length) {
        return 1;
    }

    if (/* Need to wait for all data to arrive */
        (req->flags & UCP_REQUEST_FLAG_STREAM_RECV_WAITALL) ||
        /* 0-length receive is meaningless, unless was requested explicitly */
        (req->send.state.dt_iter.offset == 0)) {
        return 0;
    }

    if (ucs_unlikely(req->send.state.dt_iter.dt_class != UCP_DATATYPE_CONTIG)) {
        /* Currently, all data types except contig have 1-byte granularity */
        return 1;
    }

    return (req->send.state.dt_iter.offset % req->send.stream.elem_size) == 0;
}

static UCS_F_ALWAYS_INLINE ssize_t
ucp_stream_rdata_unpack(const void *rdata, size_t length, ucp_request_t *dst_req)
{
    size_t offset = dst_req->send.state.dt_iter.offset;
    ucs_status_t status;
    size_t valid_len;
    int last, dereg;

    /* Truncated error is not actual for stream, need to adjust */
    valid_len = dst_req->send.state.dt_iter.length - offset;
    if (valid_len <= length) {
        last = (valid_len == length);
    } else {
        valid_len = length;
        last      = !(dst_req->flags & UCP_REQUEST_FLAG_STREAM_RECV_WAITALL);
    }
    status = ucp_datatype_iter_unpack(&dst_req->send.state.dt_iter, dst_req->send.ep->worker,
                                      valid_len, offset, rdata);
    if (last || (status != UCS_OK)) {
        dereg = dst_req->flags & UCP_REQUEST_FLAG_PROTO_INITIALIZED;
        ucp_datatype_iter_cleanup(&dst_req->send.state.dt_iter, dereg, UCP_DT_MASK_ALL);
    }

    if (ucs_likely(status == UCS_OK)) {
        dst_req->send.state.dt_iter.offset = offset + valid_len;
        return valid_len;
    }

    ucs_assert(status != UCS_ERR_MESSAGE_TRUNCATED);
    return status;
}

static UCS_F_ALWAYS_INLINE ucs_status_t
ucp_stream_rdesc_advance(ucp_recv_desc_t *rdesc, ssize_t offset,
                         ucp_stream_t *stream)
{
    ucs_assert(offset <= rdesc->length);

    if (ucs_unlikely(offset < 0)) {
        return (ucs_status_t)offset;
    } else if (ucs_likely(offset == rdesc->length)) {
        ucp_stream_rdesc_dequeue_and_release(rdesc, stream);
    } else {
        rdesc->length         -= offset;
        rdesc->payload_offset += offset;
    }

    return UCS_OK;
}

static UCS_F_ALWAYS_INLINE ucs_status_t
ucp_stream_process_rdesc(ucp_recv_desc_t *rdesc, ucp_stream_t *stream,
                         ucp_request_t *req)
{
    ssize_t unpacked;

    if (rdesc->flags & UCP_RECV_DESC_FLAG_RNDV) {
        return ucp_stream_rndv_process_rdesc(rdesc, req, stream,
                                             UCP_OP_ID_STREAM_RECV);
    }

    unpacked = ucp_stream_rdata_unpack(ucp_stream_rdesc_payload(rdesc),
                                       rdesc->length, req);
    ucs_assertv(req->send.state.dt_iter.offset <= req->send.state.dt_iter.length,
                "req=%p offset=%zu length=%zu", req, req->send.state.dt_iter.offset,
                req->send.state.dt_iter.length);

    return ucp_stream_rdesc_advance(rdesc, unpacked, stream);
}

static UCS_F_ALWAYS_INLINE ucs_status_t
ucp_stream_recv_request_init(ucp_request_t *req, ucp_ep_h ep, void *buffer,
                             size_t count, const ucp_request_param_t *param)
{
    ucp_worker_h worker     = ep->worker;
    ucp_datatype_t datatype = ucp_request_param_datatype(param);
    uint32_t flags          = ucp_request_param_flags(param);

    req->flags              = UCP_REQUEST_FLAG_PROTO_SEND |
                              UCP_REQUEST_FLAG_STREAM_RECV |
                              ((flags & UCP_STREAM_RECV_FLAG_WAITALL) ?
                               UCP_REQUEST_FLAG_STREAM_RECV_WAITALL : 0);
#if UCS_ENABLE_ASSERT
    req->status             = UCS_OK; /* for ucp_request_recv_data_unpack() */
#endif

    req->send.ep           = ep;
    req->send.stream.elem_size = ucp_contig_dt_elem_size(datatype);
    req->send.stream.pending = 0;
    ucp_stream_get_param(ep, param, 0, &req->send.stream.s);

    if (param->op_attr_mask & UCP_OP_ATTR_FIELD_CALLBACK) {
        req->flags         |= UCP_REQUEST_FLAG_CALLBACK;
        req->send.recv_cb   = param->cb.recv_stream;
        req->user_data      = ucp_request_param_user_data(param);
    }

    return ucp_datatype_iter_init_unpack(worker->context, buffer, count,
                                         &req->send.state.dt_iter, param);
}

UCS_PROFILE_FUNC(ucs_status_ptr_t, ucp_stream_recv_nb,
                 (ep, buffer, count, datatype, cb, length, flags),
                 ucp_ep_h ep, void *buffer, size_t count,
                 ucp_datatype_t datatype, ucp_stream_recv_callback_t cb,
                 size_t *length, unsigned flags)
{
    ucp_request_param_t param = {
        .op_attr_mask   = UCP_OP_ATTR_FIELD_DATATYPE |
                          UCP_OP_ATTR_FIELD_CALLBACK |
                          UCP_OP_ATTR_FIELD_FLAGS,
        .cb.recv_stream = (ucp_stream_recv_nbx_callback_t)cb,
        .flags          = flags,
        .datatype       = datatype
    };

    return ucp_stream_recv_nbx(ep, buffer, count, length, &param);
}

static UCS_F_ALWAYS_INLINE ucs_status_t
ucp_stream_try_recv_inplace(ucp_stream_t *stream, void *buffer, size_t count,
                            size_t *length, const ucp_request_param_t *param)
{
    ucp_recv_desc_t *rdesc;
    ucs_status_t status;
    uint32_t attr_mask;
    size_t recv_length;
    size_t elem_size;

    if (!ucp_stream_has_data(stream)) {
        return UCS_ERR_NO_PROGRESS;
    }

    attr_mask = param->op_attr_mask &
                (UCP_OP_ATTR_FIELD_DATATYPE | UCP_OP_ATTR_FLAG_NO_IMM_CMPL);
    if (ucs_likely(attr_mask == 0)) {
        elem_size   = 1;
        recv_length = count;
    } else if (attr_mask == UCP_OP_ATTR_FIELD_DATATYPE) {
        if (UCP_DT_IS_CONTIG(param->datatype)) {
            elem_size   = ucp_contig_dt_elem_size(param->datatype);
            recv_length = elem_size * count;
        } else if (UCP_DT_IS_IOV(param->datatype)) {
            elem_size   = 1;
            recv_length = ucp_dt_iov_length(buffer, count);
        } else {
            return UCS_ERR_NO_PROGRESS;
        }
    } else {
        ucs_assertv(attr_mask & UCP_OP_ATTR_FLAG_NO_IMM_CMPL,
                    "op_attr_mask=0x%x", param->op_attr_mask);
        return UCS_ERR_NO_PROGRESS;
    }

    rdesc = ucp_stream_rdesc_get(stream);
    if (rdesc->flags & UCP_RECV_DESC_FLAG_RNDV) {
        return UCS_ERR_NO_PROGRESS;
    }

    if (rdesc->length < recv_length) {
        if (/* Need to fill the receive buffer */
            (ucp_request_param_flags(param) & UCP_STREAM_RECV_FLAG_WAITALL) ||
            /* Need at least one element */
            (rdesc->length < elem_size)) {
            return UCS_ERR_NO_PROGRESS;
        }

        /* Unpack as much data as we have to the user buffer and respect element
           size granularity */
        recv_length = ucs_align_down(rdesc->length, elem_size);
    }

    ucs_assertv(recv_length > 0, "count=%zu elem_size=%zu", count, elem_size);
    status = ucp_datatype_iter_unpack_single(stream->ep->worker, buffer, count,
                                             ucp_stream_rdesc_payload(rdesc),
                                             recv_length, 0, param);
    if (status != UCS_OK) {
        return status;
    }

    *length = recv_length;
    return ucp_stream_rdesc_advance(rdesc, recv_length, stream);
}

static ucs_status_ptr_t
ucp_stream_recv_request(ucp_request_t *req, size_t *length,
                        const ucp_request_param_t *param)
{
    ucp_stream_t *stream = req->send.stream.s;
    ucp_recv_desc_t *rdesc;
    ucs_status_t status;

    /* OK, lets obtain all arrived data which matches the recv size */
    while ((req->send.state.dt_iter.offset < req->send.state.dt_iter.length) &&
           ucp_stream_has_data(stream)) {
        rdesc  = ucp_stream_rdesc_get(stream);
        status = ucp_stream_process_rdesc(rdesc, stream, req);
        if (ucs_unlikely(status != UCS_OK)) {
            return UCS_STATUS_PTR(status);
        }

        /*
         * NOTE: generic datatype can be completed with any amount of data to
         *       avoid extra logic in ucp_stream_process_rdesc, exception is
         *       WAITALL flag
         */
        if (ucs_unlikely(req->send.state.dt_iter.dt_class == UCP_DATATYPE_GENERIC) &&
            !(req->flags & UCP_REQUEST_FLAG_STREAM_RECV_WAITALL)) {
            break;
        }
    }

    ucs_assert(req->send.state.dt_iter.offset <= req->send.state.dt_iter.length);

    if (req->send.stream.pending > 0) {
        if (req->send.state.dt_iter.offset < req->send.state.dt_iter.length) {
            ucp_stream_req_enqueue(req);
        }
        return req + 1;
    }

    if (ucp_request_can_complete_stream_recv(req)) {
        *length = req->send.state.dt_iter.offset;
        ucp_request_imm_cmpl_param(param, req, recv_stream,
                                   req->send.state.dt_iter.offset);
        /* unreachable */
    }

    ucs_assert(!ucp_stream_has_data(stream));
    return ucp_stream_pmpy_recv(req);
}

UCS_PROFILE_FUNC(ucs_status_ptr_t, ucp_stream_recv_nbx,
                 (ep, buffer, count, length, param), ucp_ep_h ep, void *buffer,
                 size_t count, size_t *length, const ucp_request_param_t *param)
{
    ucp_stream_t *stream;
    ucs_status_ptr_t ret;
    ucs_status_t status;
    ucp_request_t *req;

    UCP_CONTEXT_CHECK_FEATURE_FLAGS(ep->worker->context, UCP_FEATURE_STREAM,
                                    return UCS_STATUS_PTR(
                                            UCS_ERR_INVALID_PARAM));
    UCP_REQUEST_CHECK_PARAM(param);

    UCP_WORKER_THREAD_CS_ENTER_CONDITIONAL(ep->worker);

    status = ucp_stream_get_param(ep, param, 0, &stream);
    if (status != UCS_OK) {
        ret = UCS_STATUS_PTR(UCS_ERR_NO_MEMORY);
        goto out;
    }

    status = ucp_stream_try_recv_inplace(stream, buffer, count, length, param);
    if (status != UCS_ERR_NO_PROGRESS) {
        ret = UCS_STATUS_PTR(status);
        goto out;
    }

    if (ucs_unlikely(param->op_attr_mask & UCP_OP_ATTR_FLAG_FORCE_IMM_CMPL)) {
        ret = UCS_STATUS_PTR(UCS_ERR_NO_RESOURCE);
        goto out;
    }

    req = ucp_request_get_param(ep->worker, param,
                                {ret = UCS_STATUS_PTR(UCS_ERR_NO_MEMORY);
                                 goto out;});

    status = ucp_stream_recv_request_init(req, ep, buffer, count, param);
    if (ucs_unlikely(status != UCS_OK)) {
        ret = UCS_STATUS_PTR(status);
        goto err_put_req;
    }

    ret = ucp_stream_recv_request(req, length, param);
    if (ucs_unlikely(UCS_PTR_IS_ERR(ret))) {
        goto err_put_req;
    }

out:
    UCP_WORKER_THREAD_CS_EXIT_CONDITIONAL(ep->worker);
    return ret;

err_put_req:
    ucp_request_put_param(param, req);
    goto out;
}

static UCS_F_ALWAYS_INLINE ucs_status_t
ucp_stream_am_data_process(ucp_worker_t *worker, ucp_stream_t *stream,
                           ucp_stream_am_data_t *am_data, size_t length,
                           unsigned am_flags)
{
    ucp_recv_desc_t  rdesc_tmp;
    void            *payload;
    ucp_recv_desc_t *rdesc;
    ucp_request_t   *req;
    ssize_t          unpacked;

    rdesc_tmp.length         = length;
    rdesc_tmp.payload_offset = sizeof(*am_data); /* add sizeof(*rdesc) only if
                                                    am_data won't be handled in
                                                    place */

    /* First, process expected requests */
    if (!ucp_stream_has_data(stream)) {
        while (!ucs_queue_is_empty(&stream->q)) {
            req      = ucs_queue_head_elem_non_empty(&stream->q,
                                                     ucp_request_t, send.stream.queue);
            payload  = UCS_PTR_BYTE_OFFSET(am_data, rdesc_tmp.payload_offset);
            unpacked = ucp_stream_rdata_unpack(payload, rdesc_tmp.length, req);
            if (ucs_unlikely(unpacked < 0)) {
                ucs_fatal("failed to unpack from am_data %p with offset %u to request %p",
                          am_data, rdesc_tmp.payload_offset, req);
            } else if (unpacked == rdesc_tmp.length) {
                if (ucp_request_can_complete_stream_recv(req)) {
                    ucp_stream_request_dequeue_and_complete(req, UCS_OK);
                }
                return UCS_OK;
            }
            ucp_stream_rdesc_advance(&rdesc_tmp, unpacked, stream);
            /* This request is full, try next one */
            ucs_assert(ucp_request_can_complete_stream_recv(req));
            ucp_stream_request_dequeue_and_complete(req, UCS_OK);
        }

    }

    ucp_stream_enqueue(stream, worker);
    ucs_assert(rdesc_tmp.length > 0);

    /* Now, enqueue the rest of data */
    if (ucs_likely(!(am_flags & UCT_CB_PARAM_FLAG_DESC))) {
        rdesc = (ucp_recv_desc_t*)ucs_mpool_set_get_inline(&worker->am_mps,
                                                           length);
        ucs_assertv_always(rdesc != NULL,
                           "ucp recv descriptor is not allocated");
        rdesc->length              = rdesc_tmp.length;
        /* reset offset to improve locality */
        rdesc->payload_offset      = sizeof(*rdesc) + sizeof(*am_data);
        rdesc->flags               = 0;
        rdesc->release_desc_offset = 0;
        ucp_recv_desc_set_name(rdesc, "stream_am_data_process");
        memcpy(ucp_stream_rdesc_payload(rdesc),
               UCS_PTR_BYTE_OFFSET(am_data, rdesc_tmp.payload_offset),
               rdesc_tmp.length);
    } else {
        /* slowpath */
        rdesc                      = (ucp_recv_desc_t *)am_data - 1;
        rdesc->length              = rdesc_tmp.length;
        rdesc->payload_offset      = rdesc_tmp.payload_offset + sizeof(*rdesc);
        rdesc->release_desc_offset = UCP_WORKER_HEADROOM_PRIV_SIZE;
        rdesc->flags               = UCP_RECV_DESC_FLAG_UCT_DESC;
    }

    ucp_stream_rdesc_enqueue(stream, rdesc);
    return UCS_INPROGRESS;
}

void ucp_stream_ep_init(ucp_ep_h ep)
{
}

void ucp_stream_cleanup(ucp_stream_t *stream, ucs_status_t status)
{
    ucp_recv_desc_t *rdesc;
    ucp_request_t *req;

    if (ucp_stream_has_data(stream)) {
        while (!ucs_queue_is_empty(&stream->q)) {
            rdesc = ucp_stream_rdesc_get(stream);
            ucp_stream_rdesc_dequeue(stream);
            if (rdesc->flags & UCP_RECV_DESC_FLAG_RNDV) {
                ucp_stream_rndv_desc_release(rdesc);
            } else {
                ucp_recv_desc_release(rdesc);
            }
        }
    } else {
        while (!ucs_queue_is_empty(&stream->q)) {
            req = ucs_queue_head_elem_non_empty(&stream->q,
                    ucp_request_t, send.stream.queue);
            ucp_stream_request_dequeue_and_complete(req, status);
        }
    }
}

void ucp_stream_ep_cleanup(ucp_ep_h ep, ucs_status_t status)
{
    ucp_stream_t *stream;

    if (!(ep->worker->context->config.features & UCP_FEATURE_STREAM)) {
        return;
    }

    kh_foreach_value(&ep->worker->stream_hash, stream, {
        if (stream->ep != ep) {
            continue;
        }
        ucp_stream_cleanup(stream, status);
        kh_del(ucp_worker_stream_hash, &ep->worker->stream_hash, __i);
        ucs_free(stream);
    });
}

void ucp_stream_ep_activate(ucp_ep_h ep)
{
}

static UCS_F_ALWAYS_INLINE ucs_status_t
ucp_stream_am_handler(void *am_arg, void *am_data, size_t am_length,
                      unsigned am_flags)
{
    ucp_worker_h          worker    = am_arg;
    ucp_stream_am_data_t *data      = am_data;
    ucp_stream_t          *stream   = NULL;
    ucs_status_t          status;

    ucs_assert(am_length >= sizeof(ucp_stream_am_hdr_t));

    status = ucp_stream_get(worker, data->hdr.ep_id, data->hdr.stream_id, 0,
                            &stream);
    /* Drop the date if the endpoint is invalid */
    if (status != UCS_OK) {
        return UCS_OK;
    }
    status = ucp_stream_am_data_process(worker, stream, data,
                                        am_length - sizeof(data->hdr),
                                        am_flags);
    if (status == UCS_OK) {
        /* rdesc was processed in place */
        return UCS_OK;
    }

    ucs_assert(status == UCS_INPROGRESS);

    return (am_flags & UCT_CB_PARAM_FLAG_DESC) ? UCS_INPROGRESS : UCS_OK;
}

static void ucp_stream_am_dump(ucp_worker_h worker, uct_am_trace_type_t type,
                               uint8_t id, const void *data, size_t length,
                               char *buffer, size_t max)
{
    const ucp_stream_am_hdr_t *hdr    = data;
    size_t                    hdr_len = sizeof(*hdr);
    char                      *p;

    snprintf(buffer, max, "STREAM ep_id 0x%"PRIx64, hdr->ep_id);
    p = buffer + strlen(buffer);

    ucs_assert(hdr->ep_id != UCS_PTR_MAP_KEY_INVALID);
    ucp_dump_payload(worker->context, p, buffer + max - p,
                     UCS_PTR_BYTE_OFFSET(data, hdr_len), length - hdr_len);
}

UCP_DEFINE_AM_WITH_PROXY(UCP_FEATURE_STREAM, UCP_AM_ID_STREAM_DATA,
                         ucp_stream_am_handler, ucp_stream_am_dump, 0);
