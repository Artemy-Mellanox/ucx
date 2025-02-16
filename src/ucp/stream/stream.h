/**
 * Copyright (c) NVIDIA CORPORATION & AFFILIATES, 2001-2017. ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#ifndef UCP_STREAM_H_
#define UCP_STREAM_H_

#include <ucp/core/ucp_ep.h>
#include <ucp/core/ucp_ep.inl>
#include <ucp/core/ucp_worker.h>
#include <ucp/core/ucp_request.inl>


#define UCP_PROTO_STREAM_OP_ID_MASK \
    (UCS_BIT(UCP_OP_ID_STREAM_SEND) | UCS_BIT(UCP_OP_ID_STREAM_RECV))


typedef struct {
    uint64_t                 ep_id;
    uint64_t                 stream_id;
} UCS_S_PACKED ucp_stream_am_hdr_t;


typedef struct {
    union {
        ucp_stream_am_hdr_t  hdr;
        ucp_recv_desc_t     *rdesc;
    };
} ucp_stream_am_data_t;

struct ucp_stream_key {
    uint64_t ep_id;
    uint64_t stream_id;
    int      direction;
};

enum {
    UCP_STREAM_FLAG_TRANSITION = UCS_BIT(0),
    UCP_STREAM_FLAG_ACTIVE     = UCS_BIT(1),
    UCP_STREAM_FLAG_SEND       = UCS_BIT(2),
    UCP_STREAM_FLAG_HAS_DATA   = UCS_BIT(3),
};

struct ucp_stream {
    ucp_ep_h                  ep;       /* Back pointer to endpoint */
    uint64_t                  stream_id;
    ucs_queue_head_t          q;        /* Queue of receive data or requests,
                                           depends on UCP_STREAM_FLAG_HAS_DATA */
    uint64_t                  local_seq;
    uint64_t                  remote_seq;
    unsigned                  flags;

    uint64_t                  unexp_eager_count;

    ucs_list_link_t           ready_list;
};

void ucp_stream_ep_init(ucp_ep_h ep);

void ucp_stream_ep_cleanup(ucp_ep_h ep, ucs_status_t status);

void ucp_stream_ep_activate(ucp_ep_h ep);


static UCS_F_ALWAYS_INLINE khint32_t
ucp_worker_stream_hash_func(ucp_stream_key_t key)
{
    return kh_int64_hash_func(key.ep_id | key.stream_id | key.direction);
}

static UCS_F_ALWAYS_INLINE int
ucp_worker_stream_hash_eq(ucp_stream_key_t key1, ucp_stream_key_t key2)
{
    return (key1.ep_id == key2.ep_id) && (key1.stream_id == key2.stream_id) &&
           (key1.direction == key2.direction);
}

KHASH_IMPL(ucp_worker_stream_hash, ucp_stream_key_t, ucp_stream_t*, 1,
           ucp_worker_stream_hash_func, ucp_worker_stream_hash_eq);

static UCS_F_ALWAYS_INLINE int ucp_stream_is_queued(ucp_stream_t *stream)
{
    return stream->ready_list.next != NULL;
}

static UCS_F_ALWAYS_INLINE int ucp_stream_has_data(ucp_stream_t *stream)
{
    return stream->flags & UCP_STREAM_FLAG_HAS_DATA;
}

static UCS_F_ALWAYS_INLINE void
ucp_stream_enqueue(ucp_stream_t *stream, ucp_worker_h worker)
{
    stream->flags |= UCP_STREAM_FLAG_HAS_DATA;
    if (!ucp_stream_is_queued(stream)) {
        ucs_list_add_tail(&worker->streams_ready, &stream->ready_list);
    }
}

static UCS_F_ALWAYS_INLINE void ucp_stream_dequeue(ucp_stream_t *stream)
{
    ucs_list_del(&stream->ready_list);
    stream->ready_list.next = NULL;
}

static UCS_F_ALWAYS_INLINE ucp_stream_t *
ucp_stream_worker_dequeue_head(ucp_worker_h worker)
{
    ucp_stream_t *stream = ucs_list_head(&worker->streams_ready,
                                         ucp_stream_t, ready_list);

    ucs_assert(stream->ready_list.next != NULL);
    ucp_stream_dequeue(stream);
    return stream;
}

static UCS_F_ALWAYS_INLINE void ucp_stream_req_enqueue(ucp_request_t *req)
{
    ucp_stream_t *stream = req->send.stream.s;

    ucs_assert(!(ucp_stream_has_data(stream)));
    ucs_queue_push(&stream->q, &req->send.stream.queue);
}

static UCS_F_ALWAYS_INLINE void
ucp_stream_rdesc_enqueue(ucp_stream_t *stream, ucp_recv_desc_t *rdesc)
{
    ucs_assert(ucp_stream_has_data(stream));
    ucs_queue_push(&stream->q, &rdesc->stream_queue);
}

static UCS_F_ALWAYS_INLINE ucp_recv_desc_t *
ucp_stream_rdesc_dequeue(ucp_stream_t *stream)
{
    ucp_recv_desc_t *rdesc = ucs_queue_pull_elem_non_empty(&stream->q,
                                                           ucp_recv_desc_t,
                                                           stream_queue);
    ucs_assert(ucp_stream_has_data(stream));
    if (ucs_unlikely(ucs_queue_is_empty(&stream->q))) {
        stream->flags &= ~UCP_STREAM_FLAG_HAS_DATA;
        if (ucp_stream_is_queued(stream)) {
            ucp_stream_dequeue(stream);
        }
    }

    return rdesc;
}

static UCS_F_ALWAYS_INLINE ucp_recv_desc_t *
ucp_stream_rdesc_get(ucp_stream_t *stream)
{
    ucp_recv_desc_t *rdesc = ucs_queue_head_elem_non_empty(&stream->q,
                                                           ucp_recv_desc_t,
                                                           stream_queue);

    ucs_assert(ucp_stream_has_data(stream));
    ucs_trace_data("ep %p, rdesc %p with %u stream bytes", stream->ep, rdesc,
                   rdesc->length);
    return rdesc;
}

static UCS_F_ALWAYS_INLINE void
ucp_stream_request_complete(ucp_request_t *req, ucs_status_t status)
{
    size_t length;

    ucs_assert(req->send.stream.pending == 0);
    if (req->flags & UCP_REQUEST_FLAG_PROTO_INITIALIZED) {
        ucp_send_request_id_release(req);
        ucp_datatype_iter_mem_dereg(&req->send.state.dt_iter, UCP_DT_MASK_ALL);
    }

    length = req->send.state.dt_iter.offset;
    ucs_trace_req(
            "completing stream receive request %p (%p) " UCP_REQUEST_FLAGS_FMT
            " count %zu, %s",
            req, req + 1, UCP_REQUEST_FLAGS_ARG(req->flags),
            length, ucs_status_string(status));
    UCS_PROFILE_REQUEST_EVENT(req, "complete_stream_recv", status);

    if (req->send.stream.s->flags & UCP_STREAM_FLAG_SEND) {
        ucp_request_complete(req, send.cb, status, req->user_data);
    } else {
        ucp_request_complete(req, send.recv_cb, status, length, req->user_data);
    }
}


static UCS_F_ALWAYS_INLINE void
ucp_stream_request_dequeue_and_complete(ucp_request_t *req, ucs_status_t status)
{
    /* dequeue request before complete */
    ucp_request_t *UCS_V_UNUSED check_req;

    check_req = ucs_queue_pull_elem_non_empty(&req->send.stream.s->q,
                                              ucp_request_t, send.stream.queue);
    ucs_assert(check_req == req);
    ucs_assert((req->send.state.dt_iter.offset > 0) || UCS_STATUS_IS_ERR(status));

    if (req->send.stream.pending == 0 || status != UCS_OK) {
        ucp_stream_request_complete(req, status);
    }
}

static UCS_F_ALWAYS_INLINE ucs_status_t
ucp_stream_create(ucp_ep_h ep, uint64_t stream_id, int dir, ucp_stream_t **stream_p)
{
    ucp_rndv_mode_t active_rndv_mode;
    ucp_stream_t *stream;

    stream = ucs_malloc(sizeof(*stream), "stream");
    stream->stream_id = stream_id;
    stream->ep = ep;
    stream->flags = 0;
    stream->local_seq = 0;
    stream->remote_seq = 0;
    stream->unexp_eager_count = 0;
    ucs_queue_head_init(&stream->q);
    stream->ready_list.prev = NULL;
    stream->ready_list.next = NULL;

    if (dir) {
        stream->flags |= UCP_STREAM_FLAG_SEND;
        active_rndv_mode = UCP_RNDV_MODE_PUT_ZCOPY;
    } else {
        active_rndv_mode = UCP_RNDV_MODE_GET_ZCOPY;
    }

    if (ep->worker->context->config.ext.rndv_mode == active_rndv_mode) {
        stream->flags |= UCP_STREAM_FLAG_ACTIVE;
    }

    *stream_p = stream;
    return UCS_OK;
}

static UCS_F_ALWAYS_INLINE ucs_status_t
ucp_stream_get(ucp_worker_h worker, uint64_t ep_id, uint64_t stream_id, int dir,
               ucp_stream_t **stream_p)
{
    ucp_stream_key_t key = {
        .ep_id = ep_id,
        .stream_id = stream_id,
        .direction = dir
    };
    ucs_status_t status;
    khiter_t iter;
    ucp_ep_h ep;
    int ret;

    iter = kh_get(ucp_worker_stream_hash, &worker->stream_hash, key);
    if (ucs_likely(iter != kh_end(&worker->stream_hash))) {
        *stream_p = kh_value(&worker->stream_hash, iter);
        return UCS_OK;
    }

    iter = kh_put(ucp_worker_stream_hash, &worker->stream_hash, key, &ret);
    if (iter == kh_end(&worker->stream_hash)) {
        return UCS_ERR_NO_MEMORY;
    }

    UCP_WORKER_GET_VALID_EP_BY_ID(&ep, worker, ep_id,
            return UCS_ERR_INVALID_PARAM,
            "new stream");

    status = ucp_stream_create(ep, stream_id, dir, stream_p);
    if (status != UCS_OK) {
        return status;
    }

    kh_value(&worker->stream_hash, iter) = *stream_p;
    return UCS_OK;
}

static UCS_F_ALWAYS_INLINE ucs_status_t
ucp_stream_get_param(ucp_ep_h ep, const ucp_request_param_t *param,
                     int dir, ucp_stream_t **stream_p)
{
    uint64_t stream_id = UCP_REQUEST_PARAM_FIELD(param, ID, id, -1ULL);
    ucp_stream_key_t key;
    ucs_status_t status;
    khiter_t iter;
    int ret;

    key.ep_id = ep->ext->local_ep_id;
    key.stream_id = stream_id;
    key.direction = dir;

    iter = kh_get(ucp_worker_stream_hash, &ep->worker->stream_hash, key);
    if (ucs_likely(iter != kh_end(&ep->worker->stream_hash))) {
        *stream_p = kh_value(&ep->worker->stream_hash, iter);
        return UCS_OK;
    }

    iter = kh_put(ucp_worker_stream_hash, &ep->worker->stream_hash, key, &ret);
    if (iter == kh_end(&ep->worker->stream_hash)) {
        return UCS_ERR_NO_MEMORY;
    }

    status = ucp_stream_create(ep, stream_id, dir, stream_p);
    if (status != UCS_OK) {
        return status;
    }

    kh_value(&ep->worker->stream_hash, iter) = *stream_p;
    return UCS_OK;
}

ucs_status_ptr_t ucp_stream_pmpy_recv(ucp_request_t *req);

ucs_status_ptr_t
ucp_stream_pmpy_send(ucp_ep_h ep, ucp_request_t *req, const void *buffer,
                     size_t count, ucp_datatype_t datatype,
                     size_t contig_length, const ucp_request_param_t *param);

ucs_status_t
ucp_stream_rndv_process_rdesc(ucp_recv_desc_t *rdesc, ucp_request_t *req,
                              ucp_stream_t *stream, ucp_operation_id_t op_id);

void ucp_stream_rndv_desc_release(ucp_recv_desc_t *rdesc);

#endif /* UCP_STREAM_H_ */
