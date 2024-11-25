#include "perftest.h"
#include <sys/time.h>

#include <stdio.h>

void clientCb(void *req, ucs_status_t status, void *arg) {
    perfCtx *ctx = arg;

    ctx->numOutstandingRequests--;
    ucp_request_free(req);
}

int64_t clientRun(perfCtx *ctx) {
    ucp_request_param_t  amParam;
    ucs_status_ptr_t req;
    struct timeval t1;
    unsigned long t = 0;
    int i;

    amParam.op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK | UCP_OP_ATTR_FIELD_USER_DATA | UCP_OP_ATTR_FLAG_MULTI_SEND | UCP_OP_ATTR_FIELD_MEMH;
    amParam.memh = ctx->mem;
    amParam.user_data = ctx;
    amParam.cb.send = &clientCb;

    for (i = -ctx->warmup; i < ctx->numIterations; i++) {
        if (i == 0) {
            gettimeofday(&t1, 0);
        }
        while (ctx->numOutstandingRequests == ctx->window) {
            int n;
            do {
                n = ucp_worker_progress(ctx->worker);
            } while (!n);
        }
        ctx->numOutstandingRequests++;
        req = ucp_am_send_nbx(ctx->ep, 0, &t, sizeof(t), ctx->addr, ctx->messageSize, &amParam);
        if (UCS_PTR_IS_ERR(req)) {
            return UCS_PTR_STATUS(req);
        }
    }
    while (ctx->numOutstandingRequests > 0) {
        ucp_worker_progress(ctx->worker);
    }
    return t1.tv_sec * 1000000 + t1.tv_usec;
}

ucs_status_t serverCb(void *arg, const void *header, size_t header_length,
        void *data, size_t length, const ucp_am_recv_param_t *param)
{
    ucp_request_param_t amParam;
    ucs_status_ptr_t sp;
    perfCtx *ctx = arg;

    amParam.op_attr_mask = UCP_OP_ATTR_FLAG_NO_IMM_CMPL | UCP_OP_ATTR_FLAG_MULTI_SEND | UCP_OP_ATTR_FIELD_MEMH;
    amParam.memh = ctx->mem;

    if (param->recv_attr & UCP_AM_RECV_ATTR_FLAG_RNDV) {
        sp = ucp_am_recv_data_nbx(ctx->worker, data, ctx->addr, ctx->messageSize, &amParam);
        ucp_request_release(sp);
    }

    return UCS_OK;
}

void serverRun(perfCtx *ctx) {
    int n;
    ucp_am_handler_param_t param = {};

    param.field_mask = UCP_AM_HANDLER_PARAM_FIELD_ID |
        UCP_AM_HANDLER_PARAM_FIELD_CB |
        UCP_AM_HANDLER_PARAM_FIELD_ARG;
    param.id         = 0;
    param.cb         = serverCb;
    param.arg        = ctx;

    param.field_mask |= UCP_AM_HANDLER_PARAM_FIELD_FLAGS;
    param.flags       = UCP_AM_FLAG_WHOLE_MSG ;

    ucp_worker_set_am_recv_handler(ctx->worker, &param);

    while(1) {
        n = ucp_worker_progress(ctx->worker);
    }
}

