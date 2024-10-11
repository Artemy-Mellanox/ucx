#include <ucp/api/ucp.h>
#include <sys/time.h>

#include <stdio.h>
#include <alloca.h>

typedef struct {
	int numIterations;
	uint64_t messageSize; 
	int window;

	ucp_context_h	     context;
	ucp_mem_h	     mem;
	ucp_worker_h	     worker;
	ucp_ep_h             ep;
	void		     *addr;

	int numOutstandingRequests;
	int numCompletedRequests;
} perfCtx;


void clientCb(void *req, ucs_status_t status, void *arg) {
	perfCtx *ctx = arg;

	ctx->numOutstandingRequests--;
	ucp_request_free(req);
}

void clientRun(perfCtx *ctx) {
	ucs_status_ptr_t req;
	struct timeval t1, t2, d;
	gettimeofday(&t1, 0);
	int lastI = 0;

	ucp_request_param_t  amParam;

	amParam.op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK | UCP_OP_ATTR_FIELD_USER_DATA | UCP_OP_ATTR_FLAG_MULTI_SEND | UCP_OP_ATTR_FIELD_MEMH;
	amParam.memh = ctx->mem;
	amParam.user_data = ctx;
	amParam.cb.send = &clientCb;

	for (int i = 0; i < ctx->numIterations; i++) {
		while (ctx->numOutstandingRequests == ctx->window) {
			int n;
			do {
				n = ucp_worker_progress(ctx->worker);
			} while (!n);
		}
		ctx->numOutstandingRequests++;
		req = ucp_am_send_nbx(ctx->ep, 0, NULL, 0, ctx->addr, ctx->messageSize, &amParam);
		if (UCS_PTR_IS_ERR(req)) {
			printf("%s:%d \n", __func__, __LINE__);
			return;
		}

		gettimeofday(&t2, 0);
		timersub(&t2, &t1, &d);
		if (d.tv_sec*1000000+d.tv_usec >= 1000000) {
			printf("%0.2f\n", (i - lastI) * ctx->messageSize / 1e6);
			lastI = i;
			t1 = t2;
		}
	}
}

ucs_status_t serverCb(void *arg, const void *header, size_t header_length,
              void *data, size_t length, const ucp_am_recv_param_t *param)
{
	perfCtx *ctx = arg;
	ucp_request_param_t m_am_rx_params;

	m_am_rx_params.op_attr_mask = UCP_OP_ATTR_FLAG_NO_IMM_CMPL | UCP_OP_ATTR_FLAG_MULTI_SEND | UCP_OP_ATTR_FIELD_MEMH;
	m_am_rx_params.memh = ctx->mem;

        if (param->recv_attr & UCP_AM_RECV_ATTR_FLAG_RNDV) {
		ucs_status_ptr_t sp = ucp_am_recv_data_nbx(ctx->worker, data,
				ctx->addr,
				ctx->messageSize,
				&m_am_rx_params);
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

