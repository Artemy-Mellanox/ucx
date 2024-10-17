#include "zero.h"

zero_worker_t *zero_worker_init() 
{
	zero_worker_t *w = calloc(1, sizeof *w);
	ucs_list_head_init(&w->reqs);
	return w;
}

void zero_worker_progress(zero_worker_t *w)
{
	zero_req_t *req;
	if (!ucs_list_is_empty(&w->reqs)) {
		req = ucs_list_extract_head(&w->reqs, zero_req_t, link);
		req->cb(req, UCS_OK, req->arg);
		free(req);
	}
}

ucs_status_ptr_t zero_ucp_am_send_nbx(zero_worker_t *zw, unsigned id, const void *header,
                 size_t header_length, const void *buffer, size_t count,
                 const ucp_request_param_t *param)
{
	zero_req_t *req = calloc(1, sizeof *req);

	ucs_list_add_tail(&zw->reqs, &req->link);
	if (param->op_attr_mask & UCP_OP_ATTR_FIELD_CALLBACK) {
		req->cb = param->cb.send;
		req->arg = param->user_data;
	}

	return UCS_STATUS_PTR(UCS_OK);
}
