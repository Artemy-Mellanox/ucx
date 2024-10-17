#include "endpoint.h"

ucs_status_ptr_t zero_ucp_am_send_nbx(ucp_ep_h ep, unsigned id, const void *header,
                 size_t header_length, const void *buffer, size_t count,
                 const ucp_request_param_t *param) {
	//if (param->op_attr_mask & UCP_OP_ATTR_FIELD_CALLBACK) {
	//	param->cb.send(NULL, UCS_OK, param->user_data);
	//}
	return UCS_STATUS_PTR(UCS_OK);
}

ucp_request_param_t *alloc_ucp_request_param(void) {
	return malloc(sizeof(ucp_request_param_t));
}
