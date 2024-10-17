#ifndef ZERO_H__
#define ZERO_H__

#include <ucp/api/ucp.h>
#include <ucs/datastruct/list.h>

#include <stdlib.h>

typedef struct {
	ucs_list_link_t reqs;
} zero_worker_t;

typedef struct {
	ucs_list_link_t link;
        ucp_send_nbx_callback_t cb;
	void *arg;
} zero_req_t;

zero_worker_t *zero_worker_init();

void zero_worker_progress(zero_worker_t *z);

ucs_status_ptr_t zero_ucp_am_send_nbx(zero_worker_t *zw, unsigned id, const void *header,
                 size_t header_length, const void *buffer, size_t count,
                 const ucp_request_param_t *param);

#endif
