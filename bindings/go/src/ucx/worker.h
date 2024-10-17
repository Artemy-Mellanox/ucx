#ifndef WORKER_H__
#define WORKER_H__

#include <ucp/api/ucp.h>

//#define QUEUE_SIZE 1024
#define QUEUE_SIZE 128

typedef	struct {
	void *data;
	size_t length;
	unsigned long attr;
} am_t;

typedef	struct {
	unsigned long status;
	void *ctx;
	void *req;
} comp_t;

typedef struct {
	unsigned long typ;
	unsigned long id;
	union {
		comp_t comp;
		am_t am;
		char pad[48];
	} u;
} am_data_t;

typedef struct {
	am_data_t q[QUEUE_SIZE];
	unsigned long pi;
} am_queue_t;

typedef struct {
	unsigned long id;
	am_queue_t *q;
} am_ctx_t;

am_ctx_t *am_ctx_init(int id, am_queue_t *queue);

void comp_cb(void *req, ucs_status_t status, void *arg);

ucs_status_t                                                         
am_data_handler(void *arg, const void *header, size_t header_length,        
                void *data, size_t length, const ucp_am_recv_param_t *param);

am_queue_t *am_queue_init();

int ucp_worker_progress_wait(ucp_worker_h worker, am_queue_t *queue);

#endif
