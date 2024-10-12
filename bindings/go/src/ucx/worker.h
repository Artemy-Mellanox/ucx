#include <stdlib.h>

#define QUEUE_SIZE 1024

typedef struct {
	unsigned id;
	void *data;
	size_t length;
	unsigned attr;
} am_data_t;

typedef struct {
	am_data_t q[QUEUE_SIZE];
	unsigned pi;
} am_queue_t;

typedef struct {
	int id;
	am_queue_t *q;
} am_ctx_t;

am_ctx_t *am_ctx_init(int id, am_queue_t *queue)
{
	am_ctx_t *ctx = calloc(1, sizeof *ctx);
	ctx->id = id;
	ctx->q = queue;
}

ucs_status_t                                                         
am_data_handler(void *arg, const void *header, size_t header_length,        
                void *data, size_t length, const ucp_am_recv_param_t *param)
{
	am_ctx_t *ctx = (am_ctx_t *)arg;
	am_queue_t *queue = ctx->q;
	am_data_t *am = queue->q + queue->pi;

	am->id = ctx->id;
	am->data = data;
	am->length = length;
	am->attr = param->recv_attr;

	queue->pi = (queue->pi + 1) % QUEUE_SIZE;
	return UCS_INPROGRESS;
}

am_queue_t *am_queue_init() 
{
	am_queue_t *queue = calloc(1, sizeof *queue);
	return queue;
}
