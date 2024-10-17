#include "worker.h"

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
	am_queue_t *queue = valloc(sizeof *queue);
	memset(queue, 0, sizeof *queue);
	return queue;
}

int ucp_worker_progress_wait(ucp_worker_h worker, am_queue_t *queue) {
	unsigned long pi = queue->pi;
	int c = 256;
	int n = 0;

	do {
		n += ucp_worker_progress(worker);
	} while (queue->pi == pi /*(queue->pi - pi) % QUEUE_SIZE < 1 && --c > 0); //n == 0); */ && --c > 0);

	return n;
}


