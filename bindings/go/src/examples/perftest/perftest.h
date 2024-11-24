#ifndef GO_PERFTEST_H_
#define GO_PERFTEST_H_

#include <ucp/api/ucp.h>

typedef struct {
    int numIterations;
    uint64_t messageSize;
    int window;
    int warmup;
    int stats;

    ucp_context_h context;
    ucp_worker_h worker;
    ucp_ep_h ep;
    void *addr;

    int numOutstandingRequests;
    int numCompletedRequests;
} perfCtx;

int64_t clientRun(perfCtx *ctx);
void serverRun(perfCtx *ctx);

#endif
