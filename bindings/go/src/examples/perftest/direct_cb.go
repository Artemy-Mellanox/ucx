/*
 * Copyright (C) 2021, NVIDIA CORPORATION & AFFILIATES. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 */
package main

// #include <ucp/api/ucp.h>
// extern ucs_status_t amRecvCallback(void *callback_id, void *header, size_t header_length, 
// void *data, size_t length, ucp_am_recv_param_t *param);
import "C"

import (
	"sync/atomic"
	. "ucx"
	"unsafe"

	_ "fmt"
)

type amRecvCallbackCtx struct {
	w *UcpWorker
}

//export amRecvCallback
func amRecvCallback(arg unsafe.Pointer, header unsafe.Pointer, headerSize C.size_t,
	data unsafe.Pointer, dataSize C.size_t, params *C.ucp_am_recv_param_t) C.ucs_status_t {
	ctx := (*amRecvCallbackCtx)(arg)
	var tid uint
	if headerSize == 8 {
		tid = *(*uint)(header)
	} else {
		tid = 0
	}

	if (params.recv_attr & C.UCP_AM_RECV_ATTR_FLAG_RNDV) != 0 {
		req, _ := ctx.w.RecvAmDataNonBlocking2(data, getAddressOffsetForThread(tid), perfTestParams.messageSize, &perfTest.amParam)
		req.Release()
	}
	atomic.AddUint32(&perfTest.numCompletedRequests, 1)

	return C.UCS_OK
}

var ctxs []*amRecvCallbackCtx

func setAmRecvCallback(t uint, w *UcpWorker) {
	ctx := &amRecvCallbackCtx{
		w: w,
	}
	ctxs = append(ctxs, ctx)

	w.SetAmRecvHandler2(t, UCP_AM_FLAG_WHOLE_MSG, unsafe.Pointer(C.amRecvCallback),
			    unsafe.Pointer(ctx))
}

func setAmRecvCallback2(t uint, w *UcpWorker, cb unsafe.Pointer, ctx unsafe.Pointer) {
	w.SetAmRecvHandler2(t, UCP_AM_FLAG_WHOLE_MSG, cb, ctx)
}
