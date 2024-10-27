/*
 * Copyright (C) 2021, NVIDIA CORPORATION & AFFILIATES. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 */
package main

// #include "perftest.h"
import "C"

import (
	"errors"
	"flag"
	"fmt"
	"math"
	"net"
	"os"
	"strings"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
	. "ucx"
	"unsafe"
	. "cuda"
	"runtime"
)

type PerfTestParams struct {
	messageSizes  string
	memType       UcsMemoryType
	numThreads    uint
	numIterations uint
	port          uint
	wakeup        bool
	ip            string
	printIter     uint
	warmUpIter    uint
	window	      int
	C             string
	stats	      bool
}

type PerfTest struct {
	size		     uint64
	context              *UcpContext
	memory               *UcpMemory
	memParams            *UcpMemAttributes
	perThreadWorkers     []*UcpWorker
	listener             *UcpListener
	eps                  []*UcpEp
	reverseEps           []*UcpEp
	numOutstandingRequests int32
	numCompletedRequests uint32
	wg                   sync.WaitGroup
	completionTime       []time.Duration
	nextStat	     time.Time
	lastI		     uint
	amParam		     UcpRequestParams
	c                    C.perfCtx
}

var perfTestParams = PerfTestParams{}
var perfTest = PerfTest{}

// Returns address of current thread memory slice.
func getAddressOffsetForThread(t uint, size uint64) unsafe.Pointer {
	var baseAddress uint = uint(uintptr(perfTest.memParams.Address))
	var offset uint = baseAddress + t*uint(size)
	return unsafe.Pointer(uintptr(offset))
}

// Printing functions
func printHeader() {
	dashes := strings.Repeat("-", 20)
	fmt.Printf("|%20s|%20s|%20s|%20s|\n", dashes, dashes, dashes, dashes)
	fmt.Printf("|%20s|%20s|%20s|%20s|\n", "Thread", "Iteration", "Latency ", "Bandwidth (Gb/s)")
	fmt.Printf("|%20s|%20s|%20s|%20s|\n", dashes, dashes, dashes, dashes)
}

func printPerThreadStatistics(i uint, t uint, size uint64) {
	bw := float64(size) * float64(i - perfTest.lastI) * float64(1e-9)
	fmt.Printf("|%20s|%20s|%20s|%20f|\n", fmt.Sprintf("%v/%v", t+1, perfTestParams.numThreads),
		fmt.Sprintf("%v/%v", i, perfTestParams.numIterations), perfTest.completionTime[t], bw)
	perfTest.lastI = i
}

func printTotalStatistics(duration time.Duration, size uint64) {
	totalBytesTransfered := size * uint64(perfTestParams.numThreads) * uint64(perfTestParams.numIterations)
	avgLat := float64(duration.Milliseconds()) / float64(perfTestParams.numIterations)
	avgBw := float64(totalBytesTransfered) * float64(1e-9) / duration.Seconds()

	dashes := strings.Repeat("-", 20)
	fmt.Printf("|%20s|%20s|%20s|%20s|\n", dashes, dashes, dashes, dashes)
	fmt.Printf("Number of iterations: %v, number of threads: %v, message size: %v, "+
		"memory type: %v, average latency (ms): %v, average bandwidth (Gb/s): %.3f \n", perfTestParams.numIterations,
		perfTestParams.numThreads, size, perfTestParams.memType, avgLat, avgBw)
}

func initContext() {
	params := (&UcpParams{}).EnableAM()

	if perfTestParams.wakeup {
		params.EnableWakeup()
	}

	perfTest.context, _ = NewUcpContext(params)
}

func tryCudaSetDevice() {
	if perfTestParams.memType == UCS_MEMORY_TYPE_CUDA {
		runtime.LockOSThread()
		if ret := CudaSetDevice(); ret != nil {
			panic(ret)
		}
	}
}

func initMemory() error {
	var err error
	memTypeMask, _ := perfTest.context.MemoryTypesMask()

	if !IsMemTypeSupported(perfTestParams.memType, memTypeMask) {
		return errors.New("requested memory type is unsupported")
	}

	mmapParams := &UcpMmapParams{}
	mmapParams.SetMemoryType(perfTestParams.memType).Allocate()
	mmapParams.SetLength(perfTest.size * uint64(perfTestParams.numThreads))

	tryCudaSetDevice()

	perfTest.memory, err = perfTest.context.MemMap(mmapParams)
	if err != nil {
		return err
	}

	perfTest.memParams, err = perfTest.memory.Query(UCP_MEM_ATTR_FIELD_ADDRESS)
	if err != nil {
		return err
	}
	return nil
}

func initWorker(i int) {
	//workerParams := (&UcpWorkerParams{}).SetThreadMode(UCS_THREAD_MODE_MULTI)
	workerParams := (&UcpWorkerParams{}).SetThreadMode(UCS_THREAD_MODE_SERIALIZED)

	if perfTestParams.wakeup {
		workerParams.WakeupTX()
		workerParams.WakeupRX()
	}

	perfTest.perThreadWorkers[i], _ = perfTest.context.NewWorker(workerParams)
}

func epErrorHandling(ep *UcpEp, status UcsStatus) {
	if status != UCS_ERR_CONNECTION_RESET {
		errorString := fmt.Sprintf("Endpoint error: %v", status.String())
		panic(errorString)
	}
}

func clientConnectWorker(i int) error {
	var err error
	epParams := &UcpEpParams{}
	serverAddress, _ := net.ResolveTCPAddr("tcp", fmt.Sprintf("%v:%v", perfTestParams.ip, perfTestParams.port))
	epParams.SetPeerErrorHandling().SetErrorHandler(epErrorHandling).SetSocketAddress(serverAddress)

	perfTest.eps[i], err = perfTest.perThreadWorkers[i].NewEndpoint(epParams)
	if err != nil {
		return err
	}

	request, err := perfTest.eps[i].FlushNonBlocking(nil)
	if err != nil {
		return err
	}

	for request.GetStatus() == UCS_INPROGRESS {
		progressWorker(i)
	}

	if status := request.GetStatus(); status != UCS_OK {
		return NewUcxError(status)
	}

	request.Close()
	return nil
}

func initListener() error {
	var err error
	listenerParams := &UcpListenerParams{}
	addr, _ := net.ResolveTCPAddr("tcp", fmt.Sprintf("0.0.0.0:%v", perfTestParams.port))

	listenerParams.SetSocketAddress(addr)
	listenerParams.SetConnectionHandler(func(connRequest *UcpConnectionRequest) {
		// No need to synchronize, since reverse eps creating from a single thread.
		numConnections := len(perfTest.reverseEps)
		reverseEp, _ := perfTest.perThreadWorkers[1+numConnections].NewEndpoint(
			(&UcpEpParams{}).SetConnRequest(connRequest).SetErrorHandler(epErrorHandling).SetPeerErrorHandling())

		perfTest.reverseEps = append(perfTest.reverseEps, reverseEp)
		fmt.Printf("Got connection for thread %v. Starting benchmark...\n", numConnections)
	})

	perfTest.listener, err = perfTest.perThreadWorkers[0].NewListener(listenerParams)
	if err != nil {
		return err
	}
	fmt.Printf("Started receiver listener on address: %v \n", addr)
	return nil
}

func progressWorker(i int) {
	if perfTestParams.C == "zero" {
		perfTest.perThreadWorkers[i].ProgressZero()
	}
	n := perfTest.perThreadWorkers[i].ProgressWait()
	if perfTestParams.wakeup {
		perfTest.perThreadWorkers[i].Wait()
	}
	if perfTestParams.C == "defer" && n > 0 {
		perfTest.perThreadWorkers[i].ProcessCallbacks()
		//if m == 0 { fmt.Printf("ProcessCallbacks %d %d\n", n, m) }
	}
}

func close() {
	for _, reverseEp := range perfTest.reverseEps {
		reverseEp.CloseNonBlockingForce(nil)
	}

	for _, ep := range perfTest.eps {
		ep.CloseNonBlockingForce(nil)
	}

	if perfTest.listener != nil {
		perfTest.listener.Close()
	}

	for _, worker := range perfTest.perThreadWorkers {
		worker.Close()
	}

	if perfTest.memory != nil {
		perfTest.memory.Close()
	}

	if perfTest.context != nil {
		perfTest.context.Close()
	}
}

func serverAmCb(request *UcpRequest, status UcsStatus, length uint64) {
	atomic.AddUint32(&perfTest.numCompletedRequests, 1)
	request.Close()
}

func serverAmRecvHandler(header unsafe.Pointer, headerSize uint64, data *UcpAmData, replyEp *UcpEp) UcsStatus {
	var tid uint
	if headerSize == 8 {
		tid = *(*uint)(header)
	} else {
		tid = 0
	}
	if data.IsDataValid() {
		atomic.AddUint32(&perfTest.numCompletedRequests, 1)
	} else {
		req, _ := data.Receive(getAddressOffsetForThread(tid, perfTest.size), perfTest.size, &perfTest.amParam)
		req.Release()
	}

	return UCS_OK
}

func serverStart() error {
	initContext()
	_, size, _ := sizes(perfTestParams.messageSizes)
	perfTest.size = size
	if err := initMemory(); err != nil {
		return err
	}

	perfTest.amParam.SetMemType(perfTestParams.memType).SetMulti().SetMemory(perfTest.memory).SetNoImmCmpl()
	// 1 global worker for listener progress and N threads for data receive.
	perfTest.perThreadWorkers = make([]*UcpWorker, perfTestParams.numThreads+1)
	initWorker(0)
	if err := initListener(); err != nil {
		return err
	}

	var ctx C.perfCtx
	// Submit AM recv handler for each thread
	for t := uint(0); t < perfTestParams.numThreads; t += 1 {
		initWorker(int(t) + 1)

		if perfTestParams.C == "cb" {
			ctx.addr = getAddressOffsetForThread(0, size);
			ctx.worker = C.ucp_worker_h(perfTest.perThreadWorkers[t+1].UCP())
			ctx.messageSize = C.uint64_t(size)
			ctx.mem = C.ucp_mem_h(perfTest.memory.UCP())
			perfTest.perThreadWorkers[t+1].SetAmRecvHandler2(t, UCP_AM_FLAG_WHOLE_MSG,
					   unsafe.Pointer(C.serverCb),
					   unsafe.Pointer(&ctx))
		} else if perfTestParams.C == "defer" {
			perfTest.perThreadWorkers[t+1].SetAmRecvHandler3(t, UCP_AM_FLAG_WHOLE_MSG, serverAmRecvHandler)
		} else {
			perfTest.perThreadWorkers[t+1].SetAmRecvHandler(t, UCP_AM_FLAG_WHOLE_MSG, serverAmRecvHandler)
		}
	}

	totalNumRequests := uint32((perfTestParams.warmUpIter + perfTestParams.numIterations) * perfTestParams.numThreads)
	perfTest.wg.Add(int(perfTestParams.numThreads + 1))
	for t := uint(0); t < perfTestParams.numThreads+1; t += 1 {
		go func(tid uint) {
			if tid > 0 && perfTestParams.C == "full" {
				ctx.addr = getAddressOffsetForThread(0, size);
				ctx.worker = C.ucp_worker_h(perfTest.perThreadWorkers[tid].UCP())
				ctx.messageSize = C.uint64_t(size)
				ctx.mem = C.ucp_mem_h(perfTest.memory.UCP())
				C.serverRun(&ctx)
			}

			tryCudaSetDevice()

			for atomic.LoadUint32(&perfTest.numCompletedRequests) < totalNumRequests {
				progressWorker(int(tid))
			}
			perfTest.wg.Done()
		}(t)
	}
	perfTest.wg.Wait()

	close()
	return nil
}

func clientAmCb(request *UcpRequest, status UcsStatus) {
	atomic.AddInt32(&perfTest.numOutstandingRequests, -1)
	request.Close()
}

func clientThreadDoIter(i int, t uint, size uint64) {
	tryCudaSetDevice()

	var header unsafe.Pointer
	var headerSize uint64
	if t != 0 {
		header = unsafe.Pointer(&t)
		headerSize = uint64(unsafe.Sizeof(t))
	}

	var err error
	if perfTestParams.C == "defer" {
		atomic.AddInt32(&perfTest.numOutstandingRequests, 1)
		_, err = perfTest.eps[t].SendAmNonBlocking4(t, header, headerSize, 
						     getAddressOffsetForThread(t, size),
						     size, 0,
						     &perfTest.amParam)
	} else if perfTestParams.C == "zero" {
		_, err = perfTest.eps[t].SendAmNonBlocking3(t, header, headerSize, 
						     getAddressOffsetForThread(t, size),
						     size, 0,
						     &perfTest.amParam)
	} else if perfTestParams.C == "cb" {
		perfTest.c.numOutstandingRequests += 1
		_, err = perfTest.eps[t].SendAmNonBlocking2(t, header, headerSize, 
						     getAddressOffsetForThread(t, size),
						     size, 0,
						     &perfTest.amParam,
						     unsafe.Pointer(C.clientCb),
						     unsafe.Pointer(&perfTest.c))
        } else {
		atomic.AddInt32(&perfTest.numOutstandingRequests, 1)
		_, err = perfTest.eps[t].SendAmNonBlocking(t, header, headerSize, 
						     getAddressOffsetForThread(t, size),
						     size, 0,
						     &perfTest.amParam)
        }
	if (err != nil) {
		panic(err)
	}

	if perfTestParams.stats && i % 100 == 0 {
		start := time.Now()
		if start.After(perfTest.nextStat) {
			printPerThreadStatistics(uint(i), t, size)
			perfTest.nextStat = start.Add(time.Second)
		}
	}

	if perfTestParams.numThreads > 1 {
		perfTest.wg.Done()
	}
}

func nextSize(v uint64, step uint64) uint64 {
	pow2 := uint64(1);                                                               
	for pow2 <= v { pow2 *= 2 }
	v = uint64(float64(v) * math.Pow(2,1.0/float64(step))) + 1;
	if v > pow2 { v = pow2 }
	return v
}

func sizes(input string) (uint64, uint64, uint64) {
	values := strings.Split(input, ":")
	min, _ := strconv.ParseUint(values[0], 10, 64)
	if len(values) == 1 {
		return min, min, 1
	}
	max, _ := strconv.ParseUint(values[1], 10, 64)
	if len(values) == 2 {
		return min, max, 1
	}
	step, _ := strconv.ParseUint(values[2], 10, 64)
	return min, max, step
}

func clientStart() error {
	initContext()
	min, max, step := sizes(perfTestParams.messageSizes)
	perfTest.size = max
	if err := initMemory(); err != nil {
		return err
	}

	perfTest.amParam.SetMemType(perfTestParams.memType).SetCallback(clientAmCb).SetMulti().SetMemory(perfTest.memory)
	perfTest.perThreadWorkers = make([]*UcpWorker, perfTestParams.numThreads)
	perfTest.eps = make([]*UcpEp, perfTestParams.numThreads)
	for i := 0; i < int(perfTestParams.numThreads); i += 1 {
		initWorker(i)
		if err := clientConnectWorker(i); err != nil {
			return err
		}
	}

	var totalDuration time.Duration = 0
	printHeader()
	perfTest.nextStat = time.Now().Add(time.Second)
	var start time.Time
	for messageSize := min; messageSize <= max; messageSize = nextSize(messageSize, step) {
		var bw float64
		perfTest.size = messageSize

		if perfTestParams.C == "full" {
			var ctx C.perfCtx
			ctx.numIterations = C.int(perfTestParams.numIterations)
			ctx.messageSize = C.uint64_t(messageSize)
			ctx.ep = C.ucp_ep_h(perfTest.eps[0].UCP())
			ctx.mem = C.ucp_mem_h(perfTest.memory.UCP())
			ctx.addr = getAddressOffsetForThread(0, messageSize);
			ctx.worker = C.ucp_worker_h(perfTest.perThreadWorkers[0].UCP())
			ctx.window = C.int(perfTestParams.window)
			ctx.warmup = C.int(perfTestParams.warmUpIter)
			if perfTestParams.stats { ctx.stats = 1 }
			bw = float64(C.clientRun(&ctx))
		} else {
			for i := -int(perfTestParams.warmUpIter); i < int(perfTestParams.numIterations); i += 1 {
				if perfTestParams.numThreads > 1 {
					perfTest.wg.Add(int(perfTestParams.numThreads))
					for t := uint(0); t < perfTestParams.numThreads; t += 1 {
						go clientThreadDoIter(i, t, messageSize)
					}
					perfTest.wg.Wait()
					var maxDuration time.Duration = 0
					for _, threadDuration := range perfTest.completionTime {
						if threadDuration > maxDuration {
							maxDuration = threadDuration
						}
					}
					totalDuration += maxDuration
				} else {
					if i == 0 {
						start = time.Now()
					}
					if perfTestParams.C == "zero" {

					} else if perfTestParams.C == "cb" {
						for perfTest.c.numOutstandingRequests == C.int(perfTestParams.window) {
							progressWorker(0)
						}
					} else {
						for atomic.LoadInt32(&perfTest.numOutstandingRequests) == int32(perfTestParams.window) {
							progressWorker(0)
						}
					}
					clientThreadDoIter(i, 0, messageSize)
					totalDuration += perfTest.completionTime[0]
				}
			}
			totalDuration = time.Since(start)

			bw = float64(messageSize) * float64(perfTestParams.numIterations) /totalDuration.Seconds() * float64(1e-9)
		}
		fmt.Printf("%20d %20f\n", messageSize, bw)
	}
	//printTotalStatistics(totalDuration, messageSize)

	close()
	return nil
}

func main() {
	flag.UintVar(&perfTestParams.numThreads, "t", 1, "number of threads for send: 1(default)")
	flag.StringVar(&perfTestParams.messageSizes, "s", "4096", "size of the message in bytes: min:max:step")
	flag.UintVar(&perfTestParams.port, "p", 36458, "port to bind: 36458(default)")
	flag.UintVar(&perfTestParams.numIterations, "n", 1000, "Number of iterations to run: 1000(default)")
	flag.UintVar(&perfTestParams.printIter, "printIter", 100, "Print summary every n iterations: 1000(default)")
	flag.BoolVar(&perfTestParams.wakeup, "wakeup", false, "use polling: false(default)")
	flag.BoolVar(&perfTestParams.stats, "S", false, "ongoing stats")
	flag.UintVar(&perfTestParams.warmUpIter, "warmup", 1000, "warmup iterations: 5(default)")
	flag.StringVar(&perfTestParams.ip, "i", "", "server address to connect")
	flag.IntVar(&perfTestParams.window, "w", 64, "window")
	flag.StringVar(&perfTestParams.C, "C", "", "in C")

	perfTestParams.memType = UCS_MEMORY_TYPE_HOST
	flag.CommandLine.Func("m", "memory type: host(default), cuda", func(p string) error {
		mtypeStr := strings.ToLower(p)
		if mtypeStr == "host" {
			perfTestParams.memType = UCS_MEMORY_TYPE_HOST
		} else if mtypeStr == "cuda" {
			perfTestParams.memType = UCS_MEMORY_TYPE_CUDA
		} else {
			return errors.New("memory type can be host or cuda")
		}
		return nil
	})

	flag.Parse()

	perfTest.completionTime = make([]time.Duration, perfTestParams.numThreads)
	var err error
	if perfTestParams.ip == "" {
		err = serverStart()
	} else {
		err = clientStart()
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error running benchmark: %v\n", err)
		os.Exit(1)
	}

}
