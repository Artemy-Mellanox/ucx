/*
 * Copyright (C) 2021, NVIDIA CORPORATION & AFFILIATES. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 */
package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	. "ucx"
	"unsafe"
	. "cuda"
	"runtime"
)

type PerfTestParams struct {
	messageSize   uint64
	memType       UcsMemoryType
	numThreads    uint
	numIterations uint
	port          uint
	wakeup        bool
	ip            string
	printIter     uint
	warmUpIter    uint
	window	      int
}

type PerfTest struct {
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
}

var perfTestParams = PerfTestParams{}
var perfTest = PerfTest{}

// Returns address of current thread memory slice.
func getAddressOffsetForThread(t uint) unsafe.Pointer {
	var baseAddress uint = uint(uintptr(perfTest.memParams.Address))
	var offset uint = baseAddress + t*uint(perfTestParams.messageSize)
	return unsafe.Pointer(uintptr(offset))
}

// Printing functions
func printHeader() {
	dashes := strings.Repeat("-", 20)
	fmt.Printf("|%20s|%20s|%20s|%20s|\n", dashes, dashes, dashes, dashes)
	fmt.Printf("|%20s|%20s|%20s|%20s|\n", "Thread", "Iteration", "Latency ", "Bandwidth (Gb/s)")
	fmt.Printf("|%20s|%20s|%20s|%20s|\n", dashes, dashes, dashes, dashes)
}

func printPerThreadStatistics(i uint, t uint) {
	bw := float64(perfTestParams.messageSize) * float64(i - perfTest.lastI) * float64(1e-9)
	fmt.Printf("|%20s|%20s|%20s|%20f|\n", fmt.Sprintf("%v/%v", t+1, perfTestParams.numThreads),
		fmt.Sprintf("%v/%v", i, perfTestParams.numIterations), perfTest.completionTime[t], bw)
	perfTest.lastI = i
}

func printTotalStatistics(duration time.Duration) {
	totalBytesTransfered := perfTestParams.messageSize * uint64(perfTestParams.numThreads) * uint64(perfTestParams.numIterations)
	avgLat := float64(duration.Milliseconds()) / float64(perfTestParams.numIterations)
	avgBw := float64(totalBytesTransfered) * float64(1e-9) / duration.Seconds()

	dashes := strings.Repeat("-", 20)
	fmt.Printf("|%20s|%20s|%20s|%20s|\n", dashes, dashes, dashes, dashes)
	fmt.Printf("Number of iterations: %v, number of threads: %v, message size: %v, "+
		"memory type: %v, average latency (ms): %v, average bandwidth (Gb/s): %.3f \n", perfTestParams.numIterations,
		perfTestParams.numThreads, perfTestParams.messageSize, perfTestParams.memType, avgLat, avgBw)
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
	mmapParams.SetLength(perfTestParams.messageSize * uint64(perfTestParams.numThreads))

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
	perfTest.perThreadWorkers[i].ProgressWait()
	if perfTestParams.wakeup {
		perfTest.perThreadWorkers[i].Wait()
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
		data.Receive(getAddressOffsetForThread(tid), perfTestParams.messageSize, &perfTest.amParam)
	}

	return UCS_OK
}

func serverStart() error {
	initContext()
	if err := initMemory(); err != nil {
		return err
	}

	perfTest.amParam.SetMemType(perfTestParams.memType).SetCallback(serverAmCb).SetMulti().SetMemory(perfTest.memory)
	// 1 global worker for listener progress and N threads for data receive.
	perfTest.perThreadWorkers = make([]*UcpWorker, perfTestParams.numThreads+1)
	initWorker(0)
	if err := initListener(); err != nil {
		return err
	}

	// Submit AM recv handler for each thread
	for t := uint(0); t < perfTestParams.numThreads; t += 1 {
		initWorker(int(t) + 1)
		//perfTest.perThreadWorkers[t+1].SetAmRecvHandler(t, UCP_AM_FLAG_WHOLE_MSG, serverAmRecvHandler)
		perfTest.perThreadWorkers[t+1].SetAmRecvHandler(t, 0, serverAmRecvHandler)
	}

	totalNumRequests := uint32((perfTestParams.warmUpIter + perfTestParams.numIterations) * perfTestParams.numThreads)
	perfTest.wg.Add(int(perfTestParams.numThreads + 1))
	for t := uint(0); t < perfTestParams.numThreads+1; t += 1 {
		go func(tid uint) {
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

func clientThreadDoIter(i int, t uint) {
	tryCudaSetDevice()

	start := time.Now()
	var header unsafe.Pointer
	var headerSize uint64
	if t != 0 {
		header = unsafe.Pointer(&t)
		headerSize = uint64(unsafe.Sizeof(t))
	}

	atomic.AddInt32(&perfTest.numOutstandingRequests, 1)

	_, err := perfTest.eps[t].SendAmNonBlocking(t, header, headerSize, getAddressOffsetForThread(t), perfTestParams.messageSize, 0, &perfTest.amParam)
	if (err != nil) {
		panic(err)
	}

	if start.After(perfTest.nextStat) {
		printPerThreadStatistics(uint(i), t)
		perfTest.nextStat = start.Add(time.Second)
	}

	if perfTestParams.numThreads > 1 {
		perfTest.wg.Done()
	}
}

func clientStart() error {
	initContext()
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
	for i := -int(perfTestParams.warmUpIter); i < int(perfTestParams.numIterations); i += 1 {
		if perfTestParams.numThreads > 1 {
			perfTest.wg.Add(int(perfTestParams.numThreads))
			for t := uint(0); t < perfTestParams.numThreads; t += 1 {
				go clientThreadDoIter(i, t)
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
			for atomic.LoadInt32(&perfTest.numOutstandingRequests) == int32(perfTestParams.window) {
				progressWorker(0)
			}
			clientThreadDoIter(i, 0)
			totalDuration += perfTest.completionTime[0]
		}
	}
	totalDuration = time.Since(start)
	printTotalStatistics(totalDuration)

	close()
	return nil
}

func main() {
	flag.UintVar(&perfTestParams.numThreads, "t", 1, "number of threads for send: 1(default)")
	flag.Uint64Var(&perfTestParams.messageSize, "s", 4096, "size of the message in bytes: 4096(default)")
	flag.UintVar(&perfTestParams.port, "p", 36458, "port to bind: 36458(default)")
	flag.UintVar(&perfTestParams.numIterations, "n", 1000, "Number of iterations to run: 1000(default)")
	flag.UintVar(&perfTestParams.printIter, "printIter", 100, "Print summary every n iterations: 1000(default)")
	flag.BoolVar(&perfTestParams.wakeup, "wakeup", false, "use polling: false(default)")
	flag.UintVar(&perfTestParams.warmUpIter, "warmup", 5, "warmup iterations: 5(default)")
	flag.StringVar(&perfTestParams.ip, "i", "", "server address to connect")
	flag.IntVar(&perfTestParams.window, "w", 64, "window")

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
