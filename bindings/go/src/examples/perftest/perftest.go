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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	. "github.com/openucx/ucx/bindings/go/src/ucx"
	"unsafe"
	. "github.com/openucx/ucx/bindings/go/src/cuda"
	"runtime"
	"github.com/docker/go-units"
	"github.com/Artemy-Mellanox/go-dbg"
)

type ProgressMode int

const (
	Callback ProgressMode = iota
	Broadcast
	Window
	Threads
	C
)

func (pm ProgressMode) String() string {
	switch pm {
	case Callback: return "callback"
	case Broadcast: return "broadcast"
	case Window: return "window"
	case C: return "c"
	case Threads: return "threads"
	default: return ""
	}
}

func (pm *ProgressMode) Set (value string) error {
	switch strings.ToLower(value) {
	case "callback", "cb": *pm = Callback
	case "broadcast", "bc": *pm = Broadcast
	case "window", "w": *pm = Window
	case "c": *pm = C
	case "threads", "t": *pm = Threads
	default: return fmt.Errorf("unknown progress mode %s", value)
	}
	return nil
}

type TestType int

const (
	Am TestType = iota
	Stream
	StreamAll
)

func (tt TestType) String() string {
	switch tt {
	case Am: return "am"
	case Stream: return "stream"
	case StreamAll: return "stream-all"
	default: return ""
	}
}

func (tt *TestType) Set (value string) error {
	switch strings.ToLower(value) {
	case "am": *tt = Am
	case "stream": *tt = Stream
	case "stream-all": *tt = StreamAll
	default: return fmt.Errorf("unknown test type %s", value)
	}
	return nil
}

type PerfTestParams struct {
	messageSizes  string
	memType       UcsMemoryType
	numThreads    uint
	numIterations uint
	port          uint
	wakeup        bool
	ip            string
	printInterval float64
	warmUpIter    uint
	progressMode  ProgressMode
	testType      TestType
}

const (
	Progress = iota
	Start
	Quit
)

type PerfTest struct {
	context              *UcpContext
	memory               *UcpMemory
	memParams            *UcpMemAttributes
	worker               *UcpWorker
	listener             *UcpListener
	ep                   *UcpEp
	messageSize          uint64
	numCompletedRequests int32
	wg                   sync.WaitGroup
	wake                 []chan int
	runProgress          int32
	statReport           int
	outstanding	     int32
}

const (
	STAT_CMD_RESET = iota
	STAT_CMD_PAUSE
	STAT_CMD_STOP
)

const (
	STAT_REPORT_SIZE = 1 << iota
	STAT_REPORT_ITER_NUM
)

var perfTestParams = PerfTestParams{}
var perfTest = PerfTest{}

// Returns address of current thread memory slice.
func getAddressOffsetForThreadWithOffset(t uint, off uint64) unsafe.Pointer {
	var baseAddress uint = uint(uintptr(perfTest.memParams.Address))
	var offset uint = baseAddress + t*uint(perfTest.messageSize) + uint(off)
	return unsafe.Pointer(uintptr(offset))
}

func getAddressOffsetForThread(t uint) unsafe.Pointer {
	return getAddressOffsetForThreadWithOffset(t, 0)
}

// Printing functions

func printHeader() {
	dashes := strings.Repeat("-", 20)
	switch perfTest.statReport {
	case STAT_REPORT_ITER_NUM:
		fmt.Printf("|%20s|%20s|%20s|\n", "# iterations", "Bandwidth (Mb/s)", "Messages/s")
		fmt.Printf("|%20s|%20s|%20s|\n", dashes, dashes, dashes)
	case STAT_REPORT_SIZE:
		fmt.Printf("|%20s|%20s|%20s|\n", "Size", "Bandwidth (Mb/s)", "Messages/s")
		fmt.Printf("|%20s|%20s|%20s|\n", dashes, dashes, dashes)
	case STAT_REPORT_SIZE|STAT_REPORT_ITER_NUM:
		fmt.Printf("|%20s|%20s|%20s|%20s|\n", "# iterations", "Size", "Bandwidth (Mb/s)", "Messages/s")
		fmt.Printf("|%20s|%20s|%20s|%20s|\n", dashes, dashes, dashes, dashes)
	}
}

func printStatistics(statCmd chan int) {
	var last int32
	d := time.Duration(perfTestParams.printInterval * float64(time.Second))
	ticker := time.NewTicker(d)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			curr := atomic.LoadInt32(&perfTest.numCompletedRequests)
			rate := float64(curr - last) / perfTestParams.printInterval
			bw := float64(perfTest.messageSize) * rate * float64(1e-6)
			if perfTest.statReport & STAT_REPORT_SIZE != 0 {
				fmt.Printf("|%20d|%20s|%20f|%20f|\n", curr, "", bw, rate)
			} else {
				fmt.Printf("|%20d|%20f|%20f|\n", curr, bw, rate)
			}
			last = curr
		case cmd := <-statCmd:
			dbg.Print("%d", cmd);
			switch cmd {
			case STAT_CMD_PAUSE:
				ticker.Stop()
			case STAT_CMD_RESET:
				last = 0
				ticker.Reset(d)
			case STAT_CMD_STOP:
				return
			}
		}
	}
}

func printTotalStatistics(duration time.Duration) {
	totalBytesTransfered := perfTest.messageSize * uint64(perfTest.numCompletedRequests)
	bw := float64(totalBytesTransfered) * float64(1e-6) / duration.Seconds()
	rate := float64(perfTest.numCompletedRequests) / duration.Seconds()
	switch perfTest.statReport {
	case STAT_REPORT_SIZE|STAT_REPORT_ITER_NUM:
		fmt.Printf("|%20s|%20d|%20f|%20f|\n", "", perfTest.messageSize, bw, rate)
	case STAT_REPORT_SIZE:
		fmt.Printf("|%20d|%20f|%20f|\n", perfTest.messageSize, bw, rate)
	default:
		fmt.Printf("Number of iterations: %v, number of threads: %v, message size: %v, "+
	                   "memory type: %v, average bandwidth (Mb/s): %.3f \n", perfTest.numCompletedRequests,
			   perfTestParams.numThreads, perfTest.messageSize, perfTestParams.memType, bw)
        }
}

func nextSize(v uint64, step uint64) uint64 {
	pow2 := uint64(1);
	for pow2 <= v {
		pow2 *= 2
	}

	v = uint64(float64(v) * math.Pow(2, 1.0 / float64(step))) + 1;
	if v > pow2 {
		v = pow2
	}
	return v
}

func parseSizes(input string) (uint64, uint64, uint64) {
	values := strings.Split(input, ":")
	min, _ := units.RAMInBytes(values[0])
	if len(values) == 1 {
		return uint64(min), uint64(min), 1
	}
	max, _ := units.RAMInBytes(values[1])
	if len(values) == 2 {
		return uint64(min), uint64(max), 1
	}
	step, _ := strconv.ParseUint(values[2], 10, 64)
	return uint64(min), uint64(max), step
}

func initContext() {
	params := (&UcpParams{}).EnableAM().EnableStream()

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
	mmapParams.SetLength(perfTest.messageSize * uint64(perfTestParams.numThreads))

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

func initWorker() {
	workerParams := (&UcpWorkerParams{}).SetThreadMode(UCS_THREAD_MODE_MULTI)

	if perfTestParams.wakeup {
		workerParams.WakeupTX()
		workerParams.WakeupRX()
	}

	perfTest.worker, _ = perfTest.context.NewWorker(workerParams)
}

func epErrorHandling(ep *UcpEp, status UcsStatus) {
	if status != UCS_ERR_CONNECTION_RESET {
		errorString := fmt.Sprintf("Endpoint error: %v", status.String())
		panic(errorString)
	} else {
		os.Exit(0)
	}
}

func flush() error {
	request, err := perfTest.ep.FlushNonBlocking(nil)
	if err != nil {
		return err
	}

	for request.GetStatus() == UCS_INPROGRESS {
		progressWorker()
	}

	if status := request.GetStatus(); status != UCS_OK {
		return NewUcxError(status)
	}

	request.Close()
	return nil
}

func clientConnectWorker() error {
	var err error
	epParams := &UcpEpParams{}
	serverAddress, _ := net.ResolveTCPAddr("tcp", fmt.Sprintf("%v:%v", perfTestParams.ip, perfTestParams.port))
	epParams.SetPeerErrorHandling().SetErrorHandler(epErrorHandling).SetSocketAddress(serverAddress)

	perfTest.ep, err = perfTest.worker.NewEndpoint(epParams)
	if err != nil {
		return err
	}

	return flush()
}

func wakeThreads(e int) {
	for _, ch := range perfTest.wake {
		select {
		case ch <- e:
		default:
		}
	}
}

func initListener() error {
	var err error
	listenerParams := &UcpListenerParams{}
	addr, _ := net.ResolveTCPAddr("tcp", fmt.Sprintf("0.0.0.0:%v", perfTestParams.port))

	listenerParams.SetSocketAddress(addr)
	listenerParams.SetConnectionHandler(func(connRequest *UcpConnectionRequest) {
		perfTest.ep, _ = perfTest.worker.NewEndpoint(
			(&UcpEpParams{}).SetConnRequest(connRequest).SetErrorHandler(epErrorHandling).SetPeerErrorHandling())

		fmt.Printf("Got connection. Starting benchmark...\n")
		wakeThreads(Start)
	})

	perfTest.listener, err = perfTest.worker.NewListener(listenerParams)
	if err != nil {
		return err
	}
	fmt.Printf("Started receiver listener on address: %v \n", addr)
	return nil
}

func progressWorker() {
	for perfTest.worker.Progress() == 0 { }
	if perfTestParams.wakeup {
		perfTest.worker.Wait()
	}
}

func progressThread() {
	for atomic.LoadInt32(&perfTest.runProgress) == 1 {
		progressWorker()
		if perfTestParams.progressMode == Broadcast {
			wakeThreads(Progress)
		}
	}
}

func closeAll() {
	if perfTest.ep != nil {
		perfTest.ep.CloseNonBlockingForce(nil)
	}

	if perfTest.listener != nil {
		perfTest.listener.Close()
	}

	if perfTest.worker != nil {
		perfTest.worker.Close()
	}

	if perfTest.memory != nil {
		perfTest.memory.Close()
	}

	if perfTest.context != nil {
		perfTest.context.Close()
	}
}

func serverAmRecvHandler(header unsafe.Pointer, headerSize uint64, data *UcpAmData, replyEp *UcpEp) UcsStatus {
	tid := *(*uint)(header)
	if !data.IsDataValid() {
		request, _ := data.Receive(getAddressOffsetForThread(tid), perfTest.messageSize,
			     (&UcpRequestParams{}).SetMemType(perfTestParams.memType).SetMulti().SetMemory(perfTest.memory))
		request.Close()
	}
	atomic.AddInt32(&perfTest.numCompletedRequests, 1)
	return UCS_OK
}

func serverPollStream(t uint) error {
	for perfTest.ep == nil {
		<-perfTest.wake[t]
	}
	tryCudaSetDevice()
	requestParams := (&UcpRequestParams{}).SetMemType(perfTestParams.memType).SetWaitAll()

	for {
		off := uint64(0)
		for {
			request, err := perfTest.ep.RecvStreamNonBlocking(int(t), getAddressOffsetForThreadWithOffset(t, off), perfTest.messageSize - off, requestParams)
			if err != nil {
				panic(err)
			}
			for {
				done, length, err := request.RecvStreamTest()
				if err != nil {
					panic(err)
				}
				if done {
					off += length
					break
				}
				e := <-perfTest.wake[t]
				if e == Quit {
					perfTest.wg.Done()
					return nil
				}
			}
			request.Close()

			if off == perfTest.messageSize {
				break
			}

			if off > perfTest.messageSize {
				panic(fmt.Sprintf("%d %d", off, perfTest.messageSize))
			}

		}
		atomic.AddInt32(&perfTest.numCompletedRequests, 1)
	}
	return nil
}

func serverPollAllStreams() {
	for perfTest.ep == nil {
		progressWorker()
	}
	tryCudaSetDevice()
	reqs := make([]*UcpRequest, perfTestParams.numThreads)
	requestParams := (&UcpRequestParams{}).SetMemType(perfTestParams.memType).SetWaitAll()
	var err error
	for id := range reqs {
		reqs[id], err = perfTest.ep.RecvStreamNonBlocking(id, getAddressOffsetForThread(uint(id)), perfTest.messageSize, requestParams)
		if err != nil {
			panic(err)
		}
	}

	for atomic.LoadInt32(&perfTest.runProgress) == 1 {
		for id, req := range reqs {
			if req.GetStatus() == UCS_OK {
				req.Close()
				atomic.AddInt32(&perfTest.numCompletedRequests, 1)
				reqs[id], err = perfTest.ep.RecvStreamNonBlocking(id, getAddressOffsetForThread(uint(id)), perfTest.messageSize, requestParams)
				if err != nil {
					panic(err)
				}
			}
		}
		progressWorker()
	}

	for _, req := range reqs {
		req.Close()
	}
}

func serverStart() error {
	_, perfTest.messageSize, _ = parseSizes(perfTestParams.messageSizes)

	initContext()
	if err := initMemory(); err != nil {
		return err
	}

	initWorker()
	if err := initListener(); err != nil {
		return err
	}

	if perfTestParams.progressMode == C {
		tryCudaSetDevice()
		var ctx C.perfCtx
		ctx.addr = getAddressOffsetForThread(0);
		ctx.worker = C.ucp_worker_h(perfTest.worker.RawPtr())
		ctx.messageSize = C.uint64_t(perfTest.messageSize)
		ctx.mem = C.ucp_mem_h(perfTest.memory.RawPtr())
		C.serverRun(&ctx)
	} else {
		atomic.StoreInt32(&perfTest.runProgress, 1)
		if perfTestParams.testType == Am {
			perfTest.worker.SetAmRecvHandler(0, UCP_AM_FLAG_WHOLE_MSG, serverAmRecvHandler)
			tryCudaSetDevice()
			progressThread()
		} else if perfTestParams.testType == Stream {
			for t := uint(0); t < perfTestParams.numThreads; t += 1 {
				go serverPollStream(t)
			}
			progressThread()
		} else if perfTestParams.testType == StreamAll {
			tryCudaSetDevice()
			serverPollAllStreams()
		}
	}

	flush()
	closeAll()
	return nil
}

func clientThreadDoIter(t uint) {
	tryCudaSetDevice()

	requestParams := (&UcpRequestParams{}).SetMemType(perfTestParams.memType)
	requestParams.SetMulti().SetMemory(perfTest.memory)
	if perfTestParams.progressMode == Threads {
		requestParams.SetCallback(func(request *UcpRequest, status UcsStatus){
			perfTest.wake[t] <- Progress
			request.Close()
		})
	} else if perfTestParams.progressMode == Callback {
		requestParams.SetCallback(func(request *UcpRequest, status UcsStatus){
			perfTest.wake[t] <- Progress
		})
	} else if perfTestParams.progressMode == Window {
		requestParams.SetCallback(func(request *UcpRequest, status UcsStatus){
			atomic.AddInt32(&perfTest.outstanding, -1)
			request.Close()
		})
	}

	header := unsafe.Pointer(&t)

	var (
		request *UcpRequest
		err error
	)

	if perfTestParams.testType == Am {
		request, err = perfTest.ep.SendAmNonBlocking(0, header, uint64(unsafe.Sizeof(t)), getAddressOffsetForThread(t), perfTest.messageSize, 0, requestParams)
	} else if perfTestParams.testType == Stream {
		request, err = perfTest.ep.SendStreamNonBlocking(int(t), getAddressOffsetForThread(t), perfTest.messageSize, requestParams)
	}
	if err != nil {
		panic(err)
	}

	switch perfTestParams.progressMode {
	case Threads: <-perfTest.wake[t]
		return;
	case Callback: <-perfTest.wake[t]
		atomic.AddInt32(&perfTest.numCompletedRequests, 1)
	case Broadcast:
		for request.GetStatus() == UCS_INPROGRESS {
			<-perfTest.wake[t]
		}
		atomic.AddInt32(&perfTest.numCompletedRequests, 1)
	case Window:
		atomic.AddInt32(&perfTest.numCompletedRequests, 1)
		atomic.AddInt32(&perfTest.outstanding, 1)
		return
	}

	if request.GetStatus() != UCS_OK {
		errorString := fmt.Sprintf("Request completion error: %v", request.GetStatus().String())
		panic(errorString)
	}
	request.Close()
	perfTest.wg.Done()
}

func align(v uint, a uint) int32 {
	return int32((v + a - 1) / a * a)
}

func clientStart() error {
	min, max, step := parseSizes(perfTestParams.messageSizes)

	initContext()
	perfTest.messageSize = max
	if err := initMemory(); err != nil {
		return err
	}

	initWorker()
	if err := clientConnectWorker(); err != nil {
		return err
	}

	warmUpIter := align(perfTestParams.warmUpIter, perfTestParams.numThreads)
	numIterations := align(perfTestParams.numIterations, perfTestParams.numThreads)

	if min != max {
		perfTest.statReport |= STAT_REPORT_SIZE
	}

	if perfTestParams.printInterval > 0 {
		perfTest.statReport |= STAT_REPORT_ITER_NUM
	}

	if perfTest.statReport != 0 {
		printHeader()
	}

	var start time.Time
	statCmd := func(int) {}
	if perfTestParams.printInterval > 0 {
		statCmdCh := make(chan int)
		statCmd = func(cmd int) {
			dbg.Print("%d", cmd);
			statCmdCh <- cmd
			dbg.Print("%d", cmd);
		}
		go printStatistics(statCmdCh)
	}

	atomic.StoreInt32(&perfTest.runProgress, 1)
	if perfTestParams.progressMode != Window && perfTestParams.progressMode != C {
		go progressThread()
	}
	for perfTest.messageSize = min; perfTest.messageSize <= max; perfTest.messageSize = nextSize(perfTest.messageSize, step) {
		perfTest.numCompletedRequests = -warmUpIter
		statCmd(STAT_CMD_PAUSE)
		if perfTestParams.progressMode == C {
			var ctx C.perfCtx
			ctx.numIterations = C.int(numIterations)
			ctx.messageSize = C.uint64_t(perfTest.messageSize)
			ctx.ep = C.ucp_ep_h(perfTest.ep.RawPtr())
			ctx.addr = getAddressOffsetForThread(0);
			ctx.worker = C.ucp_worker_h(perfTest.worker.RawPtr())
			ctx.window = C.int(perfTestParams.numThreads)
			ctx.warmup = C.int(perfTestParams.warmUpIter)
			ctx.mem = C.ucp_mem_h(perfTest.memory.RawPtr())
			start = time.UnixMicro(int64(C.clientRun(&ctx)))
			perfTest.numCompletedRequests = numIterations
			printTotalStatistics(time.Since(start))
			continue;
		}
		if perfTestParams.progressMode == Threads {
			perfTest.wg.Add(int(perfTestParams.numThreads))
			start = time.Now()
			for t := uint(0); t < perfTestParams.numThreads; t += 1 {
				go func() {
					for atomic.LoadInt32(&perfTest.numCompletedRequests) < numIterations {
						clientThreadDoIter(t);
						if atomic.AddInt32(&perfTest.numCompletedRequests, 1) == 0 {
							start = time.Now()
							statCmd(STAT_CMD_RESET)
						}
					}
					perfTest.wg.Done()
				}()
			}
			perfTest.wg.Wait()
			printTotalStatistics(time.Since(start))
			continue
		}
		for perfTest.numCompletedRequests != numIterations {
			if perfTest.numCompletedRequests == 0 {
				start = time.Now()
				statCmd(STAT_CMD_RESET)
			}
			if perfTestParams.progressMode == Window {
				for atomic.LoadInt32(&perfTest.outstanding) == int32(perfTestParams.numThreads) {
					progressWorker()
				}
				clientThreadDoIter(0)
			} else {
				perfTest.wg.Add(int(perfTestParams.numThreads))
				for t := uint(0); t < perfTestParams.numThreads; t += 1 {
					go clientThreadDoIter(t)
				}
				perfTest.wg.Wait()
			}
		}
		printTotalStatistics(time.Since(start))
	}
	atomic.StoreInt32(&perfTest.runProgress, 0)
	statCmd(STAT_CMD_STOP)

	if perfTestParams.progressMode == Window {
		for atomic.LoadInt32(&perfTest.outstanding) > 0 {
			progressWorker()
		}
	}
	closeAll()
	return nil
}

func main() {
	flag.UintVar(&perfTestParams.numThreads, "t", 1, "number of goroutines for send")
	flag.StringVar(&perfTestParams.messageSizes, "s", "4096", "sizes of the messages in bytes: min:max:step")
	flag.UintVar(&perfTestParams.port, "p", 36458, "port to bind")
	flag.UintVar(&perfTestParams.numIterations, "n", 1000, "number of iterations to run")
	flag.Float64Var(&perfTestParams.printInterval, "I", 1, "print summary every n seconds")
	flag.BoolVar(&perfTestParams.wakeup, "wakeup", false, "use polling: false(default)")
	flag.UintVar(&perfTestParams.warmUpIter, "warmup", 100, "warmup iterations")
	flag.StringVar(&perfTestParams.ip, "i", "", "server address to connect")

	perfTestParams.progressMode = Broadcast
	flag.Var(&perfTestParams.progressMode, "progress", "progress mode")

	perfTestParams.memType = UCS_MEMORY_TYPE_HOST
	flag.Var(&perfTestParams.memType, "m", "memory type: host(default), cuda")

	perfTestParams.testType = Am
	flag.Var(&perfTestParams.testType, "T", "test type: am, stream")

	flag.Parse()

	perfTest.wake = make([]chan int, perfTestParams.numThreads)
	for i := range perfTest.wake {
		perfTest.wake[i] = make(chan int, 100)
	}

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
