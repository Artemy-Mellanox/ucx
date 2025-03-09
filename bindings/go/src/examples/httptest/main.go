package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math"
	"net/http"
	"math/rand"
	"bytes"
	"os"
	"os/signal"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	uhttp "github.com/openucx/ucx/bindings/go/src/ucx/http"
)

func rootHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "Welcome to the root page!")
}

func helloHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "Hello, World!")
}

var globalData []byte

func dataHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodHead:
		w.Header().Set("Content-Length", strconv.Itoa(len(globalData)))
		w.WriteHeader(http.StatusOK)
	case http.MethodGet:
		w.Header().Set("Content-Length", strconv.Itoa(len(globalData)))
		w.Write(globalData)
	case http.MethodPut:
		globalData = make([]byte, r.ContentLength)
		_, err := io.ReadFull(r.Body, globalData)
		if err != nil {
			http.Error(w, "Error reading request body", http.StatusInternalServerError)
			return
		}
		defer r.Body.Close()
		w.WriteHeader(http.StatusOK)
	default:
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
	}
}

func dataHandler2(w http.ResponseWriter, r *http.Request) {
	size, _ := strconv.ParseInt(strings.TrimPrefix(r.URL.Path, "/data/"), 10, 64)
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	w.Write(globalData[:size])
}

func PrintHexComparison(slice1, slice2 []byte) {
	maxLen := len(slice1)
	if len(slice2) > maxLen {
		maxLen = len(slice2)
	}

	for i := 0; i < maxLen; i += 8 {
		fmt.Printf("0x%04X   ", i)
		hexStr1 := ""
		for j := i; j < i+8; j++ {
			if j < len(slice1) {
				hexStr1 += fmt.Sprintf("%02X ", slice1[j])
			} else {
				hexStr1 += "   "
			}
		}
		fmt.Printf("%-20s", hexStr1)

		hexStr2 := ""
		for j := i; j < i+8; j++ {
			if j < len(slice2) {
				hexStr2 += fmt.Sprintf("%02X ", slice2[j])
			} else {
				hexStr2 += "   "
			}
		}
		fmt.Printf("| %-20s\n", hexStr2)
	}
}

func nextSize(v uint64, step uint64) uint64 {
	pow2 := uint64(1);
	for pow2 <= v { pow2 *= 2 }
	v = uint64(float64(v) * math.Pow(2, 1.0/float64(step))) + 1;
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

func main() {
	var (
		serverMode bool
		test string
		addr string
		object_size uint64 = 1<<30
		ucxMode bool
		window int
		messageSizes string
		volume uint64
		profile string
	)

	flag := flag.NewFlagSet("myflag", flag.ExitOnError)
	flag.BoolVar(&serverMode, "s", false, "Server");
	flag.StringVar(&test, "t", "loop", "test type");
	flag.IntVar(&window, "w", 1, "window");
	flag.StringVar(&messageSizes, "m", "1073741824", "messages sizes");
	flag.StringVar(&addr, "a", "2.1.3.34:13337", "Address");
	flag.BoolVar(&ucxMode, "U", false, "use UCX");
	flag.Uint64Var(&volume, "v", 1099511627776, "volume");
	flag.StringVar(&profile, "P", "", "Profile directory");

	if err := flag.Parse(os.Args[1:]); err != nil {
		os.Exit(1)
	}

	if profile != "" {
		var proto string
		if ucxMode {
			proto = "U"
		} else {
			proto = "H"
		}
		label := fmt.Sprintf("%s-%s-%d-%s", proto, test, window, messageSizes)

		fc, err := os.Create(fmt.Sprintf("%s/gohttptest-%s.cpuprof", profile, label))
		if err != nil {
			panic(err)
		}
		defer fc.Close()
		pprof.StartCPUProfile(fc)
		defer pprof.StopCPUProfile()

		defer func() {
			fm, err := os.Create(fmt.Sprintf("%s/gohttptest-%s.memprof", profile, label))
			if err != nil {
				panic(err)
			}
			pprof.Lookup("allocs").WriteTo(fm, 0)
			fm.Close()
		}()
	}

	_, object_size, _ = sizes(messageSizes)
	if test == "srv" {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

		obj := make([]byte, object_size)
		rand.Read(obj)
		globalData = obj
		http.HandleFunc("/$", rootHandler)
		http.HandleFunc("/hello", helloHandler)
		http.HandleFunc("/data", dataHandler)
		http.HandleFunc("/data/", dataHandler2)

		if ucxMode {
			server, err := uhttp.NewServer(addr, http.DefaultServeMux)
			if err != nil {
				log.Fatalf("FATAL: StartServer: %v", err)
			}
			go func() {
				<-sigChan
				server.Close()
			}()
			fmt.Printf("Serve UCX on %s\n", addr)
			server.Serve()
		} else {
			server := &http.Server{
				Addr: addr,
			}
			go func() {
				<-sigChan
				server.Shutdown(context.Background())
			}()
			fmt.Printf("Serve HTTP on %s\n", addr)
			err := server.ListenAndServe()
			if err != nil {
				log.Fatalf("FATAL: StartServer: %v", err)
			}
		}
	} else if test == "put" {
		obj := make([]byte, object_size)
		rand.Read(obj)
		fileobj := bytes.NewReader(obj)

		url := fmt.Sprintf("http://%s/data", addr)
		req, _ := http.NewRequest("PUT", url, fileobj)
		req.Header.Set("Content-Length", strconv.FormatUint(object_size, 10))
		dateHdr := time.Now().UTC().Format("20060102T150405Z")
		req.Header.Set("X-Amz-Date", dateHdr)
		t, _ := uhttp.NewTransport()
		defer t.Close()
		client := &http.Client{Transport: t}
		resp, err := client.Do(req)
		defer resp.Body.Close()
		if err != nil {
			log.Fatalf("FATAL: Error uploading: %v", err)
		}
		fmt.Printf("Upload status %s: resp: %+v\n", resp.Status, resp)
	} else if test == "loop" {
		obj := make([]byte, object_size)
		rand.Read(obj)
		obj32 := *(*[]uint32)(unsafe.Pointer(&obj))
		obj32 = obj32[:len(obj)/4]
		for i := 0; i < len(obj32); i++ {
			obj32[i] = uint32(i)
		}
		fileobj := bytes.NewReader(obj)

		t, _ := uhttp.NewTransport()
		defer t.Close()
		client := &http.Client{Transport: t}

		url := fmt.Sprintf("http://%s/", addr)
		resp, _ := client.Get(url)
		defer resp.Body.Close()
		_, _ = ioutil.ReadAll(resp.Body)

		url = fmt.Sprintf("http://%s/data", addr)
		putReq, _ := http.NewRequest("PUT", url, fileobj)
		putReq.Header.Set("Content-Length", strconv.FormatUint(object_size, 10))
		dateHdr := time.Now().UTC().Format("20060102T150405Z")
		putReq.Header.Set("X-Amz-Date", dateHdr)
		putResp, err := client.Do(putReq)
		defer putResp.Body.Close()
		if err != nil {
			log.Fatalf("FATAL: Error uploading: %v", err)
		}
		fmt.Printf("Upload status %s: resp: %+v\n", putResp.Status, putResp)

		url = fmt.Sprintf("http://%s/data", addr)
		getReq, _ := http.NewRequest("GET", url, nil)
		getResp, err := client.Do(getReq)
		defer getResp.Body.Close()
		if err != nil {
			log.Fatalf("FATAL: Error uploading: %v", err)
		}
		read := new(bytes.Buffer)
		_, err = io.Copy(read, getResp.Body)
		if !bytes.Equal(obj, read.Bytes()) {
			PrintHexComparison(obj, read.Bytes())
		}
	} else if test == "get" {
		var t http.RoundTripper
		if ucxMode {
			t, _ = uhttp.NewTransport()
		}
		client := &http.Client{Transport: t}
		resp, err := client.Get(fmt.Sprintf("http://%s/", addr))
		fmt.Printf("%v %v\n", resp, err)
		body, _ := ioutil.ReadAll(resp.Body)
		fmt.Printf("%s\n", body)
		resp.Body.Close()

		for i := 0; i < 30 ; i++ {
			url := fmt.Sprintf("http://%s/data/%d", addr, 1 << i)
			getReq, _ := http.NewRequest("GET", url, nil)
			getResp, err := client.Do(getReq)
			if err != nil {
				log.Fatalf("FATAL: Error uploading: %v", err)
			}
			read := new(bytes.Buffer)
			io.Copy(read, getResp.Body)
			fmt.Printf("%s\n", url)
			getResp.Body.Close()
		}
		resp, err = client.Get(fmt.Sprintf("http://%s/wrong", addr))
		fmt.Printf("%v %v\n", resp, err)
		resp.Body.Close()
	} else if test == "perf" {
		var t http.RoundTripper
		if ucxMode {
			t, _ = uhttp.NewTransport()
		}
		client := &http.Client{Transport: t}

		min, max, step := sizes(messageSizes)
		for size := min; size <= max; size = nextSize(size, step) {
			start := time.Now()
			url := fmt.Sprintf("http://%s/data/%d", addr, size)
			var total int64
			var wg sync.WaitGroup
			wg.Add(window)
			done := make(chan struct{})
			go func() {
				last := atomic.LoadInt64(&total)
				ticker := time.NewTicker(time.Second)
				defer ticker.Stop()

				for {
					select {
					case <-ticker.C:
						curr := atomic.LoadInt64(&total)
						fmt.Printf("%20s %20f\n", "", float64(curr-last)*1e-6)
						last = curr
					case <-done:
						return
					}
				}
			}()

			for t := 0; t < window; t++ {
				go func() {
					content := make([]byte, size)
					iter := volume / size
					for i := uint64(0); i < iter ; i++ {
						getReq, _ := http.NewRequest("GET", url, nil)
						getResp, err := client.Do(getReq)
						if err != nil {
							log.Fatalf("FATAL: Error downloading: %v", err)
						}
						done := make(chan int64)
						go func() {
							size, _ := io.ReadFull(getResp.Body, content)
							getResp.Body.Close()
							done <- int64(size)
						}()
						select {
						case size := <-done:
							atomic.AddInt64(&total, size)
						case <-time.After(time.Second):
							log.Fatalf("timeout in read %d %s\n", i, uhttp.Dump(getResp.Body))
						}
					}
					wg.Done()
				}()
			}
			wg.Wait()
			close(done)
			fmt.Printf("%20d %20f\n", size, float64(total)/float64(time.Since(start).Seconds())*1e-6)
		}
	} else if test == "head" {
		var t http.RoundTripper
		if ucxMode {
			t, _ = uhttp.NewTransport()
		}
		client := &http.Client{Transport: t}

		start := time.Now()
		url := fmt.Sprintf("http://%s/data", addr)
		var total int64
		var wg sync.WaitGroup
		wg.Add(window)
		done := make(chan struct{})
		go func() {
			last := atomic.LoadInt64(&total)
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()

			for {
				select {
				case <-ticker.C:
					curr := atomic.LoadInt64(&total)
					fmt.Printf("%20f\n", float64(curr-last))
					last = curr
				case <-done:
					return
				}
			}
		}()

		for t := 0; t < window; t++ {
			go func() {
				for i := uint64(0); i < volume ; i++ {
					getReq, _ := http.NewRequest("HEAD", url, nil)
					getResp, err := client.Do(getReq)
					if err != nil {
						log.Fatalf("FATAL: Error downloading: %v", err)
					}
					getResp.Body.Close()
					atomic.AddInt64(&total, 1)
				}
				wg.Done()
			}()
		}
		wg.Wait()
		close(done)
		fmt.Printf("%20f\n", float64(total)/float64(time.Since(start).Seconds()))
	} else {
		t, _ := uhttp.NewTransport()
		defer t.Close()
		client := &http.Client{Transport: t}

		url := fmt.Sprintf("http://%s/", addr)
		resp, err := client.Get(url)
		fmt.Printf("%v %v\n", resp, err)
		defer resp.Body.Close()
		body, _ := ioutil.ReadAll(resp.Body)
		fmt.Printf("%s\n", body)
	}

	
}
