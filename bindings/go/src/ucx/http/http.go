package http

/*
#include <stdlib.h>
#include <string.h>
*/
import "C"
import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/openucx/ucx/bindings/go/src/ucx"
)

var (
	logLevel slog.LevelVar
	logger *slog.Logger
	levelTrace = slog.Level(-8)
	levelTraceReq = slog.Level(-9)
)

type traceHandler struct {
	h slog.Handler
}

func (h *traceHandler) Enabled(ctx context.Context, level slog.Level) bool {
    return h.h.Enabled(ctx, level)
}

func (h *traceHandler) Handle(ctx context.Context, r slog.Record) error {
	fs := runtime.CallersFrames([]uintptr{r.PC})
        f, _ := fs.Next()
	var b strings.Builder
	b.WriteString(f.Function)
	b.WriteString(":")
	b.WriteString(strconv.Itoa(f.Line))
	r.Add("src", b.String())
	return h.h.Handle(ctx, r)
}

func (h *traceHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
    return &traceHandler{h: h.h.WithAttrs(attrs)}
}

func (h *traceHandler) WithGroup(name string) slog.Handler {
    return &traceHandler{h: h.h.WithGroup(name)}
}

func init() {
	textHandler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{ Level: &logLevel })
	handler := &traceHandler{h: textHandler}
	logger = slog.New(handler)
	levelStr := os.Getenv("GO_UCX_HTTP_LOG_LEVEL")
	switch strings.ToUpper(levelStr) {
	case "TRACE": logLevel.Set(levelTrace)
	case "REQ": logLevel.Set(levelTraceReq)
	}

	ucsLevelStr := os.Getenv("UCX_LOG_LEVEL")
	if ucsLevelStr != "" {
		ucx.SetLogger(logger)
	}
}

func trace(args ...any) {
	logger.Log(context.Background(), levelTrace, "http", args...)
}

func traceReq(args ...any) {
	logger.Log(context.Background(), levelTraceReq, "http", args...)
}

const AM_REQ = 1
const AM_RESP = 2

func getBuf(buf []byte) (unsafe.Pointer, uint64) {
	if len(buf) > 0 {
		return unsafe.Pointer(&buf[0]), uint64(len(buf))
	}
	return nil, 0
}

type ctx struct {
	context *ucx.UcpContext
	worker *ucx.UcpWorker
	quit chan struct{}
}

func (c *ctx) Init() {
	contextParams := ucx.UcpParams{}
	contextParams.EnableAM()
	contextParams.EnableStream()
	context, err := ucx.NewUcpContext(&contextParams)
	if err != nil {
		log.Fatalf("Failed to create UCX context: %v", err)
	}

	workerParams := ucx.UcpWorkerParams{}
	workerParams.SetThreadMode(ucx.UCS_THREAD_MODE_MULTI)
	worker, err := context.NewWorker(&workerParams)
	if err != nil {
		log.Fatalf("Failed to create UCX worker: %v", err)
	}

	c.context = context
	c.worker = worker
	c.quit = make(chan struct{})
}

func (c *ctx) Close() {
	c.quit <- struct{}{}
	c.worker.Close()
	c.context.Close()
}

func (c *ctx) progress() {
	for {
		select {
		case <-c.quit: return
		default: c.worker.Progress();
		}
	}
}

type Server struct {
	ctx
	listener *ucx.UcpListener
	handler http.Handler
}

type reqKey struct {
	host string
	id int
}

func (key reqKey) LogValue() slog.Value {
	return slog.IntValue(key.id)
}

type responseWriter struct {
	ep       *ucx.UcpEp
	headers  http.Header
	status   int
	wrote    chan struct{}
	key	 reqKey
	headerSent bool
	length   int
}

func (w *responseWriter) Header() http.Header {
	return w.headers
}

func (w *responseWriter) onData(request *ucx.UcpRequest, status ucx.UcsStatus) {
	request.Close()
	w.wrote <- struct{}{}
}

func (w *responseWriter) Write(data []byte) (int, error) {
	dataPtr, dataLen := getBuf(data)
	if !w.headerSent {
		w.length = int(dataLen)
		w.WriteHeader(w.status)
	}
	reqParams := &ucx.UcpRequestParams{}
	reqParams.SetCallback(w.onData)
	traceReq("id", w.key, "length", dataLen)
	if _, err := w.ep.SendStreamNonBlocking(w.key.id, dataPtr, dataLen, reqParams); err != nil {
		return 0, err
	}
	<-w.wrote
	return int(dataLen), nil
}

func (w *responseWriter) WriteHeader(statusCode int) {
	w.status = statusCode

	if _, hasLength := w.headers["Content-Length"]; !hasLength {
		if w.length > 0 {
			w.headers.Set("Content-Length", strconv.Itoa(w.length))
		} else if statusCode != http.StatusOK {
			return;
		}
	}

	headerMap := map[string]string{
		"ucx-code": strconv.Itoa(w.status),
		"ucx-id": strconv.Itoa(w.key.id),
		"ucx-host": w.key.host,
	}

	for k, v := range w.headers {
		headerMap[k] = v[0]
	}

	header, err := json.Marshal(headerMap)
	if err != nil {
		return
	}

	headerPtr, headerLen := getBuf(header)
	_, err = w.ep.SendAmNonBlocking(AM_RESP,
		headerPtr, headerLen, nil, 0,
		ucx.UCP_AM_SEND_FLAG_REPLY, nil)
	if err != nil {
		return
	}
	w.headerSent = true
	traceReq("id", w.key, "status", statusCode, "length", w.headers.Get("Content-Length"))
}

type dataReader struct {
	ep *ucx.UcpEp
	read chan int
	left int
	key reqKey
	onClose func()
}

func (r *dataReader) onData(request *ucx.UcpRequest, status ucx.UcsStatus, length uint64) {
	request.Close()
	r.read <- int(length)
}

func (r *dataReader) Read(p []byte) (length int, res error) {
	if r.left != 0 {
		dataPtr, dataLen := getBuf(p)
		if dataLen > uint64(r.left) {
			dataLen = uint64(r.left)
		}
		reqParams := &ucx.UcpRequestParams{}
		reqParams.SetCallback(r.onData)
		if _, res = r.ep.RecvStreamNonBlocking(r.key.id, dataPtr, dataLen, reqParams); res != nil {
			return 0, res
		}
		length = <-r.read
		r.left -= length
		traceReq("id", r.key, "length", length, "left", r.left)
		if r.left < 0 {
			log.Fatalf("Read underrun")
		}
	}
	if r.left == 0 {
		res = io.EOF
	}
	return length, res
}

func (r *dataReader) Close() (error) {
	if r.onClose != nil {
		r.onClose()
	}
	return nil
}

func handleAm(header unsafe.Pointer, headerSize uint64, replyEp *ucx.UcpEp) (map[string]string, *dataReader, int64, reqKey, error) {
	var headerMap map[string]string
	if headerSize > 0 {
		headerBytes := ucx.GoBytes(header, headerSize)
		if err := json.Unmarshal(headerBytes, &headerMap); err != nil {
			return nil, nil, 0, reqKey{}, err
		}
	}

	length, _ := strconv.ParseInt(headerMap["Content-Length"], 10, 64)
	id, _ := strconv.Atoi(headerMap["ucx-id"])
	key := reqKey{
		id: id,
		host: headerMap["ucx-host"],
	}
	r := &dataReader {
		ep: replyEp,
		left: int(length),
		key: key,
		read: make(chan int, 1),
	}

	return headerMap, r, length, key, nil
}

func (s *Server) handleRequest(header unsafe.Pointer, headerSize uint64, data *ucx.UcpAmData, replyEp *ucx.UcpEp) ucx.UcsStatus {
	headerMap, reader, contentLength, key, err := handleAm(header, headerSize, replyEp)
	if err != nil {
		fmt.Printf("request %v\n", err)
		return ucx.UCS_ERR_IO_ERROR
	}

	req, _ := http.NewRequest(headerMap["ucx-method"], headerMap["ucx-url"], reader)
	for k, v := range headerMap {
		if !strings.HasPrefix(k, "ucx-") {
			req.Header.Set(k,v)
		}
	}
	req.ContentLength = contentLength
	req.RequestURI = req.URL.EscapedPath()
	writer := &responseWriter{
		ep: replyEp,
		headers: make(http.Header),
		key: key,
		wrote: make(chan struct{}, 1),
		status: http.StatusOK,
	}
	trace("url", req.URL, "id", key, "length", contentLength)

	go s.handler.ServeHTTP(writer, req)
	return ucx.UCS_OK
}

func onErr(ep *ucx.UcpEp, status ucx.UcsStatus) {
	if status == ucx.UCS_ERR_CONNECTION_RESET {
		return
	}
	errorString := fmt.Sprintf("Endpoint error: %v", status.String())
	panic(errorString)
}

func (s *Server) servConn(conn *ucx.UcpConnectionRequest) {
	epParams := &ucx.UcpEpParams{}
	epParams.SetConnRequest(conn)
	epParams.SetErrorHandler(onErr)
	_, err := s.worker.NewEndpoint(epParams)
	if err != nil {
		fmt.Printf("Failed to create endpoint: %v\n", err)
		return
	}
}

func (s *Server) Close() {
	s.listener.Close()
	s.ctx.Close()
}

func NewServer(addr string, handler http.Handler) (*Server, error) {
	s := &Server{
		handler: handler,
	}
	s.Init()

	s.worker.SetAmRecvHandler(AM_REQ, ucx.UCP_AM_FLAG_PERSISTENT_DATA, s.handleRequest)

	tcp, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, err
	}

	listenerParams := &ucx.UcpListenerParams{}
	listenerParams.SetSocketAddress(tcp)
	listenerParams.SetConnectionHandler(s.servConn)
	listener, err := s.worker.NewListener(listenerParams);
	if err != nil {
		return nil, err
	}

	s.listener = listener
	return s, nil
}

func (s *Server) Serve() {
	s.progress()
}

func StartServer(addr string, handler http.Handler) (serve func() error, err error) {
	s, err := NewServer(addr, handler)
	if (err != nil) {
		return nil, err
	}
	serve = func() error {
		s.Serve()
		return nil
	}
	return
}

const (
	TR_PENDING_SEND = 1 << iota
	TR_PENDING_RECV
)

type tracker struct {
	resp chan *http.Response
	noBody bool
	pending int
	data []byte
}

type Transport struct {
	ctx
	reqs sync.Map
	conns sync.Map
	mu sync.Mutex
	trPool sync.Pool
}

type connection struct {
	ep *ucx.UcpEp
	chPool chan int
	mu sync.Mutex
	host string
	transport *Transport
	err chan error
}

func (c *connection) Close() {
	c.ep.CloseNonBlockingForce(nil)
}

func (c *connection) onError(ep *ucx.UcpEp, status ucx.UcsStatus) {
	c.err <- ucx.NewUcxError(status)
}

func (t *Transport) newConnection(host string) (*connection, error) {
	conn := &connection{
		transport: t,
		host: host,
		err: make(chan error),
		chPool: make(chan int, 64),
	}

	for id := 0; id < 64; id++ {
		conn.chPool <- id
	}

	tcp, err := net.ResolveTCPAddr("tcp", host)
	if err != nil {
		return nil, err
	}

	epParams := &ucx.UcpEpParams{}
	epParams.SetSocketAddress(tcp)
	epParams.SetErrorHandler(conn.onError)
	ep, err := t.worker.NewEndpoint(epParams)
	if err != nil {
		return nil, err
	}

	conn.ep = ep
	return conn, nil
}

func (c *connection) getCh() (int) {
	select {
	case id := <-c.chPool: return id
	case <-time.After(time.Second): panic("getCh timeout")
	}
}

func (c *connection) putCh(id int) {
	c.chPool <- id
}

func (c *connection) donePending(tr *tracker, f int, reqId int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	traceReq("id", reqId, "f", f, "pending", tr.pending)
	tr.pending &= ^f
	if tr.pending == 0 {
		traceReq("id", reqId, "f", f)
		c.putCh(reqId)
		c.transport.reqs.Delete(reqId)
		c.transport.trPool.Put(tr)
	}
}

func (c *connection) roundTrip(req *http.Request) (*http.Response, error) {
	reqId := c.getCh()
	key := reqKey {
		host: c.host,
		id: reqId,
	}
	traceReq("url", req.URL, "id", key, "length", req.ContentLength)
	headerMap := map[string]string{
		"ucx-method": req.Method,
		"ucx-url": req.URL.String(),
		"ucx-id": strconv.Itoa(reqId),
		"ucx-host": c.host,
		"Content-Length": strconv.FormatInt(req.ContentLength, 10),
	}

	for k, v := range req.Header {
		headerMap[k] = v[0]
	}

	header, err := json.Marshal(headerMap)
	if err != nil {
		return nil, err
	}

	tr := c.transport.trPool.Get().(*tracker)
	tr.noBody = req.Method == http.MethodHead
	tr.pending = TR_PENDING_RECV
	c.transport.reqs.Store(key, tr)

	headerPtr, headerLen := getBuf(header)
	send, err := c.ep.SendAmNonBlocking(AM_REQ,
		headerPtr, headerLen, nil, 0,
		ucx.UCP_AM_SEND_FLAG_REPLY, nil)
	if err != nil {
		return nil, err
	}
	defer send.Close()

	if req.Body != nil {
		tr.data, err = ioutil.ReadAll(req.Body)
		dataPtr, dataLen := getBuf(tr.data)
		reqParams := &ucx.UcpRequestParams{}
		reqParams.SetCallback(func (request *ucx.UcpRequest, status ucx.UcsStatus) {
			c.donePending(tr, TR_PENDING_SEND, reqId)
			request.Close()
		})
		traceReq("url", req.URL, "length", dataLen)
		tr.pending |= TR_PENDING_SEND
		_, err := c.ep.SendStreamNonBlocking(reqId, dataPtr, dataLen, reqParams)
		if err != nil {
			return nil, err
		}
	}

	select {
	case resp := <-tr.resp:
		trace("url", req.URL, "resp", resp.StatusCode)
		return resp, nil
	case err := <-c.err:
		trace("url", req.URL, "err", err)
		return nil, err
	}
}

func NewTransport() (*Transport, error) {
	t := new(Transport)
	t.Init()
	t.worker.SetAmRecvHandler(AM_RESP, ucx.UCP_AM_FLAG_PERSISTENT_DATA, t.handleResponse)
	t.trPool = sync.Pool{
		New: func() interface{} {
			return &tracker{
				resp: make(chan *http.Response),
			}
		},
	}

	go t.progress()
	return t, nil
}

func (t *Transport) handleResponse(header unsafe.Pointer, headerSize uint64, data *ucx.UcpAmData, replyEp *ucx.UcpEp) ucx.UcsStatus {
	headerMap, reader, contentLength, key, err := handleAm(header, headerSize, replyEp)
	if err != nil {
		fmt.Printf("handleResponse %v\n", err)
		return ucx.UCS_ERR_IO_ERROR
	}

	req, _ := t.reqs.Load(key)
	c, _ := t.conns.Load(key.host)
	conn := c.(*connection)

	tr := req.(*tracker)
	if tr.noBody {
		reader.left = 0
	}

	resp := &http.Response{
		Body: reader,
	}

	reader.onClose = func() {
		conn.donePending(tr, TR_PENDING_RECV, key.id)
	}

	resp.Header = http.Header(respHeader.unpackMap())
	resp.StatusCode = status
	resp.ContentLength = length
	traceReq("host", key.host, "id", key.id, "status", status, "length", length, "left", reader.left)

	tr.resp <- resp
	return ucx.UCS_OK
}

func (t *Transport) getConnection(host string) (*connection, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	c, has := t.conns.Load(host)
	if has {
		return c.(*connection), nil
	}

	conn, err := t.newConnection(host)
	if err != nil {
		return nil, err
	}
	t.conns.Store(host, conn)
	return conn, nil
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	conn, err := t.getConnection(req.URL.Host)
	if err != nil {
		return nil, err
	}

	return conn.roundTrip(req);
}

func (t *Transport) Close() {
	t.ctx.Close()
}

func Dump(o interface{}) string {
	switch o := o.(type) {
	case *dataReader:
		return fmt.Sprintf("dataReader %d %d", o.left, o.key.host, o.key.id)
	}
	return fmt.Sprintf("%T %v", o, o)
}
