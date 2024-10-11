package ucx

// #include <ucp/api/ucp.h>
import "C"
import "unsafe"

func (w *UcpWorker) UCP() unsafe.Pointer {
	return unsafe.Pointer(w.worker)
}

func (e *UcpEp) UCP() unsafe.Pointer {
	return unsafe.Pointer(e.ep)
}

func (m *UcpMemory) UCP() unsafe.Pointer {
	return unsafe.Pointer(m.memHandle)
}
