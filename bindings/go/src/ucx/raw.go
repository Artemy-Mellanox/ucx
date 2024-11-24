package ucx

import "unsafe"

func (w *UcpWorker) RawPtr() unsafe.Pointer {
	return unsafe.Pointer(w.worker)
}

func (e *UcpEp) RawPtr() unsafe.Pointer {
	return unsafe.Pointer(e.ep)
}

func (m *UcpMemory) RawPtr() unsafe.Pointer {
	return unsafe.Pointer(m.memHandle)
}
