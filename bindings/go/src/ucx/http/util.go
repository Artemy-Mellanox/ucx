package http

import (
	"encoding/binary"
	"net/textproto"
)

type pack []byte

func newPack() pack {
	return make(pack, 0, 64)
}

func (p *pack) put(n int) []byte {
	l := len(*p)
	r := l + n
	if cap(*p) < r {
		*p = append(*p, make([]byte, n)...)
	} else {
		*p = (*p)[:r]
	}
	return (*p)[l:r]
}

func (p *pack) uint16(i uint16) {
	b := p.put(2)
	binary.LittleEndian.PutUint16(b, i)
}

func (p *pack) uint32(i uint32) {
	b := p.put(4)
	binary.LittleEndian.PutUint32(b, i)
}

func (p *pack) uint64(i uint64) {
	b := p.put(8)
	binary.LittleEndian.PutUint64(b, i)
}

func (p *pack) int64(i int64) {
	p.uint64(uint64(i))
}

func (p *pack) int(i int) {
        p.uint16(uint16(i))
}

func (p *pack) string(s string) {
	l := len(s)
	p.int(l)
	b := p.put(l)
	copy(b, []byte(s))
}

func (p *pack) strmap(m map[string][]string) {
        p.uint16(uint16(len(m)))
	for k, vv := range m {
		p.string(textproto.CanonicalMIMEHeaderKey(k))
		p.uint16(uint16(len(vv)))
		for _, v := range vv {
			p.string(v)
		}
	}
}

type unpack struct {
	b []byte
	p int
}

func (u *unpack) get(n int) []byte {
	b := u.b[u.p:u.p + n]
	u.p += n
	return b
}

func (u *unpack) uint16() uint16 {
	b := u.get(2)
	return binary.LittleEndian.Uint16(b)
}

func (u *unpack) uint32() uint32 {
	b := u.get(4)
	return binary.LittleEndian.Uint32(b)
}

func (u *unpack) uint64() uint64 {
	b := u.get(8)
	return binary.LittleEndian.Uint64(b)
}

func (u *unpack) int64() int64 {
	return int64(u.uint64())
}

func (u *unpack) int() int {
	return int(u.uint16())
}

func (u *unpack) string() string {
	l := u.int()
	return string(u.get(l))
}

func (u *unpack) strmap() map[string][]string {
	ml := u.int()
	m := make(map[string][]string, ml)
	for i := 0; i < ml; i++ {
		key := u.string()
		ll := u.int()
		m[key] = make([]string, ll)
		for j := range m[key] {
			m[key][j] = u.string()
		}
	}
	return m
}
