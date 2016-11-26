package syslogp

import (
	"bytes"
	"reflect"
	"strconv"
	"testing"
)

func Test_FrameWriter(t *testing.T) {
	const expSize = 512

	cases := [...]struct {
		in      [][]byte
		bufSize int
	}{
		{[][]byte{nil}, 0},
		{[][]byte{[]byte{}, []byte(`first`)}, 0},
		{[][]byte{[]byte(`first`), []byte(`second`)}, 0},
		{[][]byte{nil}, 128},
		{[][]byte{[]byte{}, []byte(`first`)}, 128},
		{[][]byte{[]byte(`first`), []byte(`second`)}, 128},
	}
	b, exp := new(bytes.Buffer), make([]byte, 0, expSize)

	for _, c := range cases {
		n, w := 0, NewFrameWriter(b, make([]byte, c.bufSize))

		b.Reset()
		exp = exp[:0]

		for _, frame := range c.in {
			if len(frame) == 0 {
				n++
			}
			w.Write(frame)
			exp = appendFrame(exp, frame)
		}
		w.Flush()

		if out := b.Bytes(); !bytes.Equal(exp, out) {
			t.Errorf("\n\tfor: empty/frames = %d/%d, buffer size = %d\n\texp: %q\n\tgot: %q\n", n, len(c.in), c.bufSize, exp, out)
		}
	}
}

func Test_FrameScanner(t *testing.T) {
	cases := [...]struct {
		in           []byte
		exp          []string
		err          error
		bufSize      int
		maxFrameSize int
	}{
		{[]byte(`first6 second`), []string{}, ErrFrame, 8, 16},
		{[]byte(`05first6 second`), []string{}, ErrFrame, 8, 16},
		{[]byte(`5 first06 second5 third`), []string{`first`}, ErrFrame, 8, 16},
		{[]byte(`5 first17 second1234567890a5 third`), []string{`first`}, ErrFrameExceeded, 8, 16},
		{[]byte(`5 first10 second`), []string{`first`, `second`}, nil, 8, 16},
		{[]byte(`5 first16 second12345678905 third`), []string{`first`, `second12`, `third`}, nil, 8, 16},
		{[]byte(`15 first123456789016 second1234567890`), []string{`first1234567890`, `second1234567890`}, nil, 16, 32},
		{[]byte(`5 first6 second5 third6 fourth5 fifth`), []string{`first`, `second`, `third`, `fourth`, `fifth`}, nil, 16, 32},
	}
	b := new(bytes.Buffer)

	for _, c := range cases {
		b.Reset()
		b.Write(c.in)

		f := NewFrameScanner(b, make([]byte, c.bufSize), c.maxFrameSize)
		out := []string{}

		for i := 0; f.Next(); i++ {
			out = append(out, string(f.Bytes()))
		}
		if err := f.Err(); err != c.err || !reflect.DeepEqual(c.exp, out) {
			t.Errorf("\n\tfor: %s\n\texp: %s, %v\n\tgot: %s, %v\n", c.in, c.exp, c.err, out, err)
		}

	}
}

func appendFrame(r, p []byte) []byte {
	if len(p) == 0 {
		return r
	}
	r = strconv.AppendInt(r, int64(len(p)), 10)
	m := len(r)
	r = r[:m+1]
	r[m] = ' '
	return append(r, p...)
}
