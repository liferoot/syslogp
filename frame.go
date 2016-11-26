package syslogp

import (
	"errors"
	"io"
	"strconv"
)

type FrameScanner struct {
	r            io.Reader
	err          error
	buf          []byte
	frame        []byte
	start        int
	end          int
	offset       int
	shift        int
	maxFrameSize int
}

func (f *FrameScanner) Next() bool {
	var (
		c         byte
		frameSize int
		n, m      int
	)
	for f.offset > 0 {
		if n, f.err = f.r.Read(f.buf); f.err != nil {
			return false
		}
		f.offset -= n
	}
	if f.offset < 0 {
		f.start = f.offset + n
		f.end = n
		f.offset = 0
	}
	for {
		if f.end > f.start {
			if frameSize == 0 {
				for ; f.start < f.end; f.start++ {
					c = f.buf[f.start]

					if m > 0 && c == ' ' {
						m, frameSize = 0, m
						f.start++
						break
					}
					if (m == 0 && c == '0') || '0' > c || c > '9' {
						f.err = ErrFrame
						return false
					}
					m *= 10
					m += int(c - '0')

					if 0 < f.maxFrameSize && f.maxFrameSize < m {
						f.err = ErrFrameExceeded
						return false
					}
				}
				if frameSize > len(f.buf) {
					f.offset = frameSize - len(f.buf)
					frameSize = len(f.buf)
				}
			}
			n = f.end - f.start

			if frameSize > n && f.err != nil {
				frameSize = n
			}
			if 0 < frameSize && frameSize <= n {
				frameSize += f.start
				f.frame = f.buf[f.start:frameSize]
				f.start = frameSize
				return true
			}
		}
		if f.err != nil {
			f.start = 0
			f.end = 0
			f.offset = 0
			return false
		}
		if f.start > 0 && (f.end == len(f.buf) || f.start >= f.shift) {
			copy(f.buf, f.buf[f.start:f.end])
			f.end -= f.start
			f.start = 0
		}
		n, f.err = f.r.Read(f.buf[f.end:])
		f.end += n
	}
}

func (f *FrameScanner) Bytes() []byte {
	return f.frame
}

func (f *FrameScanner) Err() error {
	if f.err == io.EOF {
		return nil
	}
	return f.err
}

func (f *FrameScanner) Reset(r io.Reader) {
	f.r = r
	f.err = nil
	f.start = 0
	f.end = 0
	f.offset = 0
}

func NewFrameScanner(r io.Reader, buf []byte, maxFrameSize int) *FrameScanner {
	if cap(buf) < 1 {
		panic(`syslogp.FrameScanner: buffer capacity must be greater than zero.`)
	}
	return &FrameScanner{
		r:            r,
		buf:          buf[:cap(buf)],
		shift:        cap(buf) >> 1,
		maxFrameSize: maxFrameSize,
	}
}

type FrameWriter struct {
	w       io.Writer
	buf     []byte
	offset  int
	scratch [20]byte
}

// Reset discards all unflushed buffered frames and
// resets f to write its output to w.
func (f *FrameWriter) Reset(w io.Writer) {
	f.w = w
	f.offset = 0
}

// Flush writes all buffered frames to the underlying io.Writer.
func (f *FrameWriter) Flush() error {
	if f.offset > 0 {
		n, err := f.w.Write(f.buf[:f.offset])

		if n < f.offset && err == nil {
			err = io.ErrShortWrite
		}
		if err != nil {
			if 0 < n && n < f.offset {
				copy(f.buf[0:], f.buf[n:f.offset])
			}
			f.offset -= n
			return err
		}
		f.offset = 0
	}
	return nil
}

// Its returns the number of bytes written and any error.
func (f *FrameWriter) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return
	}
	h := strconv.AppendInt(f.scratch[:0], int64(len(p)), 10)
	m := len(h)

	h = h[:m+1]
	h[m] = ' '

	if m += len(p) + 1; m > len(f.buf)-f.offset {
		if err = f.Flush(); err == nil && m > len(f.buf) {
			if n, err = f.write(h); err == nil {
				a := 0
				a, err = f.write(p)
				n += a
			}
			return
		}
	}
	if err == nil {
		n = copy(f.buf[f.offset:], h)
		n += copy(f.buf[f.offset+n:], p)
		f.offset += n
	}
	return
}

func (f *FrameWriter) write(p []byte) (n int, err error) {
	if n, err = f.w.Write(p); err == nil && n < len(p) {
		err = io.ErrShortWrite
	}
	return
}

func NewFrameWriter(w io.Writer, buf []byte) *FrameWriter {
	return &FrameWriter{w: w, buf: buf}
}

var (
	ErrFrame         = errors.New(`invalid frame`)
	ErrFrameExceeded = errors.New(`frame size exceeded`)
)
