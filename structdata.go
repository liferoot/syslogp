package syslogp

import (
	"errors"
	"strconv"
	"unsafe"
)

type StructDataEdger interface {
	StructDataBegin() error
	StructDataEnd() error
}

type StructDataIterator interface {
	StructDataEach(id, param, value []byte, valueType int) error
}

func ScanStructData(data []byte, pos *int, quotes bool, iter StructDataIterator) (err error) {
	var (
		c      byte
		state  uint8
		eof    = len(data)
		mark   int
		id     []byte
		param  []byte
		value  []byte
		vstate uint8
		vlen   uint8
		vtyp   int
	)
	edger, edgerOk := iter.(StructDataEdger)

	if eof == 0 || eof <= *pos {
		goto _err
	}
	if len(data[*pos:]) > 1 && data[*pos] == '-' && data[*pos+1] == ' ' {
		*pos += 2
		if edgerOk {
			if err = edger.StructDataBegin(); err != nil {
				return
			}
			err = edger.StructDataEnd()
		}
		return
	}
_resume:
	switch c = data[*pos]; state {
	case 0:
		if c == '[' {
			state = 1
			if edgerOk {
				if err = edger.StructDataBegin(); err != nil {
					return
				}
			}
			goto _next
		}
		goto _err
	case 1:
		if ' ' < c && c <= '~' && c != '"' && c != '=' {
			state = 2
			goto _mark
		}
		goto _err
	case 2:
		switch c {
		case ' ':
			state = 3
			id = data[mark:*pos]
			goto _next
		case ']':
			state = 10
			id, param, value, vtyp = data[mark:*pos], data[:0], data[:0], 0
			goto _process
		}
		if ' ' < c && c <= '~' && c != '"' && c != '=' && *pos-mark < 31 {
			goto _next
		}
		goto _err
	case 3:
		if ' ' < c && c <= '~' && c != '"' && c != '=' {
			state = 4
			goto _mark
		}
		goto _err
	case 4:
		if c == '=' {
			state = 5
			param = data[mark:*pos]
			goto _next
		}
		if ' ' < c && c <= '~' && c != '"' && *pos-mark < 31 {
			goto _next
		}
		goto _err
	case 5:
		if c == '"' {
			state = 6
			vstate, vlen, vtyp = 1, 0, 0
			goto _next
		}
		goto _err
	case 6:
		switch c {
		case '"':
			state = 9
			value = data[:0]
			goto _process
		case '\\':
			state = 8
		default:
			state = 7
			valueType(&vstate, &vlen, c)
		}
		goto _mark
	case 7:
		switch c {
		case '"':
			state = 9
			value = data[mark:*pos]
			switch vstate {
			case 16, 17:
				vtyp = Float
			case 18:
				vtyp = Int
			case 19:
				vtyp = Nil
			case 20:
				vtyp = False
			case 21:
				vtyp = True
			default:
				if quotes {
					value = data[mark-1 : *pos+1]
				}
			}
			goto _process
		case '\\':
			state = 8
			goto _next
		}
		if vstate > 0 {
			valueType(&vstate, &vlen, c)
		}
		goto _next
	case 8:
		if c == '"' || c == '\\' || c == ']' {
			vtyp++
		}
		state = 7
		goto _next
	case 9:
		switch c {
		case ' ':
			state = 3
			goto _next
		case ']':
			state = 10
			goto _next
		}
		goto _err
	case 10:
		switch c {
		case ' ':
			state = 11
			goto _next
		case '[':
			state = 1
			goto _next
		}
		goto _err
	case 11:
		goto _out
	}
_process:
	if err = iter.StructDataEach(id, param, value, vtyp); err != nil {
		return
	}
	goto _next
_mark:
	mark = *pos
_next:
	if *pos++; *pos != eof {
		goto _resume
	}
_out:
	if state < 11 {
		goto _err
	}
	if edgerOk {
		err = edger.StructDataEnd()
	}
	return
_err:
	return ErrStructData
}

func valueType(state, len *uint8, c byte) {
	switch *state {
	case 0:
		return
	case 1:
		switch c {
		case '+', '-':
			*state = 2
			return
		case '.':
			*state = 3
			return
		case 'f':
			*state = 6
			return
		case 'n':
			*state = 10
			return
		case 't':
			*state = 13
			return
		}
		if '0' <= c && c <= '9' {
			*state = 18
			return
		}
	case 2:
		if c == '.' {
			*state = 3
			return
		}
		if '0' <= c && c <= '9' {
			*state = 18
			return
		}
	case 18:
		if '0' <= c && c <= '9' && *len < 18 {
			*len++
			return
		}
		if c == '.' {
			*state = 3
			return
		}
		if c == 'e' || c == 'E' {
			*state = 4
			return
		}
	case 3:
		if '0' <= c && c <= '9' {
			*state = 16
			return
		}
	case 16:
		if '0' <= c && c <= '9' {
			return
		}
		if c == 'e' || c == 'E' {
			*state = 4
			return
		}
	case 4:
		if c == '+' || c == '-' {
			*state = 5
			return
		}
		if '0' <= c && c <= '9' {
			*state = 17
			return
		}
	case 5:
		if '0' <= c && c <= '9' {
			*state = 17
			return
		}
	case 17:
		if '0' <= c && c <= '9' {
			return
		}
	case 6:
		if c == 'a' {
			*state = 7
			return
		}
	case 7, 11:
		if c == 'l' {
			*state++
			return
		}
	case 8:
		if c == 's' {
			*state = 9
			return
		}
	case 9:
		if c == 'e' {
			*state = 20
			return
		}
	case 10, 14:
		if c == 'u' {
			*state++
			return
		}
	case 12:
		if c == 'l' {
			*state = 19
			return
		}
	case 13:
		if c == 'r' {
			*state = 14
			return
		}
	case 15:
		if c == 'e' {
			*state = 21
			return
		}
	}
	*state = 0
	return
}

func ParseValue(value []byte, valueType int) interface{} {
	if len(value) == 0 || (len(value) == 2 && value[0] == '"') {
		return ``
	}
	if valueType >= 0 {
		if value[0] == '"' {
			value = value[1 : len(value)-1]
		}
		if valueType > 0 {
			value = Unescape(value, valueType)
		}
		goto _ret
	}
	switch valueType {
	case String:
		goto _ret
	case Nil:
		return nil
	case False:
		return false
	case True:
		return true
	case Float:
		v, e := strconv.ParseFloat(bytesToStr(&value), 64)
		if e != nil {
			goto _ret
		}
		return v
	case Int:
		v, ok := parseInt(value)
		if !ok {
			goto _ret
		}
		return v
	}
_ret:
	return string(value)
}

func parseInt(data []byte) (n int64, ok bool) {
	if len(data) == 0 {
		return 0, false
	}
	c := data[0]
	if c == '-' || c == '+' {
		ok = c == '-'
		data = data[1:]
	}
	for _, c = range data {
		if '0' > c || c > '9' {
			return 0, false
		}
		n *= 10
		n += int64(c - '0')
	}
	if ok {
		return -n, true
	}
	return n, true
}

type structDataMap struct {
	m  map[string]interface{}
	id string
}

func (m *structDataMap) StructDataEach(id, param, value []byte, valueType int) error {
	if m.id != bytesToStr(&id) {
		m.id = string(id)
		m.m[m.id] = make(map[string]interface{})
	}
	if len(param) > 0 {
		(m.m[m.id].(map[string]interface{}))[string(param)] = ParseValue(value, valueType)
	}
	return nil
}

func ParseStructData(data []byte, pos *int, m map[string]interface{}) error {
	return ScanStructData(data, pos, false, &structDataMap{m: m})
}

func EscapeCount(data []byte) (n int) {
	for _, c := range data {
		if c == '"' || c == '\\' || c == ']' {
			n++
		}
	}
	return
}

func Escape(data []byte, n int) []byte {
	if len(data) == 0 || n < 1 {
		return data
	}
	r, i := make([]byte, len(data)+n), 0

	for _, c := range data {
		if c == '"' || c == '\\' || c == ']' {
			r[i] = '\\'
			i++
		}
		r[i] = c
		i++
	}
	return r
}

func UnescapeCount(data []byte) (n int) {
	p := byte(0)

	for _, c := range data {
		if p == '\\' && (c == '"' || c == ']') {
			n++
		}
		if p == '\\' && c == '\\' {
			n++
			p = byte(0)
		} else {
			p = c
		}
	}
	return
}

func Unescape(data []byte, n int) []byte {
	if len(data) == 0 || n < 1 {
		return data
	}
	r, i, p := make([]byte, len(data)-n), 0, byte(0)

	for _, c := range data {
		if p == '\\' && (c == '"' || c == ']') {
			i--
		}
		if p == '\\' && c == '\\' {
			i--
			p = byte(0)
		} else {
			p = c
		}
		r[i] = c
		i++
	}
	return r
}

func IsIdent(id string) bool {
	if len(id) == 0 || len(id) > 32 {
		return false
	}
	for _, c := range id {
		if 33 > c || c > 126 || c == '=' || c == ']' || c == '"' {
			return false
		}
	}
	return true
}

func bytesToStr(b *[]byte) string { return *(*string)(unsafe.Pointer(b)) }

const (
	String = -iota
	Nil
	False
	True
	Float
	Int
)

var (
	ErrStructData = errors.New(`invalid structured data`)
)
