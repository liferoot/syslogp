package syslogp

import (
	"bytes"
	"reflect"
	"testing"
)

func Test_EscapeCount(t *testing.T) {
	cases := [...]struct {
		in  []byte
		exp int
	}{
		{nil, 0},
		{[]byte{}, 0},
		{[]byte(`simple`), 0},
		{[]byte(`double"quote`), 1},
		{[]byte(`two "double quotes"`), 2},
		{[]byte(`back\slash`), 1},
		{[]byte(`three\\\backslash`), 3},
		{[]byte(`[right]bracket`), 1},
		{[]byte(`four [right]bracket]]]`), 4},
	}
	for _, c := range cases {
		out := EscapeCount(c.in)
		if c.exp != out {
			t.Errorf("\n\tfor: %s\n\texp: %d\n\tgot: %d\n", c.in, c.exp, out)
		}
	}
}

func Test_Escape(t *testing.T) {
	cases := [...]struct {
		in  []byte
		exp []byte
	}{
		{nil, nil},
		{[]byte{}, []byte{}},
		{[]byte(`simple`), []byte(`simple`)},
		{[]byte(`double"quote`), []byte(`double\"quote`)},
		{[]byte(`two "double quotes"`), []byte(`two \"double quotes\"`)},
		{[]byte(`back\slash`), []byte(`back\\slash`)},
		{[]byte(`three\\\backslash`), []byte(`three\\\\\\backslash`)},
		{[]byte(`[right]bracket`), []byte(`[right\]bracket`)},
		{[]byte(`four [right]bracket]]]`), []byte(`four [right\]bracket\]\]\]`)},
	}
	for _, c := range cases {
		out := Escape(c.in, EscapeCount(c.in))
		if !bytes.Equal(c.exp, out) {
			t.Errorf("\n\tfor: %s\n\texp: %s\n\tgot: %s\n", c.in, c.exp, out)
		}
	}
}

func Test_UnescapeCount(t *testing.T) {
	cases := [...]struct {
		in  []byte
		exp int
	}{
		{nil, 0},
		{[]byte{}, 0},
		{[]byte(`simple`), 0},
		{[]byte(`double\"quote`), 1},
		{[]byte(`two \"double quotes\"`), 2},
		{[]byte(`back\\slash`), 1},
		{[]byte(`three\\\\\\backslash`), 3},
		{[]byte(`[right\]bracket`), 1},
		{[]byte(`four [right\]bracket\]\]\]`), 4},
	}
	for _, c := range cases {
		out := UnescapeCount(c.in)
		if c.exp != out {
			t.Errorf("\n\tfor: %s\n\texp: %d\n\tgot: %d\n", c.in, c.exp, out)
		}
	}
}

func Test_Unescape(t *testing.T) {
	cases := [...]struct {
		in  []byte
		exp []byte
	}{
		{nil, nil},
		{[]byte{}, []byte{}},
		{[]byte(`simple`), []byte(`simple`)},
		{[]byte(`double\"quote`), []byte(`double"quote`)},
		{[]byte(`double"quote w/o escapes`), []byte(`double"quote w/o escapes`)},
		{[]byte(`two \"double quotes\"`), []byte(`two "double quotes"`)},
		{[]byte(`back\\slash`), []byte(`back\slash`)},
		{[]byte(`three\\\\\\backslash`), []byte(`three\\\backslash`)},
		{[]byte(`[right\]bracket`), []byte(`[right]bracket`)},
		{[]byte(`four [right\]bracket\]\]\]`), []byte(`four [right]bracket]]]`)},
		{[]byte(`\\\\\\\"\]`), []byte(`\\\"]`)},
	}
	for _, c := range cases {
		out := Unescape(c.in, UnescapeCount(c.in))
		if !bytes.Equal(c.exp, out) {
			t.Errorf("\n\tfor: %s\n\texp: %s\n\tgot: %s\n", c.in, c.exp, out)
		}
	}
}

func Test_IsIdent(t *testing.T) {
	cases := [...]struct {
		in  string
		exp bool
	}{
		{``, false},
		{`0123456789abcdef0123456789abcdefX`, false},
		{`invalid ident`, false},
		{`invalid[ident]`, false},
		{`reserved`, true},
		{`ourSDID@32473`, true},
	}
	for _, c := range cases {
		out := IsIdent(c.in)
		if c.exp != out {
			t.Errorf("\n\tfor: %s\n\texp: %t\n\tgot: %t\n", c.in, c.exp, out)
		}
	}
}

func Test_ParseValue(t *testing.T) {
	cases := [...]struct {
		in  []byte
		typ ValueType
		exp interface{}
	}{
		{[]byte(`null`), Nil, nil},
		{[]byte(`false`), False, false},
		{[]byte(`true`), True, true},
		{[]byte(`-1.618033988`), Float, -1.618033988},
		{[]byte(`+2.718281828`), Float, 2.718281828},
		{[]byte(`3.141592653`), Float, 3.141592653},
		{[]byte(`1.401298464e-5`), Float, 1.401298464e-5},
		{[]byte(`-64`), Int, int64(-64)},
		{[]byte(`+256`), Int, int64(256)},
		{[]byte(`1234567890123456789`), Int, int64(1234567890123456789)},
		{[]byte(`12345678901234567890`), String, `12345678901234567890`},
		{[]byte{}, String, ``},
		{[]byte(`simple`), String, `simple`},
		{[]byte(`two \"double quotes\"`), 2, `two "double quotes"`},
		{[]byte(`three\\\\\\backslash`), 3, `three\\\backslash`},
	}
	for _, c := range cases {
		out := ParseValue(c.in, c.typ)
		if c.exp == out {
			t.Errorf("\n\tfor: %v %s(%s)\n\texp: %T(%v)\n\tgot: %T(%v)\n", c.in, c.typ, c.in, c.exp, c.exp, out, out)
		}
	}
}

func Test_ParseStructData(t *testing.T) {
	empty := make(map[string]interface{})
	cases := [...]struct {
		in  []byte
		exp map[string]interface{}
		pos int
		err error
	}{
		{nil, empty, 0, ErrStructData},
		{[]byte{}, empty, 0, ErrStructData},
		{[]byte(`-`), empty, 0, ErrStructData},
		{[]byte(`- `), empty, 2, nil},
		{[]byte(`[id1]`), map[string]interface{}{`id1`: empty}, 5, ErrStructData},
		{[]byte(`[id1] `), map[string]interface{}{`id1`: empty}, 6, nil},
		{[]byte(`[id1][id2][id3] `), map[string]interface{}{`id1`: empty, `id2`: empty, `id3`: empty}, 16, nil},
		{
			[]byte(`[id1 param1="true" param2="false" param3="null"] `),
			map[string]interface{}{`id1`: map[string]interface{}{`param1`: true, `param2`: false, `param3`: nil}},
			49, nil,
		},
		{
			[]byte(`[id1 param1="3.14" param2="314E-2" param3="314e+3"] `),
			map[string]interface{}{`id1`: map[string]interface{}{`param1`: 3.14, `param2`: 3.14, `param3`: float64(314000)}},
			52, nil,
		},
		{
			[]byte(`[id1 param1="+2.71828" param2="-271828e-5"] `),
			map[string]interface{}{`id1`: map[string]interface{}{`param1`: 2.71828, `param2`: -2.71828}},
			44, nil,
		},
		{
			[]byte(`[id1 param1="1" param2="+1" param3="-1"] `),
			map[string]interface{}{`id1`: map[string]interface{}{`param1`: int64(1), `param2`: int64(1), `param3`: int64(-1)}},
			41, nil,
		},
		{
			[]byte(`[id1 param1="9223372036854775807" param2="-9223372036854775808"] `),
			map[string]interface{}{`id1`: map[string]interface{}{`param1`: int64(9223372036854775807), `param2`: int64(-9223372036854775808)}},
			65, nil,
		},
		{
			[]byte(`[id1 param1="92233720368547758070" param2=""] `),
			map[string]interface{}{`id1`: map[string]interface{}{`param1`: `92233720368547758070`, `param2`: ``}},
			46, nil,
		},
		{
			[]byte(`[id1 param1="word" param2="two words"] `),
			map[string]interface{}{`id1`: map[string]interface{}{`param1`: `word`, `param2`: `two words`}},
			39, nil,
		},
		{
			[]byte(`[id1 param1="two \"double quotes\"" param2="three\\\\\\backslash"] `),
			map[string]interface{}{`id1`: map[string]interface{}{`param1`: `two "double quotes"`, `param2`: `three\\\backslash`}},
			67, nil,
		},
	}
	for _, c := range cases {
		pos, out := 0, make(map[string]interface{})
		err := ParseStructData(c.in, &pos, out)
		if !reflect.DeepEqual(c.exp, out) || c.pos != pos || c.err != err {
			t.Errorf("\n\tfor: %s, len = %d\n\texp: %v, %d, %v\n\tgot: %v, %d, %v\n",
				c.in, len(c.in), c.exp, c.pos, c.err, out, pos, err)
		}
	}
}
