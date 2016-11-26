package syslogp

import (
	"bytes"
	"testing"
	"time"
)

func Test_SeverityString(t *testing.T) {
	cases := [...]struct {
		in  uint8
		exp string
	}{
		{EMERG, `EMERG`}, {ALERT, `ALERT`}, {CRIT, `CRIT`}, {ERROR, `ERROR`},
		{WARNING, `WARNING`}, {NOTICE, `NOTICE`}, {INFO, `INFO`}, {DEBUG, `DEBUG`},
	}
	for _, c := range cases {
		out := SeverityString(c.in)
		if c.exp != out {
			t.Errorf("for %d, expected %q, got %q", c.in, c.exp, out)
		}
	}
}

func Test_FacilityString(t *testing.T) {
	cases := [...]struct {
		in  uint8
		exp string
	}{
		{KERN, `KERN`}, {USER, `USER`}, {MAIL, `MAIL`}, {DAEMON, `DAEMON`},
		{AUTH, `AUTH`}, {SYSLOG, `SYSLOG`}, {LPR, `LPR`}, {NEWS, `NEWS`},
		{UUCP, `UUCP`}, {CRON, `CRON`}, {AUTHPRIV, `AUTHPRIV`}, {FTP, `FTP`},
		{NTP, `NTP`}, {AUDITLOG, `AUDITLOG`}, {ALERTLOG, `ALERTLOG`}, {CLOCK, `CLOCK`},
		{LOCAL0, `LOCAL0`}, {LOCAL1, `LOCAL1`}, {LOCAL2, `LOCAL2`}, {LOCAL3, `LOCAL3`},
		{LOCAL4, `LOCAL4`}, {LOCAL5, `LOCAL5`}, {LOCAL6, `LOCAL6`}, {LOCAL7, `LOCAL7`},
	}
	for _, c := range cases {
		out := FacilityString(c.in)
		if c.exp != out {
			t.Errorf("for %d, expected %q, got %q", c.in, c.exp, out)
		}
	}
}

func Test_PriorityString(t *testing.T) {
	cases := [...]struct {
		in  uint8
		exp string
	}{
		{KERN | EMERG, `KERN.EMERG`},
		{USER | ALERT, `USER.ALERT`},
		{MAIL | CRIT, `MAIL.CRIT`},
		{DAEMON | ERROR, `DAEMON.ERROR`},
		{AUTH | WARNING, `AUTH.WARNING`},
		{LPR | NOTICE, `LPR.NOTICE`},
		{NEWS | INFO, `NEWS.INFO`},
		{UUCP | DEBUG, `UUCP.DEBUG`},
	}
	for _, c := range cases {
		out := PriorityString(c.in)
		if c.exp != out {
			t.Errorf("for %d (%d.%d), expected %q, got: %q", c.in, Facility(c.in), Severity(c.in), c.exp, out)
		}
	}
}

func Test_ScanPriority(t *testing.T) {
	cases := [...]struct {
		in  []byte
		exp []byte
		pos int
		err error
	}{
		{[]byte{}, nil, 0, ErrPriority},
		{[]byte(`<>`), nil, 1, ErrPriority},
		{[]byte(`<1`), nil, 2, ErrPriority},
		{[]byte(`<a`), nil, 1, ErrPriority},
		{[]byte(`<191`), nil, 4, ErrPriority},
		{[]byte(`<200>`), nil, 3, ErrPriority},
		{[]byte(`<15>1`), []byte(`15`), 4, nil},
		{[]byte(`<191>2`), []byte(`191`), 5, nil},
	}
	for _, c := range cases {
		pos := 0
		out, err := ScanPriority(c.in, &pos)
		if !bytes.Equal(c.exp, out) || c.pos != pos || c.err != err {
			t.Errorf("\n\tfor: %q, len = %d\n\texp: %q, %d, %v\n\tgot: %q, %d, %v\n",
				c.in, len(c.in), c.exp, c.pos, c.err, out, pos, err)
		}
	}
}

func Test_ParsePriority(t *testing.T) {
	cases := [...]struct {
		in  []byte
		exp uint8
		pos int
		err error
	}{
		{[]byte{}, 0, 0, ErrPriority},
		{[]byte(`<>`), 0, 1, ErrPriority},
		{[]byte(`<1`), 0, 2, ErrPriority},
		{[]byte(`<a`), 0, 1, ErrPriority},
		{[]byte(`<191`), 0, 4, ErrPriority},
		{[]byte(`<200>`), 0, 3, ErrPriority},
		{[]byte(`<15>1`), 15, 4, nil},
		{[]byte(`<191>2`), 191, 5, nil},
	}
	for _, c := range cases {
		pos := 0
		out, err := ParsePriority(c.in, &pos)
		if c.exp != out || c.pos != pos || c.err != err {
			t.Errorf("\n\tfor: %q, len = %d\n\texp: %d, %d, %v\n\tgot: %d, %d, %v\n",
				c.in, len(c.in), c.exp, c.pos, c.err, out, pos, err)
		}
	}
}

func Test_ScanVersion(t *testing.T) {
	cases := [...]struct {
		in    []byte
		exp   []byte
		start int
		end   int
		err   error
	}{
		{[]byte{}, nil, 0, 0, ErrVersion},
		{[]byte(`1`), nil, 0, 1, ErrVersion},
		{[]byte(`abc`), nil, 0, 0, ErrVersion},
		{[]byte(`0 `), nil, 0, 0, ErrVersion},
		{[]byte(`9999 `), nil, 0, 3, ErrVersion},
		{[]byte(`1 `), []byte(`1`), 0, 2, nil},
		{[]byte(`999 `), []byte(`999`), 0, 4, nil},
	}
	for _, c := range cases {
		pos := 0
		out, err := ScanVersion(c.in, &pos)
		if !bytes.Equal(c.exp, out) || c.end != pos || c.err != err {
			t.Errorf("\n\tfor: %q, len = %d\n\texp: %q, %d, %v\n\tgot: %q, %d, %v\n",
				c.in, len(c.in), c.exp, c.end, c.err, out, pos, err)
		}
	}
}

func Test_ParseVersion(t *testing.T) {
	cases := [...]struct {
		in  []byte
		exp uint16
		pos int
		err error
	}{
		{[]byte{}, 0, 0, ErrVersion},
		{[]byte(`1`), 0, 1, ErrVersion},
		{[]byte(`abc`), 0, 0, ErrVersion},
		{[]byte(`0 `), 0, 0, ErrVersion},
		{[]byte(`9999 `), 0, 3, ErrVersion},
		{[]byte(`1 `), 1, 2, nil},
		{[]byte(`999 `), 999, 4, nil},
	}
	for _, c := range cases {
		pos := 0
		out, err := ParseVersion(c.in, &pos)
		if c.exp != out || c.pos != pos || c.err != err {
			t.Errorf("\n\tfor: %q, len = %d\n\texp: %d, %d, %v\n\tgot: %d, %d, %v\n",
				c.in, len(c.in), c.exp, c.pos, c.err, out, pos, err)
		}
	}
}

func Test_scanDate(t *testing.T) {
	cases := [...]struct {
		in  []byte
		pos int
		err error
	}{
		{[]byte{}, 0, ErrTimestamp},
		{[]byte(`1945.05-09`), 4, ErrTimestamp},
		{[]byte(`1945-05.09`), 7, ErrTimestamp},
		{[]byte(`1945-05`), 7, ErrTimestamp},
		{[]byte(`1945-5-09`), 5, ErrTimestamp},
		{[]byte(`1945-05-9`), 8, ErrTimestamp},
		{[]byte(`194-05-09`), 3, ErrTimestamp},
		{[]byte(`1945-25-09`), 5, ErrTimestamp},
		{[]byte(`1945-05-49`), 8, ErrTimestamp},
		{[]byte(`1945-05-39`), 9, ErrTimestamp},
		{[]byte(`1945-05-09`), 10, nil},
	}
	for _, c := range cases {
		pos := 0
		err := scanDate(c.in, &pos)
		if c.pos != pos || c.err != err {
			t.Errorf("\n\tfor: %q, len = %d\n\texp: %d, %v\n\tgot: %d, %v\n",
				c.in, len(c.in), c.pos, c.err, pos, err)
		}
	}
}

func Test_parseDate(t *testing.T) {
	cases := []struct {
		in    []byte
		pos   int
		err   error
		year  int
		month int
		day   int
	}{
		{[]byte{}, 0, ErrTimestamp, 0, 0, 0},
		{[]byte(`1-05-09`), 1, ErrTimestamp, 1, 0, 0},
		{[]byte(`194-05-09`), 3, ErrTimestamp, 194, 0, 0},
		{[]byte(`1945-25-09`), 5, ErrTimestamp, 1945, 0, 0},
		{[]byte(`1945-15-09`), 6, ErrTimestamp, 1945, 1, 0},
		{[]byte(`1945-05-49`), 8, ErrTimestamp, 1945, 5, 0},
		{[]byte(`1945-05-33`), 9, ErrTimestamp, 1945, 5, 3},
		{[]byte(`1945-05-09`), 10, nil, 1945, 5, 9},
		{[]byte(`2007-12-31`), 10, nil, 2007, 12, 31},
	}
	for _, c := range cases {
		pos, year, month, day := 0, 0, 0, 0
		err := parseDate(c.in, &pos, &year, &month, &day)
		if c.year != year || c.month != month || c.day != day || c.pos != pos || c.err != err {
			t.Errorf("\n\tfor: %q, len = %d\n\texp: %d-%d-%d, %d, %v\n\tgot: %d-%d-%d, %d, %v\n",
				c.in, len(c.in), c.year, c.month, c.day, c.pos, c.err, year, month, day, pos, err)
		}
	}
}

func Test_scanTime(t *testing.T) {
	cases := [...]struct {
		in  []byte
		pos int
		err error
	}{
		{[]byte{}, 0, ErrTimestamp},
		{[]byte(`00:00:00`), 0, ErrTimestamp},
		{[]byte(`T0:00:00`), 2, ErrTimestamp},
		{[]byte(`T30:00:00`), 1, ErrTimestamp},
		{[]byte(`T24:00:00`), 2, ErrTimestamp},
		{[]byte(`T00:0:00`), 5, ErrTimestamp},
		{[]byte(`T00:60:00`), 4, ErrTimestamp},
		{[]byte(`T00:00:0`), 8, ErrTimestamp},
		{[]byte(`T00:00:60`), 7, ErrTimestamp},
		{[]byte(`T23.00:00`), 3, ErrTimestamp},
		{[]byte(`T00:59.00`), 6, ErrTimestamp},
		{[]byte(`T00:00:00`), 9, nil},
		{[]byte(`T05:05:05`), 9, nil},
		{[]byte(`T10:30:30`), 9, nil},
		{[]byte(`T00:00:00.`), 10, ErrTimestamp},
		{[]byte(`T00:00:00+`), 9, nil},
		{[]byte(`T00:00:00.1`), 11, nil},
		{[]byte(`T00:00:00.000001`), 16, nil},
		{[]byte(`T00:00:00.0000001`), 16, nil},
	}
	for _, c := range cases {
		pos := 0
		err := scanTime(c.in, &pos)
		if c.pos != pos || c.err != err {
			t.Errorf("\n\tfor: %q, len = %d\n\texp: %d, %v\n\tgot: %d, %v\n",
				c.in, len(c.in), c.pos, c.err, pos, err)
		}
	}
}

func Test_parseTime(t *testing.T) {
	cases := [...]struct {
		in     []byte
		pos    int
		err    error
		hour   int
		minute int
		sec    int
		nsec   int
	}{
		{[]byte{}, 0, ErrTimestamp, 0, 0, 0, 0},
		{[]byte(`00:00:00`), 0, ErrTimestamp, 0, 0, 0, 0},
		{[]byte(`T0:00:00`), 2, ErrTimestamp, 0, 0, 0, 0},
		{[]byte(`T30:00:00`), 1, ErrTimestamp, 0, 0, 0, 0},
		{[]byte(`T24:00:00`), 2, ErrTimestamp, 2, 0, 0, 0},
		{[]byte(`T00:0:00`), 5, ErrTimestamp, 0, 0, 0, 0},
		{[]byte(`T00:60:00`), 4, ErrTimestamp, 0, 0, 0, 0},
		{[]byte(`T00:00:0`), 8, ErrTimestamp, 0, 0, 0, 0},
		{[]byte(`T00:00:60`), 7, ErrTimestamp, 0, 0, 0, 0},
		{[]byte(`T23.00:00`), 3, ErrTimestamp, 23, 0, 0, 0},
		{[]byte(`T00:59.00`), 6, ErrTimestamp, 0, 59, 0, 0},
		{[]byte(`T00:00:00`), 9, nil, 0, 0, 0, 0},
		{[]byte(`T05:05:05`), 9, nil, 5, 5, 5, 0},
		{[]byte(`T10:30:50`), 9, nil, 10, 30, 50, 0},
		{[]byte(`T00:00:00+`), 9, nil, 0, 0, 0, 0},
		{[]byte(`T00:00:00.`), 10, ErrTimestamp, 0, 0, 0, 0},
		{[]byte(`T00:00:00.1`), 11, nil, 0, 0, 0, 1e8},
		{[]byte(`T00:00:00.0001`), 14, nil, 0, 0, 0, 1e5},
		{[]byte(`T00:00:00.000001`), 16, nil, 0, 0, 0, 1000},
	}
	for _, c := range cases {
		pos, hour, minute, sec, nsec := 0, 0, 0, 0, 0
		err := parseTime(c.in, &pos, &hour, &minute, &sec, &nsec)
		if c.hour != hour || c.minute != minute || c.sec != sec || c.nsec != nsec || c.pos != pos || c.err != err {
			t.Errorf("\n\tfor: %q, len = %d\n\texp: %d:%d:%d.%d, %d, %v\n\tgot: %d:%d:%d.%d, %d, %v\n",
				c.in, len(c.in), c.hour, c.minute, c.sec, c.nsec, c.pos, c.err, hour, minute, sec, nsec, pos, err)
		}
	}
}

func Test_scanTZ(t *testing.T) {
	cases := [...]struct {
		in  []byte
		pos int
		err error
	}{
		{[]byte{}, 0, ErrTimestamp},
		{[]byte(`Z`), 1, ErrTimestamp},
		{[]byte(`Z `), 2, nil},
		{[]byte(`+30:05`), 1, ErrTimestamp},
		{[]byte(`+03.05`), 3, ErrTimestamp},
		{[]byte(`+03:60`), 4, ErrTimestamp},
		{[]byte(`+03:05`), 6, ErrTimestamp},
		{[]byte(`+03:05 `), 7, nil},
		{[]byte(`-13:15 `), 7, nil},
	}
	for _, c := range cases {
		pos := 0
		err := scanTZ(c.in, &pos)
		if c.pos != pos || c.err != err {
			t.Errorf("\n\tfor: %q, len = %d\n\texp: %d, %v\n\tgot: %d, %v\n",
				c.in, len(c.in), c.pos, c.err, pos, err)
		}
	}
}

func Test_parseTZ(t *testing.T) {
	cases := [...]struct {
		in     []byte
		offset int
		pos    int
		err    error
	}{
		{[]byte{}, 0, 0, ErrTimestamp},
		{[]byte(`Z`), 0, 1, ErrTimestamp},
		{[]byte(`Z `), 0, 2, nil},
		{[]byte(`+30:05`), 0, 1, ErrTimestamp},
		{[]byte(`+03.05`), 0, 3, ErrTimestamp},
		{[]byte(`+03:60`), 0, 4, ErrTimestamp},
		{[]byte(`+03:05`), 0, 6, ErrTimestamp},
		{[]byte(`+03:00 `), 3 * 3600, 7, nil},
		{[]byte(`+03:05 `), 3*3600 + 5*60, 7, nil},
		{[]byte(`-13:15 `), -(13*3600 + 15*60), 7, nil},
	}
	for _, c := range cases {
		pos, offset := 0, 0
		err := parseTZ(c.in, &pos, &offset)
		if c.offset != offset || c.pos != pos || c.err != err {
			t.Errorf("\n\tfor: %q, len = %d\n\texp: %d, %d, %v\n\tgot: %d, %d, %v\n",
				c.in, len(c.in), c.offset, c.pos, c.err, offset, pos, err)
		}
	}
}

func Test_ScanTimestamp(t *testing.T) {
	cases := [...]struct {
		in  []byte
		exp []byte
		pos int
		err error
	}{
		{[]byte(``), nil, 0, ErrTimestamp},
		{[]byte(`-`), nil, 0, ErrTimestamp},
		{[]byte(`- `), nil, 2, nil},
		{[]byte(`2009-11-19`), nil, 10, ErrTimestamp},
		{[]byte(`2009-11-19T05:13:47`), nil, 19, ErrTimestamp},
		{[]byte(`2009-11-19T05:13:47Z`), nil, 20, ErrTimestamp},
		{[]byte(`2009X11-19T05:13:47Z `), nil, 4, ErrTimestamp},
		{[]byte(`2009-11-19T05:13X47Z `), nil, 16, ErrTimestamp},
		{[]byte(`2009-11-19T05:13:47.`), nil, 20, ErrTimestamp},
		{[]byte(`2009-11-19T05:13:47.1234567Z `), nil, 26, ErrTimestamp},
		{[]byte(`2009-11-19T05:13:47+`), nil, 20, ErrTimestamp},
		{[]byte(`2009-11-19T05:13:47+03`), nil, 22, ErrTimestamp},
		{[]byte(`2009-11-19T05:13:47/03:00`), nil, 19, ErrTimestamp},
		{[]byte(`2009-11-19T05:13:47+03:00`), nil, 25, ErrTimestamp},
		{[]byte(`2009-11-19T05:13:47+03X00 `), nil, 22, ErrTimestamp},
		{[]byte(`2009-11-19T05:13:47Z `), []byte(`2009-11-19T05:13:47Z`), 21, nil},
		{[]byte(`2009-11-19T05:13:47.1Z `), []byte(`2009-11-19T05:13:47.1Z`), 23, nil},
		{[]byte(`2009-11-19T05:13:47.000001Z `), []byte(`2009-11-19T05:13:47.000001Z`), 28, nil},
		{[]byte(`2009-11-19T05:13:47+03:00 `), []byte(`2009-11-19T05:13:47+03:00`), 26, nil},
		{[]byte(`2009-11-19T05:13:47-03:00 `), []byte(`2009-11-19T05:13:47-03:00`), 26, nil},
		{[]byte(`2009-11-19T05:13:47.1+04:00 `), []byte(`2009-11-19T05:13:47.1+04:00`), 28, nil},
		{[]byte(`2009-11-19T05:13:47.01+04:30 localhost`), []byte(`2009-11-19T05:13:47.01+04:30`), 29, nil},
	}
	for _, c := range cases {
		pos := 0
		out, err := ScanTimestamp(c.in, &pos)
		if !bytes.Equal(c.exp, out) || c.pos != pos || c.err != err {
			t.Errorf("\n\tfor: %q, len = %d\n\texp: %q, %d, %v\n\tgot: %q, %d, %v\n",
				c.in, len(c.in), c.exp, c.pos, c.err, out, pos, err)
		}
	}
}

func Test_ParseTimestamp(t *testing.T) {
	empty := time.Time{}
	cases := [...]struct {
		in  []byte
		exp time.Time
		pos int
		err error
	}{
		{[]byte(``), empty, 0, ErrTimestamp},
		{[]byte(`-`), empty, 0, ErrTimestamp},
		{[]byte(`- `), empty, 2, nil},
		{[]byte(`2009-11-19`), empty, 10, ErrTimestamp},
		{[]byte(`2009-11-19T05:13:47`), empty, 19, ErrTimestamp},
		{[]byte(`2009-11-19T05:13:47Z`), empty, 20, ErrTimestamp},
		{[]byte(`2009X11-19T05:13:47Z `), empty, 4, ErrTimestamp},
		{[]byte(`2009-11-19T05:13X47Z `), empty, 16, ErrTimestamp},
		{[]byte(`2009-11-19T05:13:47.`), empty, 20, ErrTimestamp},
		{[]byte(`2009-11-19T05:13:47.1234567Z `), empty, 26, ErrTimestamp},
		{[]byte(`2009-11-19T05:13:47+`), empty, 20, ErrTimestamp},
		{[]byte(`2009-11-19T05:13:47+03`), empty, 22, ErrTimestamp},
		{[]byte(`2009-11-19T05:13:47/03:00`), empty, 19, ErrTimestamp},
		{[]byte(`2009-11-19T05:13:47+03:00`), empty, 25, ErrTimestamp},
		{[]byte(`2009-11-19T05:13:47+03X00 `), empty, 22, ErrTimestamp},
		{[]byte(`2009-11-19T05:13:47Z `), time.Date(2009, 11, 19, 5, 13, 47, 0, time.UTC), 21, nil},
		{[]byte(`2009-11-19T05:13:47.1Z `), time.Date(2009, 11, 19, 5, 13, 47, 1e8, time.UTC), 23, nil},
		{[]byte(`2009-11-19T05:13:47.000001Z `), time.Date(2009, 11, 19, 5, 13, 47, 1e3, time.UTC), 28, nil},
		{
			[]byte(`2009-11-19T05:13:47+03:00 `),
			time.Date(2009, 11, 19, 5, 13, 47, 0, time.FixedZone(``, 3*3600)),
			26, nil,
		},
		{
			[]byte(`2009-11-19T05:13:47-03:00 `),
			time.Date(2009, 11, 19, 5, 13, 47, 0, time.FixedZone(``, -3*3600)),
			26, nil,
		},
		{
			[]byte(`2009-11-19T05:13:47.1+04:00 `),
			time.Date(2009, 11, 19, 5, 13, 47, 1e8, time.FixedZone(``, 4*3600)),
			28, nil,
		},
		{
			[]byte(`2009-11-19T05:13:47.01+04:30 localhost`),
			time.Date(2009, 11, 19, 5, 13, 47, 1e7, time.FixedZone(``, 4*3600+30*60)),
			29, nil,
		},
	}
	for _, c := range cases {
		pos := 0
		out, err := ParseTimestamp(c.in, &pos)
		if !c.exp.Equal(out) || c.pos != pos || c.err != err {
			t.Errorf("\n\tfor: %q, len = %d\n\texp: %q, %d, %v\n\tgot: %q, %d, %v\n",
				c.in, len(c.in), c.exp, c.pos, c.err, out, pos, err)
		}
	}
}

func Test_ScanMsgId(t *testing.T) {
	cases := [...]struct {
		in  []byte
		exp []byte
		pos int
		err error
	}{
		{[]byte{}, nil, 0, ErrMsgId},
		{[]byte(`-`), nil, 1, ErrMsgId},
		{[]byte(`- `), nil, 2, nil},
		{[]byte(`abcd`), nil, 4, ErrMsgId},
		{[]byte(` abcd`), nil, 0, ErrMsgId},
		{[]byte{'a', 'b', 0, 'c'}, nil, 2, ErrMsgId},
		{[]byte(`0123456789abcdef0123456789abcdef`), nil, 32, ErrMsgId},
		{[]byte(`0123456789abcdef0123456789abcdefX `), nil, 32, ErrMsgId},
		{[]byte(`0123456789abcdef0123456789abcdef `), []byte(`0123456789abcdef0123456789abcdef`), 33, nil},
		{[]byte(`ab cd`), []byte(`ab`), 3, nil},
		{[]byte(`abcd `), []byte(`abcd`), 5, nil},
	}
	for _, c := range cases {
		pos := 0
		out, err := ScanMsgId(c.in, &pos)
		if !bytes.Equal(c.exp, out) || c.pos != pos || c.err != err {
			t.Errorf("\n\tfor: %q, len = %d\n\texp: %q, %d, %v\n\tgot: %q, %d, %v\n",
				c.in, len(c.in), c.exp, c.pos, c.err, out, pos, err)
		}
	}
}
