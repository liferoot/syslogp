package syslogp

import (
	"errors"
	"time"
)

func Severity(pri uint8) uint8 { return pri & 0x07 }
func Facility(pri uint8) uint8 { return pri & 0xf8 }

func SeverityString(pri uint8) string {
	return severity[int(Severity(pri))]
}

func FacilityString(pri uint8) string {
	i := int(Facility(pri) >> 3)
	if i >= len(facility) {
		i = 0
	}
	return facility[i]
}

func PriorityString(pri uint8) string {
	buf := [16]byte{}
	i := copy(buf[0:], FacilityString(pri))
	buf[i], i = '.', i+1
	i += copy(buf[i:], SeverityString(pri))

	return string(buf[:i])
}

// ([0-9] | [1-9][0-9] | [1][0-8][0-9] | [1][9][01])
func ScanPriority(data []byte, pos *int) ([]byte, error) {
	var (
		c     byte
		state uint8
		eof   = len(data)
	)
	if eof == 0 || eof <= *pos {
		goto _err
	}
_resume:
	switch c = data[*pos]; state {
	case 0:
		if c == '<' {
			state = 1
			goto _next
		}
		goto _err
	case 1:
		switch c {
		case '0':
			state = 2
			goto _next
		case '1':
			state = 3
			goto _next
		}
		if '2' <= c && c <= '9' {
			state = 4
			goto _next
		}
		goto _err
	case 2:
		if c == '>' {
			state = 6
			goto _next
		}
		goto _err
	case 6:
		goto _out
	case 3:
		switch c {
		case '9':
			state = 5
			goto _next
		case '>':
			state = 6
			goto _next
		}
		if '0' <= c && c <= '8' {
			state = 4
			goto _next
		}
		goto _err
	case 4:
		if c == '>' {
			state = 6
			goto _next
		}
		if '0' <= c && c <= '9' {
			state = 2
			goto _next
		}
		goto _err
	case 5:
		if c == '>' {
			state = 6
			goto _next
		}
		if c == '0' || c == '1' {
			state = 2
			goto _next
		}
		goto _err
	}
_next:
	if *pos++; *pos != eof {
		goto _resume
	}
_out:
	if state < 6 {
		goto _err
	}
	return data[1 : *pos-1], nil
_err:
	return nil, ErrPriority
}

// ([0-9] | [1-9][0-9] | [1][0-8][0-9] | [1][9][01])
func ParsePriority(data []byte, pos *int) (uint8, error) {
	var (
		c     byte
		state uint8
		eof   = len(data)
		pri   uint8
	)
	if eof == 0 || eof <= *pos {
		goto _err
	}
_resume:
	switch c = data[*pos]; state {
	case 0:
		if c == '<' {
			state = 1
			goto _next
		}
		goto _err
	case 1:
		switch c {
		case '0':
			state = 2
			goto _next
		case '1':
			state = 3
			pri = 1
			goto _next
		}
		if '2' <= c && c <= '9' {
			state = 4
			goto _pri
		}
		goto _err
	case 2:
		if c == '>' {
			state = 6
			goto _next
		}
		goto _err
	case 6:
		goto _out
	case 3:
		switch c {
		case '9':
			state = 5
			goto _pri
		case '>':
			state = 6
			goto _next
		}
		if '0' <= c && c <= '8' {
			state = 4
			goto _pri
		}
		goto _err
	case 4:
		if c == '>' {
			state = 6
			goto _next
		}
		if '0' <= c && c <= '9' {
			state = 2
			goto _pri
		}
		goto _err
	case 5:
		if c == '>' {
			state = 6
			goto _next
		}
		if c == '0' || c == '1' {
			state = 2
			goto _pri
		}
		goto _err
	}
_pri:
	pri *= 10
	pri += uint8(c - '0')
_next:
	if *pos++; *pos != eof {
		goto _resume
	}
_out:
	if state < 6 {
		goto _err
	}
	return pri, nil
_err:
	return 0, ErrPriority
}

// [1-9][0-9]{,2}
func ScanVersion(data []byte, pos *int) ([]byte, error) {
	var (
		c     byte
		state uint8
		eof   = len(data)
		p     = *pos
	)
	if eof == 0 || eof <= *pos {
		goto _err
	}
_resume:
	switch c = data[*pos]; state {
	case 0:
		if '1' <= c && c <= '9' {
			state = 1
			goto _next
		}
		goto _err
	case 1, 2:
		if c == ' ' {
			state = 4
			goto _next
		}
		if '0' <= c && c <= '9' {
			state++
			goto _next
		}
		goto _err
	case 4:
		goto _out
	case 3:
		if c == ' ' {
			state = 4
			goto _next
		}
		goto _err
	}
_next:
	if *pos++; *pos != eof {
		goto _resume
	}
_out:
	if state < 4 {
		goto _err
	}
	return data[p : *pos-1], nil
_err:
	return nil, ErrVersion
}

// [1-9][0-9]{,2}
func ParseVersion(data []byte, pos *int) (uint16, error) {
	var (
		c     byte
		state uint8
		eof   = len(data)
		ver   uint16
	)
	if eof == 0 || eof <= *pos {
		goto _err
	}
_resume:
	switch c = data[*pos]; state {
	case 0:
		if '1' <= c && c <= '9' {
			state = 1
			goto _ver
		}
		goto _err
	case 1, 2:
		if c == ' ' {
			state = 4
			goto _next
		}
		if '0' <= c && c <= '9' {
			state++
			goto _ver
		}
		goto _err
	case 4:
		goto _out
	case 3:
		if c == ' ' {
			state = 4
			goto _next
		}
		goto _err
	}
_ver:
	ver *= 10
	ver += uint16(c - '0')
_next:
	if *pos++; *pos != eof {
		goto _resume
	}
_out:
	if state < 4 {
		goto _err
	}
	return ver, nil
_err:
	return 0, ErrVersion
}

func ScanTimestamp(data []byte, pos *int) (res []byte, err error) {
	if err = ErrTimestamp; len(data) > *pos {
		if len(data[*pos:]) > 1 && data[*pos] == '-' && data[*pos+1] == ' ' {
			*pos += 2
			return res, nil
		}
		if err = scanDate(data, pos); err == nil {
			if err = scanTime(data, pos); err == nil {
				if err = scanTZ(data, pos); err == nil {
					res = data[:*pos-1]
				}
			}
		}
	}
	return
}

func ParseTimestamp(data []byte, pos *int) (res time.Time, err error) {
	var year, month, day, hour, minute, sec, nsec, offset int

	if err = ErrTimestamp; len(data) > *pos {
		if len(data[*pos:]) > 1 && data[*pos] == '-' && data[*pos+1] == ' ' {
			*pos += 2
			return res, nil
		}
		if err = parseDate(data, pos, &year, &month, &day); err == nil {
			if err = parseTime(data, pos, &hour, &minute, &sec, &nsec); err == nil {
				if err = parseTZ(data, pos, &offset); err == nil {
					if offset == 0 {
						res = time.Date(
							year, time.Month(month), day,
							hour, minute, sec, nsec,
							time.UTC,
						)
					} else {
						res = time.Date(
							year, time.Month(month), day,
							hour, minute, sec, nsec,
							time.FixedZone(``, offset),
						)
					}
				}
			}
		}
	}
	return
}

// [0-9]{4} '-' ([0][1-9] | [1][012]) '-' ([0][1-9] | [12][0-9] | [3][01])
func scanDate(data []byte, pos *int) error {
	var (
		c     byte
		state uint8
		eof   = len(data)
	)
	if eof == 0 || eof <= *pos {
		goto _err
	}
_resume:
	switch c = data[*pos]; state {
	case 0, 1, 2, 3:
		if '0' <= c && c <= '9' {
			state++
			goto _next
		}
		goto _err
	case 4, 7:
		if c == '-' {
			state++
			goto _next
		}
		goto _err
	case 5:
		switch c {
		case '0':
			state = 6
			goto _next
		case '1':
			state = 12
			goto _next
		}
		goto _err
	case 6:
		if '1' <= c && c <= '9' {
			state = 7
			goto _next
		}
		goto _err
	case 8:
		switch c {
		case '0':
			state = 9
			goto _next
		case '3':
			state = 11
			goto _next
		}
		if c == '1' || c == '2' {
			state = 10
			goto _next
		}
		goto _err
	case 9:
		if '1' <= c && c <= '9' {
			state = 13
			goto _next
		}
		goto _err
	case 13:
		goto _out
	case 10:
		if '0' <= c && c <= '9' {
			state = 13
			goto _next
		}
		goto _err
	case 11:
		if c == '0' || c == '1' {
			state = 13
			goto _next
		}
		goto _err
	case 12:
		if '0' <= c && c <= '2' {
			state = 7
			goto _next
		}
		goto _err
	}
_next:
	if *pos++; *pos != eof {
		goto _resume
	}
_out:
	if state < 13 {
		goto _err
	}
	return nil
_err:
	return ErrTimestamp
}

// [0-9]{4} '-' ([0][1-9] | [1][012]) '-' ([0][1-9] | [12][0-9] | [3][01])
func parseDate(data []byte, pos, year, month, day *int) error {
	var (
		c     byte
		state uint8
		eof   = len(data)
	)
	if eof == 0 || eof <= *pos {
		goto _err
	}
_resume:
	switch c = data[*pos]; state {
	case 0, 1, 2, 3:
		if '0' <= c && c <= '9' {
			state++
			goto _year
		}
		goto _err
	case 4, 7:
		if c == '-' {
			state++
			goto _next
		}
		goto _err
	case 5:
		switch c {
		case '0':
			state = 6
			goto _month
		case '1':
			state = 12
			goto _month
		}
		goto _err
	case 6:
		if '1' <= c && c <= '9' {
			state = 7
			goto _month
		}
		goto _err
	case 8:
		switch c {
		case '0':
			state = 9
			goto _day
		case '3':
			state = 11
			goto _day
		}
		if c == '1' || c == '2' {
			state = 10
			goto _day
		}
		goto _err
	case 9:
		if '1' <= c && c <= '9' {
			state = 13
			goto _day
		}
		goto _err
	case 13:
		goto _out
	case 10:
		if '0' <= c && c <= '9' {
			state = 13
			goto _day
		}
		goto _err
	case 11:
		if c == '0' || c == '1' {
			state = 13
			goto _day
		}
		goto _err
	case 12:
		if '0' <= c && c <= '2' {
			state = 7
			goto _month
		}
		goto _err
	}
_day:
	*day *= 10
	*day += int(c - '0')
	goto _next
_month:
	*month *= 10
	*month += int(c - '0')
	goto _next
_year:
	*year *= 10
	*year += int(c - '0')
_next:
	if *pos++; *pos != eof {
		goto _resume
	}
_out:
	if state < 13 {
		goto _err
	}
	return nil
_err:
	return ErrTimestamp
}

// 'T' ([01][0-9] | [2][0-3]) ':' [0-5][0-9] ':' [0-5][0-9] ('.' [0-9]{1,6})?
func scanTime(data []byte, pos *int) error {
	var (
		c     byte
		state uint8
		eof   = len(data)
	)
	if eof == 0 || eof <= *pos {
		goto _err
	}
_resume:
	switch c = data[*pos]; state {
	case 0:
		if c == 'T' {
			state = 1
			goto _next
		}
		goto _err
	case 1:
		if c == '2' {
			state = 10
			goto _next
		}
		if c == '0' || c == '1' {
			state = 2
			goto _next
		}
		goto _err
	case 2, 5:
		if '0' <= c && c <= '9' {
			state++
			goto _next
		}
		goto _err
	case 10:
		if '0' <= c && c <= '3' {
			state = 3
			goto _next
		}
		goto _err
	case 3, 6:
		if c == ':' {
			state++
			goto _next
		}
		goto _err
	case 4, 7:
		if '0' <= c && c <= '5' {
			state++
			goto _next
		}
		goto _err
	case 8:
		if '0' <= c && c <= '9' {
			state = 11
			goto _next
		}
		goto _err
	case 11:
		if c == '.' {
			state = 9
			goto _next
		}
		goto _out
	case 9:
		if '0' <= c && c <= '9' {
			state = 12
			goto _next
		}
		goto _err
	case 12, 13, 14, 15, 16:
		if '0' <= c && c <= '9' {
			state++
			goto _next
		}
		goto _out
	case 17:
		goto _out
	}
_next:
	if *pos++; *pos != eof {
		goto _resume
	}
_out:
	if state < 10 {
		goto _err
	}
	return nil
_err:
	return ErrTimestamp
}

// 'T' ([01][0-9] | [2][0-3]) ':' [0-5][0-9] ':' [0-5][0-9] ('.' [0-9]{1,6})?
func parseTime(data []byte, pos, hour, minute, sec, nsec *int) error {
	var (
		c     byte
		state uint8
		eof   = len(data)
		x     = int(1e9)
	)
	if eof == 0 || eof <= *pos {
		goto _err
	}
_resume:
	switch c = data[*pos]; state {
	case 0:
		if c == 'T' {
			state = 1
			goto _next
		}
		goto _err
	case 1:
		if c == '2' {
			state = 10
			goto _hour
		}
		if c == '0' || c == '1' {
			state = 2
			goto _hour
		}
		goto _err
	case 2:
		if '0' <= c && c <= '9' {
			state = 3
			goto _hour
		}
		goto _err
	case 10:
		if '0' <= c && c <= '3' {
			state = 3
			goto _hour
		}
		goto _err
	case 3, 6:
		if c == ':' {
			state++
			goto _next
		}
		goto _err
	case 4:
		if '0' <= c && c <= '5' {
			state = 5
			goto _minute
		}
		goto _err
	case 5:
		if '0' <= c && c <= '9' {
			state = 6
			goto _minute
		}
		goto _err
	case 7:
		if '0' <= c && c <= '5' {
			state = 8
			goto _sec
		}
		goto _err
	case 8:
		if '0' <= c && c <= '9' {
			state = 11
			goto _sec
		}
		goto _err
	case 11:
		if c == '.' {
			state = 9
			goto _next
		}
		goto _out
	case 9:
		if '0' <= c && c <= '9' {
			state = 12
			goto _nsec
		}
		goto _err
	case 12, 13, 14, 15, 16:
		if '0' <= c && c <= '9' {
			state++
			goto _nsec
		}
		goto _out
	case 17:
		goto _out
	}
_hour:
	*hour *= 10
	*hour += int(c - '0')
	goto _next
_minute:
	*minute *= 10
	*minute += int(c - '0')
	goto _next
_sec:
	*sec *= 10
	*sec += int(c - '0')
	goto _next
_nsec:
	x /= 10
	*nsec *= 10
	*nsec += int(c - '0')
_next:
	if *pos++; *pos != eof {
		goto _resume
	}
_out:
	if state < 10 {
		goto _err
	}
	*nsec *= x
	return nil
_err:
	return ErrTimestamp
}

// 'Z' | (('+' | '-')([01][0-9] | [2][0-3]) ':' [0-5][0-9])
func scanTZ(data []byte, pos *int) error {
	var (
		c     byte
		state uint8
		eof   = len(data)
	)
	if eof == 0 || eof <= *pos {
		goto _err
	}
_resume:
	switch c = data[*pos]; state {
	case 0:
		switch c {
		case '+', '-':
			state = 1
			goto _next
		case 'Z':
			state = 7
			goto _next
		}
		goto _err
	case 1:
		if c == '2' {
			state = 6
			goto _next
		}
		if c == '0' || c == '1' {
			state = 2
			goto _next
		}
		goto _err
	case 2:
		if '0' <= c && c <= '9' {
			state = 3
			goto _next
		}
		goto _err
	case 3:
		if c == ':' {
			state = 4
			goto _next
		}
		goto _err
	case 4:
		if '0' <= c && c <= '5' {
			state = 5
			goto _next
		}
		goto _err
	case 5:
		if '0' <= c && c <= '9' {
			state = 7
			goto _next
		}
		goto _err
	case 6:
		if '0' <= c && c <= '3' {
			state = 4
			goto _next
		}
		goto _err
	case 7:
		if c == ' ' {
			state = 8
			goto _next
		}
		goto _err
	case 8:
		goto _out
	}
_next:
	if *pos++; *pos != eof {
		goto _resume
	}
_out:
	if state < 8 {
		goto _err
	}
	return nil
_err:
	return ErrTimestamp
}

// 'Z' | (('+' | '-')([01][0-9] | [2][0-3]) ':' [0-5][0-9])
func parseTZ(data []byte, pos, offset *int) error {
	var (
		c      byte
		state  uint8
		eof    = len(data)
		hour   int
		minute int
		sign   = 1
	)
	if eof == 0 || eof <= *pos {
		goto _err
	}
_resume:
	switch c = data[*pos]; state {
	case 0:
		switch c {
		case '+':
			state = 1
			goto _next
		case '-':
			state = 1
			sign = -1
			goto _next
		case 'Z':
			state = 7
			goto _next
		}
		goto _err
	case 1:
		if c == '2' {
			state = 6
			goto _hour
		}
		if c == '0' || c == '1' {
			state = 2
			goto _hour
		}
		goto _err
	case 2:
		if '0' <= c && c <= '9' {
			state = 3
			goto _hour
		}
		goto _err
	case 3:
		if c == ':' {
			state = 4
			goto _next
		}
		goto _err
	case 4:
		if '0' <= c && c <= '5' {
			state = 5
			goto _minute
		}
		goto _err
	case 5:
		if '0' <= c && c <= '9' {
			state = 7
			goto _minute
		}
		goto _err
	case 6:
		if '0' <= c && c <= '3' {
			state = 4
			goto _hour
		}
		goto _err
	case 7:
		if c == ' ' {
			state = 8
			goto _next
		}
		goto _err
	case 8:
		goto _out
	}
_minute:
	minute *= 10
	minute += int(c - '0')
	goto _next
_hour:
	hour *= 10
	hour += int(c - '0')
_next:
	if *pos++; *pos != eof {
		goto _resume
	}
_out:
	if state < 8 {
		goto _err
	}
	*offset = sign * (hour*3600 + minute*60)
	return nil
_err:
	return ErrTimestamp
}

func ScanHostname(data []byte, pos *int) ([]byte, error) {
	return scanField(data, pos, 255, ErrHostname)
}

func ScanAppName(data []byte, pos *int) ([]byte, error) {
	return scanField(data, pos, 48, ErrAppName)
}

func ScanProcId(data []byte, pos *int) ([]byte, error) {
	return scanField(data, pos, 128, ErrProcId)
}

func ScanMsgId(data []byte, pos *int) ([]byte, error) {
	return scanField(data, pos, 32, ErrMsgId)
}

func scanField(data []byte, pos *int, width int, err error) ([]byte, error) {
	if w, p := len(data), *pos; w > p {
		if len(data[*pos:]) > 1 && data[*pos] == '-' && data[*pos+1] == ' ' {
			*pos += 2
			return nil, nil
		}
		if w > width {
			w = *pos + width
		}
		for ; *pos < w; *pos++ {
			if data[*pos] == ' ' {
				break
			}
			if 33 > data[*pos] || data[*pos] > 126 {
				return nil, err
			}
		}
		if p < *pos && *pos < len(data) && data[*pos] == ' ' {
			*pos++
			return data[p : *pos-1], nil
		}
	}
	return nil, err
}

const (
	// Severity
	EMERG   uint8 = iota // 0
	ALERT                // 1
	CRIT                 // 2
	ERROR                // 3
	WARNING              // 4
	NOTICE               // 5
	INFO                 // 6
	DEBUG                // 7
)

const (
	// Facility
	KERN     uint8 = iota << 3 // 0
	USER                       // 8
	MAIL                       // 16
	DAEMON                     // 24
	AUTH                       // 32
	SYSLOG                     // 40
	LPR                        // 48
	NEWS                       // 56
	UUCP                       // 64
	CRON                       // 72
	AUTHPRIV                   // 80
	FTP                        // 88
	NTP                        // 96
	AUDITLOG                   // 104
	ALERTLOG                   // 112
	CLOCK                      // 120
	LOCAL0                     // 128
	LOCAL1                     // 136
	LOCAL2                     // 144
	LOCAL3                     // 152
	LOCAL4                     // 160
	LOCAL5                     // 168
	LOCAL6                     // 176
	LOCAL7                     // 184
)

var (
	severity = []string{`EMERG`, `ALERT`, `CRIT`, `ERROR`, `WARNING`, `NOTICE`, `INFO`, `DEBUG`}
	facility = []string{
		`KERN`, `USER`, `MAIL`, `DAEMON`, `AUTH`, `SYSLOG`, `LPR`, `NEWS`,
		`UUCP`, `CRON`, `AUTHPRIV`, `FTP`, `NTP`, `AUDITLOG`, `ALERTLOG`, `CLOCK`,
		`LOCAL0`, `LOCAL1`, `LOCAL2`, `LOCAL3`, `LOCAL4`, `LOCAL5`, `LOCAL6`, `LOCAL7`,
	}

	ErrHeader    = errors.New(`invalid header`)
	ErrPriority  = errors.New(`invalid priority`)
	ErrVersion   = errors.New(`invalid version`)
	ErrTimestamp = errors.New(`invalid timestamp`)
	ErrHostname  = errors.New(`invalid hostname`)
	ErrAppName   = errors.New(`invalid app_name`)
	ErrProcId    = errors.New(`invalid proc_id`)
	ErrMsgId     = errors.New(`invalid msg_id`)
)
