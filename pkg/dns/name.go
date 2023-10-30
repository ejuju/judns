package dns

import (
	"errors"
	"fmt"
	"strings"
)

type Name []string

func DecodeName(src []byte) (int, Name, error) {
	if len(src) == 0 {
		return 0, nil, errors.New("buffer is empty")
	}
	read := 0
	n := Name{}
	for i := 0; ; i++ {
		compressed := (src[read] & 0b_1100_0000) >> 6
		labelLength := src[read] & 0b_0011_1111
		read++
		if compressed > 0 {
			return read, nil, fmt.Errorf("compression not supported yet (at label #%d)", i)
		} else if labelLength == 0 {
			break
		}

		endIndex := read + int(labelLength)
		if endIndex > len(src) {
			return read, nil, fmt.Errorf("label %q shorter than %d (at label #%d)", src[read:], labelLength, i)
		}
		n = append(n, string(src[read:endIndex]))
		read += int(labelLength)
	}

	return read, n, nil
}

func (n Name) AppendEncoded(b []byte) []byte {
	for _, label := range n {
		b = append(b, uint8(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0)
	return b
}

func (n Name) String() string { return strings.Join(n, ".") + "." }

func (n Name) Is(other Name) bool {
	if len(n) != len(other) {
		return false
	}
	for i, label := range n {
		if !strings.EqualFold(label, other[i]) {
			return false
		}
	}
	return true
}
