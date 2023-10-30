package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
)

/*
Question represents a DNS question as defined in RFC-1035.

	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                                               |
	/                     QNAME                     /
	/                                               /
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                     QTYPE                     |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                     QCLASS                    |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
type Question struct {
	Name  Name   // Domain name as a sequence of labels
	Type  uint16 // Type of query
	Class uint16 // Class of the query
}

func DecodeQuestion(src []byte) (int, *Question, error) {
	read, name, err := DecodeName(src)
	if err != nil {
		return read, nil, err
	}
	if len(src) < read+4 {
		return read, nil, errors.New("missing QTYPE/QCLASS")
	}
	return read + 4, &Question{
		Name:  name,
		Type:  binary.BigEndian.Uint16(src[read:]),
		Class: binary.BigEndian.Uint16(src[read+2:]),
	}, nil
}

func (q *Question) AppendEncoded(b []byte) []byte {
	b = q.Name.AppendEncoded(b)
	b = binary.BigEndian.AppendUint16(b, q.Type)
	b = binary.BigEndian.AppendUint16(b, q.Class)
	return b
}

func DecodeQuestions(n uint16, src []byte) (int, []*Question, error) {
	if n == 0 {
		return 0, nil, nil
	}

	out := make([]*Question, 0, n)
	read := 0
	for i := uint16(0); i < n; i++ {
		n, q, err := DecodeQuestion(src[read:])
		read += n
		if err != nil {
			return read, nil, fmt.Errorf("decode question: %w (question #%d)", err, i)
		}
		out = append(out, q)
	}
	return read, out, nil
}
