package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
)

type Record struct {
	Question *Question // Question
	TTL      uint32    // Cache lifetime
	Data     []byte    // Record data (depends on type)
}

func DecodeRecord(src []byte) (int, *Record, error) {
	read, question, err := DecodeQuestion(src)
	if err != nil {
		return read, nil, err
	}

	if len(src) < read+6 {
		return read, nil, errors.New("missing TTL/RDLENGTH")
	}
	ttl := binary.BigEndian.Uint32(src[read:])
	rdlength := binary.BigEndian.Uint16(src[read+4:])
	read += 6

	endIndex := read + int(rdlength)
	if len(src) < endIndex {
		return read, nil, fmt.Errorf("rdata %q shorter than expected %d", src[read:], rdlength)
	}

	return read + int(rdlength), &Record{
		Question: question,
		TTL:      ttl,
		Data:     src[read:endIndex],
	}, nil
}

func (rr *Record) AppendEncoded(b []byte) []byte {
	b = rr.Question.AppendEncoded(b)
	b = binary.BigEndian.AppendUint32(b, rr.TTL)
	b = binary.BigEndian.AppendUint16(b, uint16(len(rr.Data)))
	b = append(b, rr.Data...)
	return b
}

func DecodeRecords(n uint16, src []byte) (int, []*Record, error) {
	if n == 0 {
		return 0, nil, nil
	}

	records := make([]*Record, 0, n)
	read := 0
	for i := uint16(0); i < n; i++ {
		n, rr, err := DecodeRecord(src[read:])
		read += n
		if err != nil {
			return read, nil, fmt.Errorf("[%d/%d] %w", i+1, n, err)
		}
		records = append(records, rr)
	}
	return read, records, nil
}
