package dns

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
)

type Message struct {
	Header     *Header
	Questions  []*Question
	Answer     []*Record
	Authority  []*Record
	Additional []*Record
}

func DecodeMessage(src []byte) (int, *Message, error) {
	read := 0

	n, header, err := DecodeHeader(src)
	read += n
	if err != nil {
		return read, nil, fmt.Errorf("decode header: %w", err)
	}

	n, questions, err := DecodeQuestions(header.QDCount, src[read:])
	read += n
	if err != nil {
		return read, nil, fmt.Errorf("decode questions: %w", err)
	}

	n, answer, err := DecodeRecords(header.ANCount, src[read:])
	read += n
	if err != nil {
		return read, nil, fmt.Errorf("decode answer records: %w", err)
	}

	n, authority, err := DecodeRecords(header.NSCount, src[read:])
	read += n
	if err != nil {
		return read, nil, fmt.Errorf("decode authority records: %w", err)
	}

	n, additional, err := DecodeRecords(header.ARCount, src[read:])
	read += n
	if err != nil {
		return read, nil, fmt.Errorf("decode additional records: %w", err)
	}

	return read, &Message{
		Header:     header,
		Questions:  questions,
		Answer:     answer,
		Authority:  authority,
		Additional: additional,
	}, nil
}

func (m *Message) AppendEncoded(b []byte) []byte {
	b = m.Header.AppendEncoded(b)
	for _, q := range m.Questions {
		b = q.AppendEncoded(b)
	}
	for _, answer := range m.Answer {
		b = answer.AppendEncoded(b)
	}
	for _, authority := range m.Authority {
		b = authority.AppendEncoded(b)
	}
	for _, additional := range m.Additional {
		b = additional.AppendEncoded(b)
	}
	return b
}

func (m *Message) JSON() []byte {
	b, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	return b
}

/*
Header represents a DNS message header, as defined in RFC-1035 and RFC-4035.

	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                      ID                       |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|QR|   Opcode  |AA|TC|RD|RA|Z0|AD|CD|   RCODE   |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                    QDCOUNT                    |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                    ANCOUNT                    |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                    NSCOUNT                    |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                    ARCOUNT                    |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
type Header struct {
	ID      uint16
	QR      bool
	Opcode  uint8
	AA      bool
	TC      bool
	RD      bool
	RA      bool
	Z0      bool
	AD      bool
	CD      bool
	RCode   uint8
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

const (
	maskQR     uint16 = 0b_10000000_00000000
	maskOpcode uint16 = 0b_01111000_00000000
	maskAA     uint16 = 0b_00000100_00000000
	maskTC     uint16 = 0b_00000010_00000000
	maskRD     uint16 = 0b_00000001_00000000
	maskRA     uint16 = 0b_00000000_10000000
	maskZ0     uint16 = 0b_00000000_01000000
	maskAD     uint16 = 0b_00000000_00100000
	maskCD     uint16 = 0b_00000000_00010000
	maskRCode  uint16 = 0b_00000000_00001111
)

func DecodeHeader(src []byte) (int, *Header, error) {
	if len(src) < 12 {
		return 0, nil, fmt.Errorf("invalid header length %d", len(src))
	}
	flags := binary.BigEndian.Uint16(src[2:])
	return 12, &Header{
		ID:      binary.BigEndian.Uint16(src[0:]),
		QR:      flags&maskQR != 0,
		Opcode:  uint8((flags & maskOpcode) >> 11),
		AA:      flags&maskAA != 0,
		TC:      flags&maskTC != 0,
		RD:      flags&maskRD != 0,
		RA:      flags&maskRA != 0,
		Z0:      flags&maskZ0 != 0,
		AD:      flags&maskAD != 0,
		CD:      flags&maskCD != 0,
		RCode:   uint8(flags & maskRCode),
		QDCount: binary.BigEndian.Uint16(src[4:]),
		ANCount: binary.BigEndian.Uint16(src[6:]),
		NSCount: binary.BigEndian.Uint16(src[8:]),
		ARCount: binary.BigEndian.Uint16(src[10:]),
	}, nil
}

func (h *Header) AppendEncoded(b []byte) []byte {
	flags := uint16(h.Opcode)<<11 | uint16(h.RCode)
	if h.QR {
		flags |= maskQR
	}
	if h.AA {
		flags |= maskAA
	}
	if h.TC {
		flags |= maskTC
	}
	if h.RD {
		flags |= maskRD
	}
	if h.RA {
		flags |= maskRA
	}
	if h.Z0 {
		flags |= maskZ0
	}
	if h.AD {
		flags |= maskAD
	}
	if h.CD {
		flags |= maskCD
	}

	b = binary.BigEndian.AppendUint16(b, h.ID)
	b = binary.BigEndian.AppendUint16(b, flags)
	b = binary.BigEndian.AppendUint16(b, h.QDCount)
	b = binary.BigEndian.AppendUint16(b, h.ANCount)
	b = binary.BigEndian.AppendUint16(b, h.NSCount)
	b = binary.BigEndian.AppendUint16(b, h.ARCount)
	return b
}
