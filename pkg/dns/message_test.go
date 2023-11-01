package dns

import (
	"bytes"
	"reflect"
	"strconv"
	"testing"
)

func TestMessage_HeaderEncoding(t *testing.T) {
	tests := []struct {
		decoded *Header
		encoded [12]byte
	}{
		{
			decoded: &Header{
				ID:                   1,
				IsResponse:           true,
				Opcode:               0b_1111,
				IsAuthoritative:      true,
				IsTruncated:          true,
				IsRecursionDesired:   true,
				IsRecursionAvailable: true,
				Z0:                   true,
				IsAuthenticData:      true,
				IsCheckingDisabled:   true,
				RCode:                0b_1111,
				QDCount:              1,
				ANCount:              2,
				NSCount:              3,
				ARCount:              4,
			},
			encoded: [12]byte{
				0, 1,
				0b_11111111, 0b_11111111,
				0, 1,
				0, 2,
				0, 3,
				0, 4,
			},
		},
		{
			decoded: &Header{
				ID:                   0,
				IsResponse:           false,
				Opcode:               0b_0000,
				IsAuthoritative:      false,
				IsTruncated:          false,
				IsRecursionDesired:   false,
				IsRecursionAvailable: false,
				Z0:                   false,
				IsAuthenticData:      false,
				IsCheckingDisabled:   false,
				RCode:                0b_0000,
				QDCount:              0,
				ANCount:              0,
				NSCount:              0,
				ARCount:              0,
			},
			encoded: [12]byte{
				0b_00000000, 0b_00000000,
				0b_00000000, 0b_00000000,
				0b_00000000, 0b_00000000,
				0b_00000000, 0b_00000000,
				0b_00000000, 0b_00000000,
				0b_00000000, 0b_00000000,
			},
		},
	}

	for i, test := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			_, gotDecoded, _ := DecodeHeader(test.encoded[:])
			if !reflect.DeepEqual(gotDecoded, test.decoded) {
				t.Fatalf("decoded %+v instead of %+v", gotDecoded, test.decoded)
			}
			gotEncoded := test.decoded.AppendEncoded([]byte{})
			if !bytes.Equal(gotEncoded, test.encoded[:]) {
				t.Fatalf("encoded %+v instead of %+v", gotEncoded, test.encoded)
			}
		})
	}
}

func TestMessage_Encoding(t *testing.T) {
	tests := []struct {
		decoded *Message
		encoded []byte
	}{
		{
			decoded: &Message{
				Header: &Header{
					ID:                   1,
					IsResponse:           true,
					Opcode:               0b_1111,
					IsAuthoritative:      true,
					IsTruncated:          true,
					IsRecursionDesired:   true,
					IsRecursionAvailable: true,
					Z0:                   true,
					IsAuthenticData:      true,
					IsCheckingDisabled:   true,
					RCode:                0b_1111,
					QDCount:              2,
					ANCount:              2,
					NSCount:              1,
					ARCount:              0,
				},
				Questions: []*Question{
					{Name: Name{"com"}, Type: 1, Class: 1},
					{Name: Name{"fr"}, Type: 3, Class: 4},
				},
			},
			encoded: []byte{
				// Header
				0, 1, //                     Header: ID */
				0b_11111111, 0b_11111111, // Header: Flags */
				0, 2, //                     Header: QDCount */
				0, 2, //                     Header: ANCount */
				0, 1, //                     Header: NSCount */
				0, 0, //                     Header: ARCount */
				// Question #1
				3, 'c', 'o', 'm', 0, //      Question #1: Name */
				0, 1, //                     Question #1: Type */
				0, 2, //                     Question #1: Class */
				// Question #2
				2, 'f', 'r', 0, //           Question #2: Name */
				0, 3, //                     Question #2: Type */
				0, 4, //                     Question #2: Class */
				// Answer #1
				3, 'c', 'o', 'm', 0, //      Answer #1: Name */
				0, 1, //                     Answer #1: Type */
				0, 2, //                     Answer #1: Class */
				0, 0, 0, 1, //               Answer #1: TTL */
				0, 3, //                     Answer #1: RDLength */
				'f', 'o', 'o', //            Answer #1: RData */
				// Answer #2
				2, 'f', 'r', 0, //           Answer #2: Name */
				0, 3, //                     Answer #2: Type */
				0, 4, //                     Answer #2: Class */
				0, 0, 0, 1, //               Answer #2: TTL */
				0, 3, //                     Answer #2: RDLength */
				'f', 'o', 'o', //            Answer #2: RData
				// Authority
				2, 'a', 'r', 0, //           Authority #1: Name */
				0, 1, //                     Authority #1: Type */
				0, 1, //                     Authority #1: Class */
				0, 0, 0, 255, //             Authority #1: TTL */
				0, 3, //                     Authority #1: RDLength */
				'f', 'o', 'o', //            Authority #1: RData
				// Additional (none)
			},
		},
	}

	for i, test := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			_, gotDecoded, err := DecodeMessage(test.encoded)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(gotDecoded, test.decoded) {
				t.Fatalf("decoded %s instead of %s", gotDecoded.JSON(), test.decoded.JSON())
			}
			gotEncoded := test.decoded.AppendEncoded([]byte{})
			if !bytes.Equal(gotEncoded, test.encoded[:]) {
				t.Fatalf("encoded %+v instead of %+v", gotEncoded, test.encoded)
			}
		})
	}
}
