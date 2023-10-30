package dns

import (
	"bytes"
	"reflect"
	"strconv"
	"testing"
)

func TestRecord(t *testing.T) {
	t.Run("can encode and decode a record", func(t *testing.T) {
		tests := []struct {
			decoded *Record
			encoded []byte
		}{
			{
				decoded: &Record{
					Question: &Question{
						Name:  Name{"com"},
						Type:  1,
						Class: 1,
					},
					TTL:  1,
					Data: []byte("foo"),
				},
				encoded: []byte{
					3, 'c', 'o', 'm', 0, // Name
					0, 1, // Class
					0, 1, // Type
					0, 0, 0, 1, // TTL
					0, 3, // RDLength
					'f', 'o', 'o', // RData
				},
			},
		}

		for i, test := range tests {
			t.Run(strconv.Itoa(i), func(t *testing.T) {
				n, gotDecoded, err := DecodeRecord(test.encoded)
				if err != nil {
					t.Fatal(err)
				} else if !reflect.DeepEqual(gotDecoded, test.decoded) {
					t.Fatalf("decoded %+v instead of %+v", gotDecoded, test.decoded)
				} else if n != len(test.encoded) {
					t.Fatalf("decoded %d bytes instead of %d", n, len(test.encoded))
				}

				gotEncoded := test.decoded.AppendEncoded([]byte{})
				if !bytes.Equal(gotEncoded, test.encoded) {
					t.Fatalf("encoded %+v instead of %+v", gotEncoded, test.encoded)
				}
			})
		}
	})
}
