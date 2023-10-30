package dns

import (
	"bytes"
	"reflect"
	"strconv"
	"testing"
)

func TestQuestion(t *testing.T) {
	t.Run("can encode and decode question", func(t *testing.T) {
		tests := []struct {
			decoded *Question
			encoded []byte
		}{
			{
				decoded: &Question{
					Name:  Name{"com"},
					Type:  1,
					Class: 2,
				},
				encoded: []byte{
					3, 'c', 'o', 'm', 0, // Name
					0, 1, // Type
					0, 2, // Class
				},
			},
		}

		for i, test := range tests {
			t.Run(strconv.Itoa(i), func(t *testing.T) {
				n, gotDecoded, err := DecodeQuestion(test.encoded)
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
