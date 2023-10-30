package dns

import (
	"bytes"
	"strconv"
	"testing"
)

func TestName(t *testing.T) {
	t.Run("can encode and decode name", func(t *testing.T) {
		tests := []struct {
			decoded Name
			encoded []byte
		}{
			{
				decoded: Name{"www", "example", "com"},
				encoded: []byte{
					3, 'w', 'w', 'w',
					7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
					3, 'c', 'o', 'm',
					0,
				},
			},
		}

		for i, test := range tests {
			t.Run(strconv.Itoa(i), func(t *testing.T) {
				n, gotDecoded, err := DecodeName(test.encoded)
				if err != nil {
					t.Fatal(err)
				} else if !gotDecoded.Is(test.decoded) {
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
