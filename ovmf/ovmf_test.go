package ovmf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLittleEndianBytes(t *testing.T) {
	testCases := map[string]struct {
		input  [16]byte
		output [16]byte
	}{
		"success": {
			input:  [16]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15},
			output: [16]byte{0x03, 0x02, 0x01, 0x00, 0x05, 0x04, 0x07, 0x06, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			output := LittleEndianBytes(tc.input)
			assert.True(bytes.Equal(tc.output[:], output[:]), fmt.Sprintf("expected %x, got %x", tc.output, output))
		})
	}
}

func TestNewAPIObject(t *testing.T) {
	ovmf, err := New("../guest/testdata/ovmf_img_2.bin")
	require.NoError(t, err)

	apiObject, err := NewMetadataWrapper(ovmf)
	require.NoError(t, err)

	data, err := json.Marshal(apiObject)
	require.NoError(t, err)

	err = os.WriteFile("testdata/ovmf_img_2.json", data, 0o644)
	require.NoError(t, err)
}
