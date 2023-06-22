/*
Copyright Edgeless Systems GmbH
Copyright 2022- IBM Inc. All rights reserved

SPDX-License-Identifier: Apache-2.0
*/

package ovmf

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
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
