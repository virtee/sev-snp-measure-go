/*
SPDX-License-Identifier: Apache-2.0
*/

package ovmf

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

const (
	SEV_HASH_TABLE_HEADER_GUID = "9438d606-4f22-4cc9-b479-a793d411fd21"
	SEV_KERNEL_ENTRY_GUID      = "4de79437-abd2-427f-b835-d5b172d2045b"
	SEV_INITRD_ENTRY_GUID      = "44baf731-3a2f-4bd7-9af1-41e29169781d"
	SEV_CMDLINE_ENTRY_GUID     = "97d02dd8-bd20-4c94-aa78-e7714d36ab2a"
)

type SevHashes struct {
	KernelHash  []byte
	InitrdHash  []byte
	CmdlineHash []byte
}

func NewSevHashes(kernel []byte, initrd []byte, cmdlineAppend string) (*SevHashes, error) {
	kernelHash := sha256.Sum256(kernel)
	initrdHash := sha256.Sum256(initrd)

	cmdline := append([]byte(cmdlineAppend), 0x00)
	cmdlineHash := sha256.Sum256(cmdline)

	return &SevHashes{
		KernelHash:  kernelHash[:],
		InitrdHash:  initrdHash[:],
		CmdlineHash: cmdlineHash[:],
	}, nil
}

type SevHashTableEntry struct {
	Guid   [16]byte
	Length uint16
	Hash   [32]byte
}

type SevHashTable struct {
	Guid    [16]byte
	Length  uint16
	Cmdline SevHashTableEntry
	Initrd  SevHashTableEntry
	Kernel  SevHashTableEntry
}

func (h *SevHashes) ConstructTable() ([]byte, error) {
	headerGuid, err := GuidFromStr(SEV_HASH_TABLE_HEADER_GUID)
	if err != nil {
		return nil, err
	}
	cmdlineGuid, err := GuidFromStr(SEV_CMDLINE_ENTRY_GUID)
	if err != nil {
		return nil, err
	}
	initrdGuid, err := GuidFromStr(SEV_INITRD_ENTRY_GUID)
	if err != nil {
		return nil, err
	}
	kernelGuid, err := GuidFromStr(SEV_KERNEL_ENTRY_GUID)
	if err != nil {
		return nil, err
	}

	table := SevHashTable{
		Guid:   headerGuid,
		Length: uint16(binary.Size(SevHashTable{})),
		Cmdline: SevHashTableEntry{
			Guid:   cmdlineGuid,
			Length: uint16(binary.Size(SevHashTableEntry{})),
		},
		Initrd: SevHashTableEntry{
			Guid:   initrdGuid,
			Length: uint16(binary.Size(SevHashTableEntry{})),
		},
		Kernel: SevHashTableEntry{
			Guid:   kernelGuid,
			Length: uint16(binary.Size(SevHashTableEntry{})),
		},
	}

	copy(table.Cmdline.Hash[:], h.CmdlineHash)
	copy(table.Initrd.Hash[:], h.InitrdHash)
	copy(table.Kernel.Hash[:], h.KernelHash)

	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, table); err != nil {
		return nil, err
	}

	// Add padding to round up to 16-byte boundary (matching Python implementation)
	tableSize := buf.Len()
	paddedSize := (tableSize + 15) & ^15
	paddingSize := paddedSize - tableSize
	padding := make([]byte, paddingSize)
	buf.Write(padding)

	return buf.Bytes(), nil
}

func (h *SevHashes) ConstructPage(offset int) ([]byte, error) {
	if offset >= 4096 {
		return nil, fmt.Errorf("offset %d must be less than 4096", offset)
	}

	tableBytes, err := h.ConstructTable()
	if err != nil {
		return nil, err
	}

	// Calculate padding size
	tableSize := len(tableBytes)
	paddedSize := (tableSize + 15) & ^15

	page := make([]byte, 4096)
	if len(page) < offset+paddedSize {
		return nil, fmt.Errorf("table does not fit in page at offset %d", offset)
	}

	copy(page[offset:], tableBytes)

	return page, nil
}
