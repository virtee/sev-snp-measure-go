/*
Copyright Edgeless Systems GmbH
Copyright 2022- IBM Inc. All rights reserved

SPDX-License-Identifier: Apache-2.0
*/

package ovmf

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

type SectionType int

const (
	SNPSECMEM SectionType = iota + 1
	SNPSecrets
	CPUID
	SVSMCAA
	SNPKernelHashes SectionType = 0x10

	FOUR_GB                 = 0x100000000
	OVMF_TABLE_FOOTER_GUID  = "96b582de-1fb2-45f7-baea-a366c55a082d"
	SEV_HASH_TABLE_RV_GUID  = "7255371f-3a3b-4b04-927b-1da6efa8d454"
	SEV_ES_RESET_BLOCK_GUID = "00f771de-1a7e-4fcb-890e-68c77e2fb44e"
	OVMF_SEV_META_DATA_GUID = "dc886566-984a-4798-a75e-5585a7bf67cc"
	SVSMInfoGUID            = "a789a612-0597-4c4b-a49f-cbb1fe9d1ddd"
)

func New(filename string, endAt int) (OVMF, error) {
	if endAt == 0 {
		endAt = FOUR_GB
	}

	ovmf := OVMF{
		endAt: endAt,
	}

	file, err := os.Open(filename)
	if err != nil {
		return OVMF{}, err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return OVMF{}, err
	}

	ovmf.data = data

	err = ovmf.parseFooterTable()
	if err != nil {
		return OVMF{}, fmt.Errorf("parsing footer table: %w", err)
	}

	err = ovmf.parseSevMetadata()
	if err != nil {
		return OVMF{}, fmt.Errorf("parsing SEV metadata: %w", err)
	}

	return ovmf, nil
}

func LittleEndianBytes(bytes [16]byte) [16]byte {
	part1 := reverseBytes(bytes[:4])
	part2 := reverseBytes(bytes[4:6])
	part3 := reverseBytes(bytes[6:8])
	part4 := bytes[8:]

	return [16]byte(append(append(append(part1, part2...), part3...), part4...))
}

type FooterTableEntry struct {
	Size uint16
	Guid [16]byte
}

func NewFooterTableEntry(data []byte) (*FooterTableEntry, error) {
	var entry FooterTableEntry
	err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &entry)
	if err != nil {
		return nil, fmt.Errorf("reading OvmfFooterTableEntry from data: %w", err)
	}
	return &entry, nil
}

type MetadataHeader struct {
	Signature [4]uint8
	// Size describes how big the metadata section is.
	Size    uint32
	Version uint32
	// NumItems describes how many MetadataSection items there are.
	NumItems uint32
}

func NewMetadataHeader(data []byte) (*MetadataHeader, error) {
	var entry MetadataHeader
	err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &entry)
	if err != nil {
		return nil, fmt.Errorf("reading OvmfSevMetadataHeader from data: %w", err)
	}
	return &entry, nil
}

func (h *MetadataHeader) Verify() error {
	if string(h.Signature[:]) != "ASEV" {
		return errors.New("wrong SEV metadata signature")
	}
	if h.Version != 1 {
		return errors.New("wrong SEV metadata version")
	}
	return nil
}

type MetadataSection struct {
	// GPA is the Guest Physical Adress of the page. The GPA becomes part of the launch digest.
	GPA  uint32
	Size uint32
	// SectionTypeInt is the Section Type of the described page. The type becomes part of the launch digest.
	SectionTypeInt uint32
}

// MarshalJSON is a custom marshaller for MetadataSection. It converts the GPA and Size to hex strings.
func (m *MetadataSection) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"GPA":            fmt.Sprintf("0x%x", m.GPA),
		"Size":           fmt.Sprintf("0x%x", m.Size),
		"SectionTypeInt": m.SectionTypeInt,
	})
}

// UnmarshalJSON is a custom unmarshaller for MetadataSection. It converts the GPA and Size from hex strings.
func (m *MetadataSection) UnmarshalJSON(data []byte) error {
	var tmp map[string]any
	err := json.Unmarshal(data, &tmp)
	if err != nil {
		return err
	}

	// For some reason json unmarshals SectionTypeInt to a float64.
	sectionType, ok := tmp["SectionTypeInt"].(float64)
	if !ok {
		return errors.New("missing SectionTypeInt")
	}
	m.SectionTypeInt = uint32(sectionType)

	gpa, ok := tmp["GPA"].(string)
	if !ok {
		return errors.New("missing GPA")
	}
	gpa, found := strings.CutPrefix(gpa, "0x")
	if !found {
		return errors.New("missing 0x prefix from gpa")
	}

	size, ok := tmp["Size"].(string)
	if !ok {
		return errors.New("missing Size")
	}
	size, found = strings.CutPrefix(size, "0x")
	if !found {
		return errors.New("missing 0x prefix from size")
	}

	gpaInt, err := strconv.ParseInt(gpa, 16, 0)
	if err != nil {
		return fmt.Errorf("parsing GPA: %w", err)
	}

	sizeInt, err := strconv.ParseInt(size, 16, 0)
	if err != nil {
		return fmt.Errorf("parsing Size: %w", err)
	}

	m.GPA = uint32(gpaInt)
	m.Size = uint32(sizeInt)

	return nil
}

func NewMetadataSectionDesc(data []byte) (*MetadataSection, error) {
	var entry MetadataSection
	err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &entry)
	if err != nil {
		return nil, fmt.Errorf("reading MetadataSectionDesc from data: %w", err)
	}
	return &entry, nil
}

func (o *MetadataSection) SectionType() (SectionType, error) {
	st := SectionType(o.SectionTypeInt)

	switch st {
	case SNPSECMEM, SNPSecrets, CPUID, SNPKernelHashes, SVSMCAA:
		return st, nil
	default:
		return -1, fmt.Errorf("unknown OVMF metadata section type: %d", st)
	}
}

type OVMF struct {
	data          []byte
	table         map[string][]byte
	metadataItems []MetadataSection
	endAt         int
}

// MetadataWrapper replaces the OVMF binary when using an OVMF hash.
// It contains the metadata items and the reset EIP that have been parsed from the binary before.
type MetadataWrapper struct {
	MetadataItems []MetadataSection
	ResetEIP      uint32
	OVMFHash      []byte
}

func NewMetadataWrapper(ovmf OVMF, ovmfHash []byte) (*MetadataWrapper, error) {
	resetEIP, err := ovmf.SevESResetEIP()
	if err != nil {
		return nil, fmt.Errorf("getting reset EIP: %w", err)
	}

	return &MetadataWrapper{
		MetadataItems: ovmf.MetadataItems(),
		ResetEIP:      resetEIP,
		OVMFHash:      ovmfHash,
	}, nil
}

// MarshalJSON is a custom marshaller for MetadataSection. It converts the GPA and Size to hex strings.
func (m *MetadataWrapper) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"MetadataItems": m.MetadataItems,
		"ResetEIP":      fmt.Sprintf("0x%x", m.ResetEIP),
		"OVMFHash":      hex.EncodeToString(m.OVMFHash),
	})
}

// UnmarshalJSON is a custom unmarshaller for MetadataSection. It converts the GPA and Size from hex strings.
func (m *MetadataWrapper) UnmarshalJSON(data []byte) error {
	var tmp map[string]json.RawMessage
	err := json.Unmarshal(data, &tmp)
	if err != nil {
		return err
	}

	foo, ok := tmp["MetadataItems"]
	if !ok {
		return errors.New("missing MetadataItems")
	}
	if err := json.Unmarshal(foo, &m.MetadataItems); err != nil {
		return err
	}

	resetEIP, ok := tmp["ResetEIP"]
	if !ok {
		return errors.New("missing ResetEIP")
	}
	var eip string
	if err := json.Unmarshal(resetEIP, &eip); err != nil {
		return err
	}

	foo, ok = tmp["OVMFHash"]
	if !ok {
		return errors.New("missing OVMFHash")
	}
	var hash string
	if err := json.Unmarshal(foo, &hash); err != nil {
		return err
	}

	// TODO: cut prefix?

	hashRaw, err := hex.DecodeString(hash)
	if err != nil {
		return fmt.Errorf("decoding hash: %w", err)
	}
	m.OVMFHash = hashRaw

	eip, found := strings.CutPrefix(eip, "0x")
	if !found {
		return errors.New("missing 0x prefix from ResetEIP")
	}
	eipInt, err := strconv.ParseInt(eip, 16, 0)
	if err != nil {
		return fmt.Errorf("parsing ResetEIP: %w", err)
	}

	m.ResetEIP = uint32(eipInt)

	return nil
}

// NewFromAPIObject creates an OVMF object from an APIObject.
// This OVMF object can only be used in conjunction with a OVMF Hash, as the data property is not
func NewFromAPIObject(apiObject MetadataWrapper) (OVMF, error) {
	ovmf := OVMF{}

	ovmf.metadataItems = apiObject.MetadataItems

	resetEIP := make([]byte, 4)
	binary.LittleEndian.PutUint32(resetEIP, apiObject.ResetEIP)
	ovmf.table[SEV_ES_RESET_BLOCK_GUID] = resetEIP

	return ovmf, nil
}

func NewFromMetadataItems(metadataItems []MetadataSection) OVMF {
	return OVMF{
		metadataItems: metadataItems,
	}
}

func (o *OVMF) Data() []byte {
	return o.data
}

func (o *OVMF) GPA() int {
	return o.endAt - len(o.data)
}

func (o *OVMF) TableItem(guid string) ([]byte, error) {
	if item, ok := o.table[guid]; ok {
		return item, nil
	}
	return nil, errors.New("GUID not found in table")
}

func (o *OVMF) MetadataItems() []MetadataSection {
	return o.metadataItems
}

func (o *OVMF) SevESResetEIP() (uint32, error) {
	item, err := o.TableItem(SEV_ES_RESET_BLOCK_GUID)
	if err != nil {
		return 0, err
	}
	if len(item) < 4 {
		return 0, fmt.Errorf("invalid SEV_ES_RESET_BLOCK_GUID item size %d, expected 4", len(item))
	}
	return binary.LittleEndian.Uint32(item[:4]), nil
}

func (o *OVMF) Size() int {
	return len(o.data)
}

func (o *OVMF) EndGPA() int {
	return o.GPA() + o.Size()
}

func (o *OVMF) HasMetadataSection(sectionType SectionType) bool {
	for _, item := range o.metadataItems {
		if SectionType(item.SectionTypeInt) == sectionType {
			return true
		}
	}
	return false
}

func (o *OVMF) IsSevHashesTableSupported() bool {
	_, ok := o.table[SEV_HASH_TABLE_RV_GUID]
	return ok && o.SevHashesTableGPA() != 0
}

func (o *OVMF) SevHashesTableGPA() uint32 {
	entry, ok := o.table[SEV_HASH_TABLE_RV_GUID]
	if !ok {
		return 0
	}
	return binary.LittleEndian.Uint32(entry[:4])
}

func (o *OVMF) parseFooterTable() error {
	o.table = make(map[string][]byte)
	size := len(o.data)
	entryHeaderSize := binary.Size(FooterTableEntry{})

	footerTableStartIdx := size - 32 - entryHeaderSize
	footerRaw := o.data[footerTableStartIdx:]

	footer, err := NewFooterTableEntry(footerRaw)
	if err != nil {
		return fmt.Errorf("parsing FooterTableEntry: %w", err)
	}

	expectedFooterGUID, err := uuid.Parse(OVMF_TABLE_FOOTER_GUID)
	if err != nil {
		return err
	}

	guidBytesLE := LittleEndianBytes(expectedFooterGUID)

	if !bytes.Equal(footer.Guid[:], guidBytesLE[:]) {
		return fmt.Errorf("invalid footer GUID <%x> expected <%x>", footer.Guid, guidBytesLE)
	}

	tableSize := footer.Size - uint16(entryHeaderSize)

	tableBytes := o.data[footerTableStartIdx-int(tableSize) : footerTableStartIdx]

	for len(tableBytes) >= entryHeaderSize {
		entry, err := NewFooterTableEntry(tableBytes[len(tableBytes)-entryHeaderSize:])
		if err != nil {
			return fmt.Errorf("parsing FooterTableEntry 2: %w", err)
		}

		if entry.Size < uint16(entryHeaderSize) {
			return errors.New("invalid entry size")
		}

		guidLE := LittleEndianBytes(entry.Guid)
		uuid, err := uuid.FromBytes(guidLE[:])
		if err != nil {
			return fmt.Errorf("parsing GUID: %w", err)
		}

		entryData := tableBytes[len(tableBytes)-int(entry.Size) : len(tableBytes)-entryHeaderSize]

		o.table[uuid.String()] = entryData
		tableBytes = tableBytes[:len(tableBytes)-int(entry.Size)]
	}

	return nil
}

func (o *OVMF) parseSevMetadata() error {
	o.metadataItems = make([]MetadataSection, 0)

	entry, ok := o.table[OVMF_SEV_META_DATA_GUID]
	if !ok {
		return nil
	}

	offsetFromEnd := binary.LittleEndian.Uint32(entry[:4])
	headerStartIdx := len(o.data) - int(offsetFromEnd)
	var header MetadataHeader

	data := o.data[headerStartIdx:]
	err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &header)
	if err != nil {
		return err
	}

	if err := header.Verify(); err != nil {
		return fmt.Errorf("verifying header: %w", err)
	}

	items := o.data[headerStartIdx+binary.Size(MetadataHeader{}) : headerStartIdx+int(header.Size)]

	for i := 0; i < int(header.NumItems); i++ {
		offset := i * binary.Size(MetadataSection{})
		var item MetadataSection

		err := binary.Read(bytes.NewReader(items[offset:]), binary.LittleEndian, &item)
		if err != nil {
			return fmt.Errorf("reading MetadataSection at idx %x: %w", offset, err)
		}

		o.metadataItems = append(o.metadataItems, item)
	}

	return nil
}

type SVSM struct {
	OVMF
}

func NewSVSM(filename string, endAt int) (*SVSM, error) {
	ovmf, err := New(filename, endAt)
	if err != nil {
		return nil, err
	}
	return &SVSM{OVMF: ovmf}, nil
}

func (s *SVSM) SevEsResetEip() (uint32, error) {
	entry, ok := s.table[SVSMInfoGUID]
	if !ok {
		return 0, errors.New("can't find SVSM_INFO_GUID entry in SVSM table")
	}
	return binary.LittleEndian.Uint32(entry[:4]) + uint32(s.GPA()), nil
}

func reverseBytes(bytes []byte) []byte {
	length := len(bytes)
	reversed := make([]byte, length)
	for i := range bytes {
		reversed[i] = bytes[length-i-1]
	}
	return reversed
}
