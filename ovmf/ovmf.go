package ovmf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/google/uuid"
)

type SectionType int

const (
	SNPSECMEM SectionType = iota + 1
	SNPSecrets
	CPUID
	SNPKernelHashes SectionType = 0x10

	FOUR_GB                 = 0x100000000
	OVMF_TABLE_FOOTER_GUID  = "96b582de-1fb2-45f7-baea-a366c55a082d"
	SEV_HASH_TABLE_RV_GUID  = "7255371f-3a3b-4b04-927b-1da6efa8d454"
	SEV_ES_RESET_BLOCK_GUID = "00f771de-1a7e-4fcb-890e-68c77e2fb44e"
	OVMF_SEV_META_DATA_GUID = "dc886566-984a-4798-a75e-5585a7bf67cc"
)

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
	GPA            uint32
	Size           uint32
	SectionTypeInt uint32
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
	case SNPSECMEM, SNPSecrets, CPUID, SNPKernelHashes:
		return st, nil
	default:
		return -1, fmt.Errorf("unknown OVMF metadata section type: %d", st)
	}
}

type OVMF struct {
	data          []byte
	table         map[string][]byte
	metadataItems []MetadataSection
}

// func New() *OVMF {
// 	return &OVMF{}
// }

func New(filename string) (*OVMF, error) {
	ovmf := &OVMF{}

	path, err := os.Getwd()
	if err != nil {
		log.Println(err)
	}
	fmt.Println(path)
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	ovmf.data = data

	err = ovmf.parseFooterTable()
	if err != nil {
		return nil, fmt.Errorf("parsing footer table: %w", err)
	}

	err = ovmf.parseSevMetadata()
	if err != nil {
		return nil, fmt.Errorf("parsing SEV metadata: %w", err)
	}

	return ovmf, nil
}

func (o *OVMF) Data() []byte {
	return o.data
}

func (o *OVMF) GPA() int {
	return FOUR_GB - len(o.data)
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
			return errors.New("Invalid entry size")
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

func LittleEndianBytes(bytes [16]byte) [16]byte {
	part1 := reverseBytes(bytes[:4])
	part2 := reverseBytes(bytes[4:6])
	part3 := reverseBytes(bytes[6:8])
	part4 := bytes[8:]

	return [16]byte(append(append(append(part1, part2...), part3...), part4...))
}

func reverseBytes(bytes []byte) []byte {
	length := len(bytes)
	reversed := make([]byte, length)
	for i := range bytes {
		reversed[i] = bytes[length-i-1]
	}
	return reversed
}
