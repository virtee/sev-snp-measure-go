package sevhashes

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"reflect"

	"github.com/google/uuid"
	"github.com/virtee/sev-snp-measure-go/ovmf"
)

const SHA256_DIGEST_SIZE = 32

var (
	SEV_HASH_TABLE_HEADER_GUID = "9438d606-4f22-4cc9-b479-a793d411fd21"
	SEV_KERNEL_ENTRY_GUID      = "4de79437-abd2-427f-b835-d5b172d2045b"
	SEV_INITRD_ENTRY_GUID      = "44baf731-3a2f-4bd7-9af1-41e29169781d"
	SEV_CMDLINE_ENTRY_GUID     = "97d02dd8-bd20-4c94-aa78-e7714d36ab2a"
)

func New(kernel, initrd, append string) (*SevHashes, error) {
	sh := &SevHashes{}

	kernelHash, err := hashFile(kernel)
	if err != nil {
		return nil, err
	}
	sh.KernelHash = kernelHash

	if initrd != "" {
		initrdHash, err := hashFile(initrd)
		if err != nil {
			return nil, err
		}
		sh.InitrdHash = initrdHash
	}

	var cmdline []byte
	if append != "" {
		cmdline = []byte(append + "\x00")
	} else {
		cmdline = []byte{0}
	}
	sh.CmdlineHash = sha256.Sum256(cmdline)

	return sh, nil
}

func NewPaddedSevHashTable(ht SevHashTable) PaddedSevHashTable {
	size := sizeofStruct(ht)
	paddingSize := (size+15) & ^15 - size
	return PaddedSevHashTable{
		Ht:      ht,
		Padding: make([]byte, paddingSize),
	}
}

type GuidLe [16]byte

func (g *GuidLe) FromStr(guidStr string) {
	u := uuid.MustParse(guidStr)
	*g = ovmf.LittleEndianBytes(u)
}

type Sha256Hash [SHA256_DIGEST_SIZE]byte

type SevHashTableEntry struct {
	Guid   GuidLe
	Length uint16
	Hash   Sha256Hash
}

type SevHashTable struct {
	Guid    GuidLe
	Length  uint16
	Cmdline SevHashTableEntry
	Initrd  SevHashTableEntry
	Kernel  SevHashTableEntry
}

type PaddedSevHashTable struct {
	Ht      SevHashTable
	Padding []byte
}

type SevHashes struct {
	KernelHash  Sha256Hash
	InitrdHash  Sha256Hash
	CmdlineHash Sha256Hash
}

func (sh *SevHashes) ConstructTable() []byte {
	ht := SevHashTable{
		Guid:   GuidLe{},
		Length: uint16(sizeofStruct(SevHashTable{})),
		Cmdline: SevHashTableEntry{
			Guid:   GuidLe{},
			Length: uint16(sizeofStruct(SevHashTableEntry{})),
			Hash:   sh.CmdlineHash,
		},
		Initrd: SevHashTableEntry{
			Guid:   GuidLe{},
			Length: uint16(sizeofStruct(SevHashTableEntry{})),
			Hash:   sh.InitrdHash,
		},
		Kernel: SevHashTableEntry{
			Guid:   GuidLe{},
			Length: uint16(sizeofStruct(SevHashTableEntry{})),
			Hash:   sh.KernelHash,
		},
	}

	ht.Guid.FromStr(SEV_HASH_TABLE_HEADER_GUID)
	ht.Cmdline.Guid.FromStr(SEV_CMDLINE_ENTRY_GUID)
	ht.Initrd.Guid.FromStr(SEV_INITRD_ENTRY_GUID)
	ht.Kernel.Guid.FromStr(SEV_KERNEL_ENTRY_GUID)

	pht := NewPaddedSevHashTable(ht)
	return toBytesLE(pht)
}

func (sh *SevHashes) ConstructPage(offset uint32) ([]byte, error) {
	if offset >= 4096 {
		return nil, fmt.Errorf("offset must be less than 4096")
	}

	hashesTable := sh.ConstructTable()
	page := make([]byte, 4096)
	copy(page[offset:], hashesTable)
	return page, nil
}

func toBytesLE(data interface{}) []byte {
	v := reflect.ValueOf(data)
	buf := new(bytes.Buffer)

	var writeField func(reflect.Value)
	writeField = func(field reflect.Value) {
		switch field.Kind() {
		case reflect.Struct:
			for i := 0; i < field.NumField(); i++ {
				writeField(field.Field(i))
			}
		case reflect.Array, reflect.Slice:
			if field.Type().Elem().Kind() == reflect.Uint8 {
				binary.Write(buf, binary.LittleEndian, field.Interface())
			} else {
				for i := 0; i < field.Len(); i++ {
					writeField(field.Index(i))
				}
			}
		case reflect.Uint16:
			binary.Write(buf, binary.LittleEndian, uint16(field.Uint()))
		case reflect.Uint32:
			binary.Write(buf, binary.LittleEndian, uint32(field.Uint()))
		case reflect.Uint64:
			binary.Write(buf, binary.LittleEndian, uint64(field.Uint()))
		default:
			fmt.Printf("Unhandled type: %v\n", field.Kind())
		}
	}

	writeField(v)
	return buf.Bytes()
}

func sizeofStruct(v interface{}) int {
	return int(reflect.TypeOf(v).Size())
}

func hashFile(filename string) (Sha256Hash, error) {
	f, err := os.Open(filename)
	if err != nil {
		return Sha256Hash{}, err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return Sha256Hash{}, err
	}

	var hash Sha256Hash
	copy(hash[:], h.Sum(nil))
	return hash, nil
}
