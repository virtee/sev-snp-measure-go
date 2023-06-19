/*
- Guest Context (GCTX).
- VM Save Area (VMSA).
- Reverse Map Table (RMP).
- Guest Physical Address (GPA).
*/
package gctx

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"errors"
)

const (
	VMSA_GPA = 0xFFFFFFFFF000
	LD_SIZE  = sha512.Size384
)

// GCTX represents a SNP Guest Context.
// VMSA page is recorded in the RMP table with GPA (u64)(-1).
// However, the address is page-aligned, and also all the bits above 51 are cleared.
type GCTX struct {
	// ld is the launch digest of the guest.
	ld []byte
}

func New(seed []byte) *GCTX {
	return &GCTX{
		ld: seed,
	}
}

// LD returns the launch digest of the guest.
func (g *GCTX) LD() []byte {
	return g.ld
}

// update extends the current launch digest with the hash of a page.
// The hash also includes the page type, GPA, and permissions.
func (g *GCTX) update(pageType byte, gpa uint64, contents []byte) error {
	if len(contents) != LD_SIZE {
		return errors.New("invalid content size")
	}
	pageInfoLen := 0x70
	isImi := 0
	vmpl3Perms := 0
	vmpl2Perms := 0
	vmpl1Perms := 0

	// SNP spec 8.17.2 Table 67 Layout of the PAGE_INFO structure
	pageInfo := append(g.ld, contents...)

	pageInfo = binary.LittleEndian.AppendUint16(pageInfo, uint16(pageInfoLen))
	pageInfo = append(pageInfo, pageType, byte(isImi), byte(vmpl3Perms), byte(vmpl2Perms), byte(vmpl1Perms), byte(0))
	pageInfo = binary.LittleEndian.AppendUint64(pageInfo, gpa)

	if len(pageInfo) != pageInfoLen {
		return errors.New("invalid page info length")
	}

	// Update the launch digest
	h := sha512.New384()
	h.Write(pageInfo)
	g.ld = h.Sum(nil)

	return nil
}

func (g *GCTX) UpdateVmsaPage(data []byte) error {
	if len(data) != 4096 {
		return errors.New("invalid data length")
	}
	h := sha512.New384()
	h.Write(data)
	hash := h.Sum(nil)
	return g.update(0x02, VMSA_GPA, hash)
}

// UpdateZeroPages extends the current launch digest with the hash of a page containing only zeros. Pagetype is set to 0x03.
func (g *GCTX) UpdateZeroPages(gpa uint64, lengthBytes int) error {
	if lengthBytes%4096 != 0 {
		return errors.New("invalid length")
	}
	offset := 0
	for offset < lengthBytes {
		if err := g.update(0x03, gpa+uint64(offset), bytes.Repeat([]byte{0x00}, LD_SIZE)); err != nil {
			return err
		}
		offset += 4096
	}
	return nil
}

// UpdateSecretsPage extends the current launch digest with the hash of a page containing only zeros. Pagetype is set to 0x05.
func (g *GCTX) UpdateSecretsPage(gpa uint64) error {
	return g.update(0x05, gpa, bytes.Repeat([]byte{0x00}, LD_SIZE))
}

// UpdateSecretsPage extends the current launch digest with the hash of a page containing only zeros. Pagetype is set to 0x06.
func (g *GCTX) UpdateCpuidPage(gpa uint64) error {
	return g.update(0x06, gpa, bytes.Repeat([]byte{0x00}, LD_SIZE))
}
