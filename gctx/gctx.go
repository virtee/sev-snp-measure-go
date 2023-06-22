/*
Copyright Edgeless Systems GmbH
Copyright 2022- IBM Inc. All rights reserved

SPDX-License-Identifier: Apache-2.0
*/

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
	"fmt"
)

const (
	VMSA_GPA  = 0xFFFFFFFFF000
	LD_SIZE   = sha512.Size384
	PAGE_SIZE = 4096
)

// GCTX represents a SNP Guest Context.
// VMSA page is recorded in the RMP table with GPA (u64)(-1).
// However, the address is page-aligned, and also all the bits above 51 are cleared.
type GCTX struct {
	// ld is the launch digest of the guest.
	ld []byte
}

func New(seed []byte) *GCTX {
	if seed == nil {
		seed = bytes.Repeat([]byte{0x00}, LD_SIZE)
	}
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
	if len(data) != PAGE_SIZE {
		return errors.New("invalid data length")
	}
	h := sha512.New384()
	h.Write(data)
	hash := h.Sum(nil)
	return g.update(0x02, VMSA_GPA, hash)
}

// UpdateNormalPages extends the current launch digest with the hash of data.
// The hash is generated page by page. Pagetype is set to 0x01.
func (g *GCTX) UpdateNormalPages(startGpa uint64, data []byte) error {
	if len(data)%PAGE_SIZE != 0 {
		return errors.New("data length should be a multiple of 4096")
	}
	offset := 0
	for offset < len(data) {
		pageData := data[offset : offset+PAGE_SIZE]
		sha384hash := sha512.Sum384(pageData)
		err := g.update(0x01, startGpa+uint64(offset), sha384hash[:])
		if err != nil {
			return fmt.Errorf("updating page %d: %w", offset/PAGE_SIZE, err)
		}
		offset += PAGE_SIZE
	}
	return nil
}

// UpdateZeroPages extends the current launch digest with the hash of a page containing only zeros. Pagetype is set to 0x03.
func (g *GCTX) UpdateZeroPages(gpa uint64, lengthBytes int) error {
	if lengthBytes%PAGE_SIZE != 0 {
		return errors.New("invalid length")
	}
	offset := 0
	for offset < lengthBytes {
		if err := g.update(0x03, gpa+uint64(offset), bytes.Repeat([]byte{0x00}, LD_SIZE)); err != nil {
			return err
		}
		offset += PAGE_SIZE
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
