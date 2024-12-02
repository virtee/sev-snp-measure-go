/*
Copyright Edgeless Systems GmbH
Copyright 2022- IBM Inc. All rights reserved

SPDX-License-Identifier: Apache-2.0
*/

/*
- Virtual Machine Save Area (VMSA).
- Virtual Machine Control Block (VMCB).
*/
package vmsa

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/virtee/sev-snp-measure-go/vmmtypes"
)

const (
	BspEIP uint32 = 0xfffffff0
)

// VmcbSeg represents a VMCB Segment (struct vmcb_seg in the linux kernel).
type VmcbSeg struct {
	Selector uint16
	Attrib   uint16
	Limit    uint32
	Base     uint64
}

// VMSA page
//
// The names of the fields are taken from struct sev_es_work_area in the linux kernel:
// https://github.com/AMDESE/linux/blob/sev-snp-v12/arch/x86/include/asm/svm.h#L318
// (following the definitions in AMD APM Vol 2 Table B-4)
type SevEsSaveArea struct {
	Es               VmcbSeg
	Cs               VmcbSeg
	Ss               VmcbSeg
	Ds               VmcbSeg
	Fs               VmcbSeg
	Gs               VmcbSeg
	Gdtr             VmcbSeg
	Ldtr             VmcbSeg
	Idtr             VmcbSeg
	Tr               VmcbSeg
	Vmpl0Ssp         uint64
	Vmpl1Ssp         uint64
	Vmpl2Ssp         uint64
	Vmpl3Ssp         uint64
	UCet             uint64
	Reserved1        [2]uint8
	Vmpl             uint8
	Cpl              uint8
	Reserved2        [4]uint8
	Efer             uint64
	Reserved3        [104]uint8
	Xss              uint64
	Cr4              uint64
	Cr3              uint64
	Cr0              uint64
	Dr7              uint64
	Dr6              uint64
	Rflags           uint64
	Rip              uint64
	Dr0              uint64
	Dr1              uint64
	Dr2              uint64
	Dr3              uint64
	Dr0AddrMask      uint64
	Dr1AddrMask      uint64
	Dr2AddrMask      uint64
	Dr3AddrMask      uint64
	Reserved4        [24]uint8
	Rsp              uint64
	SCet             uint64
	Ssp              uint64
	IsstAddr         uint64
	Rax              uint64
	Star             uint64
	Lstar            uint64
	Cstar            uint64
	Sfmask           uint64
	KernelGsBase     uint64
	SysenterCs       uint64
	SysenterEsp      uint64
	SysenterEip      uint64
	Cr2              uint64
	Reserved5        [32]uint8
	GPat             uint64
	Dbgctrl          uint64
	BrFrom           uint64
	BrTo             uint64
	LastExcpFrom     uint64
	LastExcpTo       uint64
	Reserved7        [80]uint8
	Pkru             uint32
	Reserved8        [20]uint8
	Reserved9        uint64
	Rcx              uint64
	Rdx              uint64
	Rbx              uint64
	Reserved10       uint64
	Rbp              uint64
	Rsi              uint64
	Rdi              uint64
	R8               uint64
	R9               uint64
	R10              uint64
	R11              uint64
	R12              uint64
	R13              uint64
	R14              uint64
	R15              uint64
	Reserved11       [16]uint8
	GuestExitInfo1   uint64
	GuestExitInfo2   uint64
	GuestExitIntInfo uint64
	GuestNrip        uint64
	SevFeatures      uint64
	VintrCtrl        uint64
	GuestExitCode    uint64
	VirtualTom       uint64
	TlbId            uint64
	PcpuId           uint64
	EventInj         uint64
	Xcr0             uint64
	Reserved12       [16]uint8
	X87Dp            uint64
	Mxcsr            uint32
	X87Ftw           uint16
	X87Fsw           uint16
	X87Fcw           uint16
	X87Fop           uint16
	X87Ds            uint16
	X87Cs            uint16
	X87Rip           uint64
	FpregX87         [80]uint8
	FpregXmm         [256]uint8
	FpregYmm         [256]uint8
	Unused           [2448]uint8
}

func BuildSaveArea(eip uint32, guestFeatures uint64, vcpuSig uint64, vmmType vmmtypes.VMMType) (SevEsSaveArea, error) {
	var csFlags, ssFlags, trFlags uint16
	var rdx uint64
	var mxcsr uint32
	var fcw uint16

	switch vmmType {
	case vmmtypes.QEMU:
		csFlags = 0x9b
		ssFlags = 0x93
		trFlags = 0x8b
		rdx = vcpuSig
		mxcsr = 0x1f80
		fcw = 0x37f
	case vmmtypes.EC2:
		csFlags = 0x9b
		if eip == 0xfffffff0 {
			csFlags = 0x9a
		}
		ssFlags = 0x92
		trFlags = 0x83
		rdx = 0
		mxcsr = 0
		fcw = 0
	default:
		return SevEsSaveArea{}, errors.New("unknown VMM type")
	}

	return SevEsSaveArea{
		Es:          VmcbSeg{0, 0x93, 0xffff, 0},
		Cs:          VmcbSeg{0xf000, csFlags, 0xffff, uint64(eip & 0xffff0000)},
		Ss:          VmcbSeg{0, ssFlags, 0xffff, 0},
		Ds:          VmcbSeg{0, 0x93, 0xffff, 0},
		Fs:          VmcbSeg{0, 0x93, 0xffff, 0},
		Gs:          VmcbSeg{0, 0x93, 0xffff, 0},
		Gdtr:        VmcbSeg{0, 0, 0xffff, 0},
		Idtr:        VmcbSeg{0, 0, 0xffff, 0},
		Ldtr:        VmcbSeg{0, 0x82, 0xffff, 0},
		Tr:          VmcbSeg{0, trFlags, 0xffff, 0},
		Efer:        0x1000, // KVM enables EFER_SVME.
		Cr4:         0x40,   // KVM enables X86_CR4_MCE.
		Cr0:         0x10,
		Dr7:         0x400,
		Dr6:         0xffff0ff0,
		Rflags:      0x2,
		Rip:         uint64(eip & 0xffff),
		GPat:        0x7040600070406, // PAT MSR: See AMD APM Vol 2, Section A.3.
		Rdx:         rdx,
		SevFeatures: guestFeatures, // Documentation: https://github.com/virtee/sev-snp-measure/pull/32/files#diff-b335630551682c19a781afebcf4d07bf978fb1f8ac04c6bf87428ed5106870f5R125.
		Xcr0:        0x1,
		Mxcsr:       mxcsr,
		X87Fcw:      fcw,
	}, nil
}

type VMSA struct {
	BspSaveArea SevEsSaveArea
	ApSaveArea  SevEsSaveArea
}

func New(apEip uint32, guestFeatures uint64, vcpuSig uint64, vmmType vmmtypes.VMMType) (VMSA, error) {
	bspSaveArea, err := BuildSaveArea(BspEIP, guestFeatures, vcpuSig, vmmType)
	if err != nil {
		return VMSA{}, err
	}
	var apSaveArea SevEsSaveArea
	if apEip != 0 {
		apSaveArea, err = BuildSaveArea(apEip, guestFeatures, vcpuSig, vmmType)

		if err != nil {
			return VMSA{}, err
		}
	}
	return VMSA{BspSaveArea: bspSaveArea, ApSaveArea: apSaveArea}, nil
}

func (v VMSA) Pages(vcpus int) ([][]byte, error) {
	var result [][]byte
	for i := 0; i < vcpus; i++ {
		if i == 0 {
			bspSavedAreaRaw := bytes.NewBuffer([]byte{})
			if err := binary.Write(bspSavedAreaRaw, binary.LittleEndian, &v.BspSaveArea); err != nil {
				return nil, fmt.Errorf("writing bsp saved area: %w", err)
			}
			result = append(result, bspSavedAreaRaw.Bytes())
		} else {
			apSavedAreaRaw := bytes.NewBuffer([]byte{})
			if err := binary.Write(apSavedAreaRaw, binary.LittleEndian, &v.ApSaveArea); err != nil {
				return nil, fmt.Errorf("writing ap saved area: %w", err)
			}
			result = append(result, apSavedAreaRaw.Bytes())
		}
	}
	return result, nil
}

// VMSA_SVSM represents the VMSA for Secure Virtual Machine Secure Monitor
type VMSA_SVSM struct {
	SaveArea SevEsSaveArea
}

func NewSVSM(apEip uint32, vcpuSig uint64, vmmType vmmtypes.VMMType) (VMSA_SVSM, error) {
	sevFeatures := uint64(0x1)
	saveArea, err := BuildSaveAreaSVSM(apEip, sevFeatures, vcpuSig, vmmType)
	if err != nil {
		return VMSA_SVSM{}, err
	}
	return VMSA_SVSM{SaveArea: saveArea}, nil
}

func BuildSaveAreaSVSM(eip uint32, sevFeatures uint64, vcpuSig uint64, vmmType vmmtypes.VMMType) (SevEsSaveArea, error) {
	var mxcsr uint32
	var fcw uint16

	if vmmType == vmmtypes.QEMU {
		mxcsr = 0x1f80
		fcw = 0x37f
	} else {
		mxcsr = 0
		fcw = 0
	}

	return SevEsSaveArea{
		Es:          VmcbSeg{16, 0xc93, 0xffffffff, 0},
		Cs:          VmcbSeg{8, 0xc9b, 0xffffffff, 0},
		Ss:          VmcbSeg{16, 0xc93, 0xffffffff, 0},
		Ds:          VmcbSeg{16, 0xc93, 0xffffffff, 0},
		Fs:          VmcbSeg{16, 0xc93, 0xffffffff, 0},
		Gs:          VmcbSeg{0, 0x093, 0xffff, 0},
		Gdtr:        VmcbSeg{0, 0, 0xffff, 0},
		Idtr:        VmcbSeg{0, 0, 0xffff, 0},
		Ldtr:        VmcbSeg{0, 0x82, 0xffff, 0},
		Tr:          VmcbSeg{0, 0x8b, 0xffff, 0},
		Efer:        0x1000,
		Cr4:         0x40,
		Cr0:         0x11,
		Dr7:         0x400,
		Dr6:         0xffff0ff0,
		Rflags:      0x2,
		Rip:         uint64(eip),
		GPat:        0x7040600070406,
		Rdx:         vcpuSig,
		SevFeatures: sevFeatures,
		Xcr0:        0x1,
		Mxcsr:       mxcsr,
		X87Fcw:      fcw,
	}, nil
}

func (v VMSA_SVSM) Pages(vcpus int) ([][]byte, error) {
	var result [][]byte
	for i := 0; i < vcpus; i++ {
		savedAreaRaw := bytes.NewBuffer([]byte{})
		if err := binary.Write(savedAreaRaw, binary.LittleEndian, &v.SaveArea); err != nil {
			return nil, fmt.Errorf("writing SVSM saved area: %w", err)
		}
		result = append(result, savedAreaRaw.Bytes())
	}
	return result, nil
}
