/*
Copyright Edgeless Systems GmbH
Copyright 2022- IBM Inc. All rights reserved
SPDX-License-Identifier: Apache-2.0
*/
package guest

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/virtee/sev-snp-measure-go/cpuid"
	"github.com/virtee/sev-snp-measure-go/gctx"
	"github.com/virtee/sev-snp-measure-go/ovmf"
	"github.com/virtee/sev-snp-measure-go/sevhashes"
	"github.com/virtee/sev-snp-measure-go/vmmtypes"
	"github.com/virtee/sev-snp-measure-go/vmsa"
)

const PAGE_MASK = 0xfff

//go:generate stringer -type=SevMode
type SevMode int

const (
	SEV SevMode = iota
	SEV_ES
	SEV_SNP
	SEV_SNP_SVSM
)

func SevModeFromString(s string) SevMode {
	s = strings.ToUpper(s)
	switch s {
	case SEV.String():
		return SEV
	case "SEVES", "SEV-ES":
		return SEV_ES
	case "SNP", "SEV-SNP":
		return SEV_SNP
	case "SNP:SVSM", "SEV-SNP:SVSM":
		return SEV_SNP_SVSM
	default:
		return -1
	}
}

// LaunchDigestFromMetadataWrapper calculates a launch digest from a MetadataWrapper object.
func LaunchDigestFromMetadataWrapper(wrapper ovmf.MetadataWrapper, guestFeatures uint64, vcpuCount int, vmmtype vmmtypes.VMMType, vcpu_type string) ([]byte, error) {
	return launchDigest(wrapper.MetadataItems, wrapper.ResetEIP, guestFeatures, vcpuCount, wrapper.OVMFHash, vmmtype, vcpu_type)
}

// LaunchDigestFromOVMF calculates a launch digest from an OVMF object and an ovmfHash.
func LaunchDigestFromOVMF(ovmfObj ovmf.OVMF, guestFeatures uint64, vcpuCount int, ovmfHash []byte, vmmtype vmmtypes.VMMType, vcpu_type string) ([]byte, error) {
	resetEIP, err := ovmfObj.SevESResetEIP()
	if err != nil {
		return nil, fmt.Errorf("getting reset EIP: %w", err)
	}
	return launchDigest(ovmfObj.MetadataItems(), resetEIP, guestFeatures, vcpuCount, ovmfHash, vmmtype, vcpu_type)
}

func CalcLaunchDigest(mode SevMode, vcpus int, vcpuSig uint64, ovmfFile string,
	kernel string, initrd string, append string, guestFeatures uint64, snpOvmfHashStr string,
	vmmType vmmtypes.VMMType, dumpVMSA bool, svsmFile string,
	ovmfVarsSize int,
) ([]byte, error) {
	switch mode {
	case SEV_SNP:
		return snpCalcLaunchDigest(vcpus, vcpuSig, ovmfFile, kernel, initrd, append, guestFeatures,
			snpOvmfHashStr, vmmType, dumpVMSA)
	case SEV_ES:
		return sevesCalcLaunchDigest(vcpus, vcpuSig, ovmfFile, kernel, initrd, append, vmmType, dumpVMSA)
	case SEV:
		return sevCalcLaunchDigest(ovmfFile, kernel, initrd, append)
	case SEV_SNP_SVSM:
		if vmmType != vmmtypes.QEMU {
			return nil, errors.New("SVSM mode is only implemented for QEMU")
		}
		return svsmCalcLaunchDigest(vcpus, vcpuSig, ovmfFile, ovmfVarsSize, svsmFile, dumpVMSA)
	default:
		return nil, errors.New("unknown SEV mode")
	}
}

func CalcSnpOvmfHash(ovmfFile string) ([]byte, error) {
	ovmfObj, err := ovmf.New(ovmfFile, 0)
	if err != nil {
		return nil, err
	}

	gctx := gctx.New(nil)
	if err := gctx.UpdateNormalPages(uint64(ovmfObj.GPA()), ovmfObj.Data()); err != nil {
		return nil, err
	}
	return gctx.LD(), nil
}

func OVMFHash(ovmfObj ovmf.OVMF) ([]byte, error) {
	gctx := gctx.New(nil)
	if err := gctx.UpdateNormalPages(uint64(ovmfObj.GPA()), ovmfObj.Data()); err != nil {
		return nil, fmt.Errorf("updating normal pages: %w", err)
	}
	return gctx.LD(), nil
}

// launchDigest calculates the launch digest from metadata and ovmfHash for a SNP guest.
func launchDigest(metadata []ovmf.MetadataSection, resetEIP uint32, guestFeatures uint64, vcpuCount int, ovmfHash []byte, vmmtype vmmtypes.VMMType, vcpu_type string) ([]byte, error) {
	guestCtx := gctx.New(ovmfHash)

	ovmfObj := ovmf.NewFromMetadataItems(metadata)

	if err := snpUpdateMetadataPages(guestCtx, ovmfObj, nil, vmmtype); err != nil {
		return nil, fmt.Errorf("updating metadata pages: %w", err)
	}

	vcpu_sig, ok := cpuid.CpuSigs[vcpu_type]
	if !ok {
		fmt.Printf("Failed to find VCPU signature for vcpu_type %s\n", vcpu_type)
		vcpu_sig = 0
	}

	vmsaObj, err := vmsa.New(resetEIP, guestFeatures, uint64(vcpu_sig), vmmtype)
	if err != nil {
		return nil, fmt.Errorf("creating VMSA: %w", err)
	}

	pages, err := vmsaObj.Pages(vcpuCount)
	if err != nil {
		return nil, fmt.Errorf("getting VMSA pages: %w", err)
	}
	for _, desc := range pages {
		err := guestCtx.UpdateVmsaPage(desc)
		if err != nil {
			return nil, fmt.Errorf("updating VMSA page: %w", err)
		}
	}
	return guestCtx.LD(), nil
}

func snpUpdateKernelHashes(gctx *gctx.GCTX, ovmf ovmf.OVMF, sevHashes *sevhashes.SevHashes, gpa uint64, size int) error {
	if sevHashes != nil {
		sevHashesTableGPA := ovmf.SevHashesTableGPA()
		offsetInPage := sevHashesTableGPA & PAGE_MASK
		sevHashesPage, err := sevHashes.ConstructPage(offsetInPage)
		if err != nil {
			return err
		}
		if size != len(sevHashesPage) {
			return errors.New("size mismatch in snpUpdateKernelHashes")
		}
		return gctx.UpdateNormalPages(gpa, sevHashesPage)
	}
	return gctx.UpdateZeroPages(gpa, size)
}

func snpUpdateSection(desc ovmf.MetadataSection, gctx *gctx.GCTX, ovmfObj ovmf.OVMF,
	sevHashes *sevhashes.SevHashes, vmmType vmmtypes.VMMType,
) error {
	sectionType, err := desc.SectionType()
	if err != nil {
		return err
	}
	switch sectionType {
	case ovmf.SNPSECMEM:
		return gctx.UpdateZeroPages(uint64(desc.GPA), int(desc.Size))
	case ovmf.SNPSecrets:
		return gctx.UpdateSecretsPage(uint64(desc.GPA))
	case ovmf.CPUID:
		if vmmType != vmmtypes.EC2 {
			return gctx.UpdateCpuidPage(uint64(desc.GPA))
		}
	case ovmf.SNPKernelHashes:
		return snpUpdateKernelHashes(gctx, ovmfObj, sevHashes, uint64(desc.GPA), int(desc.Size))
	case ovmf.SVSMCAA:
		return gctx.UpdateZeroPages(uint64(desc.GPA), int(desc.Size))
	default:
		return errors.New("unknown OVMF metadata section type")
	}
	return nil
}

func snpUpdateMetadataPages(gctx *gctx.GCTX, ovmfObj ovmf.OVMF, sevHashes *sevhashes.SevHashes, vmmType vmmtypes.VMMType) error {
	for _, desc := range ovmfObj.MetadataItems() {
		if err := snpUpdateSection(desc, gctx, ovmfObj, sevHashes, vmmType); err != nil {
			return err
		}
	}

	if vmmType == vmmtypes.EC2 {
		for _, desc := range ovmfObj.MetadataItems() {
			sectionType, err := desc.SectionType()
			if err != nil {
				return err
			}
			if sectionType == ovmf.CPUID {
				if err := gctx.UpdateCpuidPage(uint64(desc.GPA)); err != nil {
					return err
				}
			}
		}
	}

	if sevHashes != nil && !ovmfObj.HasMetadataSection(ovmf.SNPKernelHashes) {
		return errors.New("kernel specified but OVMF metadata doesn't include SNP_KERNEL_HASHES section")
	}

	return nil
}

func snpCalcLaunchDigest(vcpus int, vcpuSig uint64, ovmfFile string,
	kernel string, initrd string, append string, guestFeatures uint64,
	ovmfHashStr string, vmmType vmmtypes.VMMType, dumpVMSA bool,
) ([]byte, error) {
	var gctxObj *gctx.GCTX

	ovmfObj, err := ovmf.New(ovmfFile, 0)
	if err != nil {
		return nil, err
	}

	if ovmfHashStr != "" {
		ovmfHash, err := hex.DecodeString(ovmfHashStr)
		if err != nil {
			return nil, err
		}
		gctxObj = gctx.New(ovmfHash)
	} else {
		gctxObj = gctx.New(nil)
		if err := gctxObj.UpdateNormalPages(uint64(ovmfObj.GPA()), ovmfObj.Data()); err != nil {
			return nil, err
		}
	}

	var sevHashes *sevhashes.SevHashes
	if kernel != "" {
		sevHashes, err = sevhashes.New(kernel, initrd, append)
		if err != nil {
			return nil, err
		}
	}

	if err := snpUpdateMetadataPages(gctxObj, ovmfObj, sevHashes, vmmType); err != nil {
		return nil, err
	}

	apEIP, err := ovmfObj.SevESResetEIP()
	if err != nil {
		return nil, err
	}
	vmsaObj, err := vmsa.New(apEIP, guestFeatures, vcpuSig, vmmType)
	if err != nil {
		return nil, err
	}

	pages, err := vmsaObj.Pages(vcpus)
	if err != nil {
		return nil, err
	}

	for i, page := range pages {
		if err := gctxObj.UpdateVmsaPage(page); err != nil {
			return nil, err
		}
		if dumpVMSA {
			if err := dumpVMSAPage(page, i); err != nil {
				return nil, err
			}
		}
	}

	return gctxObj.LD(), nil
}

func svsmCalcLaunchDigest(vcpus int, vcpuSig uint64, ovmfFile string, ovmfVarsSize int, svsmFile string,
	dumpVMSA bool,
) ([]byte, error) {
	gctx := gctx.New(nil)

	ovmfObj, err := ovmf.New(ovmfFile, 0)
	if err != nil {
		return nil, fmt.Errorf("creating OVMF object: %w", err)
	}

	svsmObj, err := ovmf.NewSVSM(svsmFile, ovmfObj.GPA()-ovmfVarsSize)
	if err != nil {
		return nil, fmt.Errorf("creating SVSM object: %w", err)
	}

	eip, err := svsmObj.SevESResetEIP()
	if err != nil {
		return nil, fmt.Errorf("getting reset EIP: %w", err)
	}

	if err := gctx.UpdateNormalPages(uint64(ovmfObj.GPA()), ovmfObj.Data()); err != nil {
		return nil, fmt.Errorf("updating OVMF normal pages: %w", err)
	}
	if err := gctx.UpdateNormalPages(uint64(svsmObj.GPA()), svsmObj.Data()); err != nil {
		return nil, fmt.Errorf("updating SVSM normal pages: %w", err)
	}

	if err := snpUpdateMetadataPages(gctx, svsmObj.OVMF, nil, vmmtypes.QEMU); err != nil {
		return nil, fmt.Errorf("updating metadata pages: %w", err)
	}

	vmsaObj, err := vmsa.NewSVSM(eip, vcpuSig, vmmtypes.QEMU)
	if err != nil {
		return nil, fmt.Errorf("creating VMSA SVSM object: %w", err)
	}

	pages, err := vmsaObj.Pages(vcpus)
	if err != nil {
		return nil, fmt.Errorf("getting VMSA pages: %w", err)
	}

	for i, page := range pages {
		if err := gctx.UpdateVmsaPage(page); err != nil {
			return nil, fmt.Errorf("updating VMSA page: %w", err)
		}
		if dumpVMSA {
			if err := dumpVMSAPage(page, i); err != nil {
				return nil, fmt.Errorf("dumping VMSA page: %w", err)
			}
		}
	}

	return gctx.LD(), nil
}

func sevesCalcLaunchDigest(vcpus int, vcpuSig uint64, ovmfFile string, kernel string, initrd string, append string,
	vmmType vmmtypes.VMMType, dumpVMSA bool,
) ([]byte, error) {
	ovmfObj, err := ovmf.New(ovmfFile, 0)
	if err != nil {
		return nil, err
	}

	launchHash := sha256.New()
	launchHash.Write(ovmfObj.Data())

	if kernel != "" {
		if !ovmfObj.IsSevHashesTableSupported() {
			return nil, errors.New("kernel specified but OVMF doesn't support kernel/initrd/cmdline measurement")
		}
		sevHashes, err := sevhashes.New(kernel, initrd, append)
		if err != nil {
			return nil, err
		}
		sevHashesTable := sevHashes.ConstructTable()
		launchHash.Write(sevHashesTable)
	}

	apEIP, err := ovmfObj.SevESResetEIP()
	if err != nil {
		return nil, err
	}
	vmsaObj, err := vmsa.New(apEIP, 0, vcpuSig, vmmType)
	if err != nil {
		return nil, err
	}

	pages, err := vmsaObj.Pages(vcpus)
	if err != nil {
		return nil, err
	}

	for i, page := range pages {
		launchHash.Write(page)
		if dumpVMSA {
			if err := dumpVMSAPage(page, i); err != nil {
				return nil, err
			}
		}
	}

	return launchHash.Sum(nil), nil
}

func sevCalcLaunchDigest(ovmfFile string, kernel string, initrd string, append string) ([]byte, error) {
	ovmfObj, err := ovmf.New(ovmfFile, 0)
	if err != nil {
		return nil, err
	}

	launchHash := sha256.New()
	launchHash.Write(ovmfObj.Data())

	if kernel != "" {
		if !ovmfObj.IsSevHashesTableSupported() {
			return nil, errors.New("kernel specified but OVMF doesn't support kernel/initrd/cmdline measurement")
		}
		sevHashes, err := sevhashes.New(kernel, initrd, append)
		if err != nil {
			return nil, err
		}
		sevHashesTable := sevHashes.ConstructTable()
		launchHash.Write(sevHashesTable)
	}

	return launchHash.Sum(nil), nil
}

func dumpVMSAPage(page []byte, index int) error {
	return os.WriteFile(fmt.Sprintf("vmsa%d.bin", index), page, 0o644)
}
