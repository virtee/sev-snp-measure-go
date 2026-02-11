/*
Copyright Edgeless Systems GmbH
Copyright 2022- IBM Inc. All rights reserved

SPDX-License-Identifier: Apache-2.0
*/

package guest

import (
	"errors"
	"fmt"

	"github.com/virtee/sev-snp-measure-go/cpuid"
	"github.com/virtee/sev-snp-measure-go/gctx"
	"github.com/virtee/sev-snp-measure-go/ovmf"
	"github.com/virtee/sev-snp-measure-go/vmmtypes"
	"github.com/virtee/sev-snp-measure-go/vmsa"
)

const PAGE_MASK = 0xfff

// LaunchDigestFromMetadataWrapper calculates a launch digest from a MetadataWrapper object.
func LaunchDigestFromMetadataWrapper(wrapper ovmf.MetadataWrapper, guestFeatures uint64, vcpuCount int, vmmtype vmmtypes.VMMType, vcpu_type string, kernel []byte, initrd []byte, cmdline string) ([]byte, error) {
	return launchDigest(wrapper.MetadataItems, wrapper.ResetEIP, guestFeatures, vcpuCount, wrapper.OVMFHash, vmmtype, vcpu_type, kernel, initrd, cmdline, wrapper.SevHashesTableGPA)
}

// LaunchDigestFromOVMF calculates a launch digest from an OVMF object and an ovmfHash.
func LaunchDigestFromOVMF(ovmfObj ovmf.OVMF, guestFeatures uint64, vcpuCount int, ovmfHash []byte, vmmtype vmmtypes.VMMType, vcpu_type string, kernel []byte, initrd []byte, cmdline string) ([]byte, error) {
	resetEIP, err := ovmfObj.SevESResetEIP()
	if err != nil {
		return nil, fmt.Errorf("getting reset EIP: %w", err)
	}

	sevHashesTableGPA, err := ovmfObj.SevHashesTableGPA()
	if err != nil {
		// Non-fatal: older OVMF may not have this
		sevHashesTableGPA = 0
	}

	return launchDigest(ovmfObj.MetadataItems(), resetEIP, guestFeatures, vcpuCount, ovmfHash, vmmtype, vcpu_type, kernel, initrd, cmdline, sevHashesTableGPA)
}

func OVMFHash(ovmfObj ovmf.OVMF) ([]byte, error) {
	gctx := gctx.New(nil)
	if err := gctx.UpdateNormalPages(uint64(ovmfObj.GPA()), ovmfObj.Data()); err != nil {
		return nil, fmt.Errorf("updating normal pages: %w", err)
	}
	return gctx.LD(), nil
}

// launchDigest calculates the launch digest from metadata and ovmfHash for a SNP guest.
func launchDigest(metadata []ovmf.MetadataSection, resetEIP uint32, guestFeatures uint64, vcpuCount int, ovmfHash []byte, vmmtype vmmtypes.VMMType, vcpu_type string, kernel []byte, initrd []byte, cmdline string, sevHashesTableGPA uint32) ([]byte, error) {
	guestCtx := gctx.New(ovmfHash)

	var sevHashes *ovmf.SevHashes
	if kernel != nil {
		var err error
		sevHashes, err = ovmf.NewSevHashes(kernel, initrd, cmdline)
		if err != nil {
			return nil, fmt.Errorf("creating SevHashes: %w", err)
		}
	}

	if err := snpUpdateMetadataPages(guestCtx, metadata, vmmtype, sevHashes, sevHashesTableGPA); err != nil {
		return nil, fmt.Errorf("updating metadata pages: %w", err)
	}

	// Allow empty vcpu_type for EC2 and GCE for backwards compatibility.
	// vcpuSig is ignored in BuildSaveArea.
	// TODO: once the project has a release pipeline consider a major release to break the API.
	if vmmtype == vmmtypes.EC2 || vmmtype == vmmtypes.GCE {
		vcpu_type = "EPYC"
	}

	cpuSig, ok := cpuid.CpuSigs[vcpu_type]
	if !ok {
		return nil, fmt.Errorf("failed to find VCPU signature for vcpu_type %q", vcpu_type)
	}
	vcpuSig := uint64(cpuSig)

	vmsaObj, err := vmsa.New(resetEIP, guestFeatures, vcpuSig, vmmtype)
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

func snpUpdateMetadataPages(gctx *gctx.GCTX, metadata []ovmf.MetadataSection, vmmType vmmtypes.VMMType, sevHashes *ovmf.SevHashes, sevHashesTableGPA uint32) error {
	hasKernelHashesSection := false
	for _, desc := range metadata {
		st, err := desc.SectionType()
		if err != nil {
			return fmt.Errorf("getting sectionType: %w", err)
		}
		if st == ovmf.SNPKernelHashes {
			hasKernelHashesSection = true
		}
		switch st {
		case ovmf.SNPSECMEM:
			if vmmType == vmmtypes.GCE {
				if err := gctx.UpdateUnmeasuredPages(uint64(desc.GPA), int(desc.Size)); err != nil {
					return fmt.Errorf("updating unmeasured pages: %w", err)
				}
			} else {
				if err := gctx.UpdateZeroPages(uint64(desc.GPA), int(desc.Size)); err != nil {
					return fmt.Errorf("updating zero pages: %w", err)
				}
			}
		case ovmf.SVSM_CAA:
			if err := gctx.UpdateZeroPages(uint64(desc.GPA), int(desc.Size)); err != nil {
				return fmt.Errorf("updating zero pages: %w", err)
			}
		case ovmf.SNPSecrets:
			if err := gctx.UpdateSecretsPage(uint64(desc.GPA)); err != nil {
				return fmt.Errorf("updating secrets page: %w", err)
			}
		case ovmf.CPUID:
			if vmmType != vmmtypes.EC2 {
				if err := gctx.UpdateCpuidPage(uint64(desc.GPA)); err != nil {
					return fmt.Errorf("updating cpuid page: %w", err)
				}
			}
		case ovmf.SNPKernelHashes:
			if sevHashes != nil {
				offset := int(sevHashesTableGPA) & PAGE_MASK
				page, err := sevHashes.ConstructPage(offset)
				if err != nil {
					return fmt.Errorf("constructing hash page: %w", err)
				}
				if err := gctx.UpdateNormalPages(uint64(desc.GPA), page); err != nil {
					return fmt.Errorf("updating hash page: %w", err)
				}
			} else {
				if err := gctx.UpdateZeroPages(uint64(desc.GPA), int(desc.Size)); err != nil {
					return fmt.Errorf("updating zero pages: %w", err)
				}
			}
		default:
			return errors.New("unknown OVMF metadata section type")
		}
	}

	if sevHashes != nil && !hasKernelHashesSection {
		return errors.New("kernel specified but OVMF metadata doesn't include SNP_KERNEL_HASHES section")
	}

	if vmmType == vmmtypes.EC2 {
		for _, desc := range metadata {
			st, err := desc.SectionType()
			if err != nil {
				return fmt.Errorf("getting sectionType: %w", err)
			}
			if st == ovmf.CPUID {
				if err := gctx.UpdateCpuidPage(uint64(desc.GPA)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
