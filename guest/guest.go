package guest

import (
	"errors"
	"fmt"

	"edgelesssys/sevsnpmeasure/gctx"
	"edgelesssys/sevsnpmeasure/ovmf"
	"edgelesssys/sevsnpmeasure/vmmtypes"
	"edgelesssys/sevsnpmeasure/vmsa"
)

// LaunchDigestFromOVMF calculates a launch digest from a MetadataWrapper object and an ovmfHash.
func LaunchDigestFromMetadataWrapper(wrapper ovmf.MetadataWrapper, vcpuCount int, ovmfHash []byte) ([]byte, error) {
	return launchDigest(wrapper.MetadataItems, wrapper.ResetEIP, vcpuCount, ovmfHash)
}

// LaunchDigestFromOVMF calculates a launch digest from an OVMF object and an ovmfHash.
func LaunchDigestFromOVMF(ovmfObj ovmf.OVMF, vcpuCount int, ovmfHash []byte) ([]byte, error) {
	resetEIP, err := ovmfObj.SevESResetEIP()
	if err != nil {
		return nil, fmt.Errorf("getting reset EIP: %w", err)
	}
	return launchDigest(ovmfObj.MetadataItems(), resetEIP, vcpuCount, ovmfHash)
}

func OVMFHash(ovmfObj ovmf.OVMF) ([]byte, error) {
	gctx := gctx.New(nil)
	if err := gctx.UpdateNormalPages(uint64(ovmfObj.GPA()), ovmfObj.Data()); err != nil {
		return nil, fmt.Errorf("updating normal pages: %w", err)
	}
	return gctx.LD(), nil
}

// launchDigest calculates the launch digest from metadata and ovmfHash for a SNP guest.
func launchDigest(metadata []ovmf.MetadataSection, resetEIP uint32, vcpuCount int, ovmfHash []byte) ([]byte, error) {
	guestCtx := gctx.New(ovmfHash)

	if err := snpUpdateMetadataPages(guestCtx, metadata, vmmtypes.EC2); err != nil {
		return nil, fmt.Errorf("updating metadata pages: %w", err)
	}

	// Add support for flags {vcpus_family, vcpu_sig, vcpu_type} here, if relevant.
	// Use cpuid pkg.
	vmsaObj, err := vmsa.New(resetEIP, 0, vmmtypes.EC2)
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

func snpUpdateMetadataPages(gctx *gctx.GCTX, metadata []ovmf.MetadataSection, vmmType vmmtypes.VMMType) error {
	for _, desc := range metadata {
		st, err := desc.SectionType()
		if err != nil {
			return fmt.Errorf("getting sectionType: %w", err)
		}
		switch st {
		case ovmf.SNPSECMEM:
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
		default:
			return errors.New("unknown OVMF metadata section type")
		}
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
