package guest

import (
	"errors"
	"fmt"

	"edgelesssys/sevsnpmeasure/gctx"
	"edgelesssys/sevsnpmeasure/ovmf"
	"edgelesssys/sevsnpmeasure/vmmtypes"
	"edgelesssys/sevsnpmeasure/vmsa"
)

func snpCalcLaunchDigests(ovmfPath string, vcpuCount int, ovmfHash []byte) ([]byte, error) {
	guestCtx := gctx.New(ovmfHash)
	ovmfObj, err := ovmf.New(ovmfPath)
	if err != nil {
		return nil, fmt.Errorf("creating OVMF: %w", err)
	}
	if err := snpUpdateMetadataPages(guestCtx, ovmfObj, vmmtypes.EC2); err != nil {
		return nil, fmt.Errorf("updating metadata pages: %w", err)
	}

	resetEIP, err := ovmfObj.SevESResetEIP()
	if err != nil {
		return nil, fmt.Errorf("getting reset EIP: %w", err)
	}

	// Add support for flags {vcpus_family, vcpu_sig, vcpu_type} here, if relevant.
	// Use cpuid pkg.
	vmsaObj, err := vmsa.New(resetEIP, 0, vmmtypes.EC2)
	if err != nil {
		return nil, fmt.Errorf("creating VMSA: %w", err)
	}

	for _, desc := range vmsaObj.Pages(vcpuCount) {
		err := guestCtx.UpdateVmsaPage(desc)
		if err != nil {
			return nil, fmt.Errorf("updating VMSA page: %w", err)
		}
	}
	return guestCtx.LD(), nil
}

func snpUpdateMetadataPages(gctx *gctx.GCTX, metadata *ovmf.OVMF, vmmType vmmtypes.VMMType) error {
	for _, desc := range metadata.MetadataItems() {
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
		for _, desc := range metadata.MetadataItems() {
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
