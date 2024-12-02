/*
Copyright Edgeless Systems GmbH

SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/virtee/sev-snp-measure-go/cpuid"
	"github.com/virtee/sev-snp-measure-go/guest"
	"github.com/virtee/sev-snp-measure-go/vmmtypes"
)

const defGuestFeatures = 0x1

var (
	mode          string
	vcpus         int
	vcpuType      string
	ovmfFile      string
	kernelFile    string
	initrdFile    string
	append        string
	vcpuSig       int
	vcpuFamily    int
	vcpuModel     int
	vcpuStepping  int
	vmmtype       string
	guestFeatures uint64
	varsSize      int64
	varsFile      string
	snpOvmfHash   string
	dumpVmsa      bool
	svsmFile      string
	outputFmt     string
)

// Execute executes the root command.
func Execute() error {
	return newRootCmd().Execute()
}

// newRootCmd creates the root command.
func newRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "sevsnpmeasure",
		Short: "Calculate AMD SEV/SEV-ES/SEV-SNP guest launch measurement",
		Long:  "Calculate AMD SEV/SEV-ES/SEV-SNP guest launch measurement.",
		RunE:  launchMeasurement,
	}

	rootCmd.Flags().StringVarP(&mode, "mode", "m", "", "Guest mode, either 'snp', 'seves', 'sev', 'snp:ovmf-hash' or 'snp:svsm'.")
	rootCmd.MarkFlagRequired("mode")
	rootCmd.Flags().IntVar(&vcpus, "vcpus", 0, "Number of guest vCPUs.")
	rootCmd.Flags().StringVarP(&vcpuType, "vcpu-type", "t", "", "Guest vCPU type")
	rootCmd.Flags().StringVarP(&ovmfFile, "ovmf", "o", "", "Path to OVMF binary.")
	rootCmd.MarkFlagRequired("ovmf")
	rootCmd.Flags().StringVarP(&kernelFile, "kernel", "k", "", "Path to kernel binary.")
	rootCmd.Flags().StringVarP(&initrdFile, "initrd", "i", "", "Path to initrd binary.")
	rootCmd.Flags().StringVarP(&append, "append", "a", "", "Kernel command line arguments.")
	rootCmd.Flags().IntVarP(&vcpuSig, "vcpu-sig", "s", 0, "Guest vCPU signature.")
	rootCmd.Flags().IntVarP(&vcpuFamily, "vcpu-family", "f", 0, "Guest vCPU family.")
	rootCmd.Flags().IntVarP(&vcpuModel, "vcpu-model", "l", 0, "Guest vCPU model.")
	rootCmd.Flags().IntVarP(&vcpuStepping, "vcpu-stepping", "p", 0, "Guest vCPU stepping.")
	rootCmd.Flags().StringVar(&vmmtype, "vmm-type", vmmtypes.QEMU.String(), "Guest VMM type, either 'QEMU' or 'EC2'.")
	rootCmd.Flags().Uint64Var(&guestFeatures, "guest-features", defGuestFeatures, "The guest kernel features expected to be included.")
	rootCmd.Flags().Int64Var(&varsSize, "vars-size", 0, "Size of the OVMF_VARS file in bytes.")
	rootCmd.Flags().StringVar(&varsFile, "vars-file", "", "Path to OVMF_VARS file.")
	rootCmd.Flags().StringVar(&snpOvmfHash, "snp-ovmf-hash", "", "Precalculated hash of the OVMF binary (hex string).")
	rootCmd.Flags().BoolVar(&dumpVmsa, "dump-vmsa", false, "Write measured VMSAs to vmsa<N>.bin (seves, snp, and snp:svsm modes only).")
	rootCmd.Flags().StringVar(&svsmFile, "svsm", "", "Path to the SVSM binary.")
	rootCmd.Flags().StringVar(&outputFmt, "output-format", "hex", "Output format, either 'hex' or 'base64'.")
	rootCmd.MarkFlagsMutuallyExclusive("svsm", "ovmf")

	rootCmd.AddCommand(NewParseCmd())

	return rootCmd
}

func launchMeasurement(cmd *cobra.Command, args []string) error {
	if mode == "snp:ovmf-hash" {
		hash, err := guest.CalcSnpOvmfHash(ovmfFile)
		if err != nil {
			return err
		}
		outputMeasurement(hash)
	}

	if err := validateFlags(); err != nil {
		return err
	}

	vmmType := vmmtypes.VMMTypeFromString(vmmtype)
	if vmmType == -1 {

		return fmt.Errorf("invalid vmm-type")
	}

	vcpuSig, err := vCPUSIG()
	if err != nil {
		return err
	}

	sevMode := guest.SevModeFromString(mode)
	if sevMode == -1 {
		return fmt.Errorf("invalid mode")
	}

	if sevMode == guest.SEV_SNP_SVSM {
		if varsFile != "" {
			varsInfo, err := os.Stat(varsFile)
			if err != nil {
				return err
			}
			varsSize = varsInfo.Size()
		}

		if varsSize == 0 {
			return fmt.Errorf("SNP:SVSM mode requires vars-size")
		}
	}

	ld, err := guest.CalcLaunchDigest(sevMode, vcpus, uint64(vcpuSig), ovmfFile, kernelFile, initrdFile, append, guestFeatures, snpOvmfHash, vmmType, dumpVmsa, svsmFile, int(varsSize))
	if err != nil {
		return err
	}

	outputMeasurement(ld)
	return nil
}

func vCPUSIG() (int, error) {
	if mode == guest.SEV.String() {
		return 0, nil
	} else if vcpuFamily != 0 {
		return cpuid.CpuSig(vcpuFamily, vcpuModel, vcpuStepping), nil
	} else if vcpuSig != 0 {
		return vcpuSig, nil
	} else if vcpuType != "" {
		return cpuid.CpuSigs[vcpuType], nil
	} else {
		return -1, fmt.Errorf("missing vcpu-type or vcpu-sig or vcpu-family in guest mode %s", mode)
	}
}

func validateFlags() error {
	if initrdFile != "" && kernelFile == "" {
		return fmt.Errorf("kernel required when initrd is provided")
	}

	if append != "" && kernelFile == "" {
		return fmt.Errorf("kernel required when append is provided")
	}

	if mode != guest.SEV.String() && vcpus == 0 {
		return fmt.Errorf("vcpus required")
	}

	return nil
}

func outputMeasurement(ld []byte) {
	switch outputFmt {
	case "hex":
		fmt.Printf("%s\n", hex.EncodeToString(ld))
	case "base64":
		fmt.Printf("%s\n", base64.StdEncoding.EncodeToString(ld))
	default:
		fmt.Printf("Invalid output format: %s\n", outputFmt)
	}
}
