/*
Copyright Edgeless Systems GmbH

SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/virtee/sev-snp-measure-go/guest"
	"github.com/virtee/sev-snp-measure-go/ovmf"
)

func NewParseCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "parse-metadata <ovmf binary>",
		Short: "Show metadata from a OVMF binary",
		Long:  "Show metadata from a OVMF binary, optionally write data to JSON file.",
		Args:  cobra.ExactArgs(1),
		RunE:  parseMetadata,
	}

	cmd.Flags().StringP("output", "o", "", "path to output JSON, prints to stdout if not set")

	return cmd
}

func parseMetadata(cmd *cobra.Command, args []string) error {
	ovmfObj, err := ovmf.New(args[0], 0)
	if err != nil {
		return fmt.Errorf("creating OVMF object: %w", err)
	}

	hash, err := guest.OVMFHash(ovmfObj)
	if err != nil {
		return fmt.Errorf("calculating OVMF hash: %w", err)
	}

	metadata, err := ovmf.NewMetadataWrapper(ovmfObj, hash)
	if err != nil {
		return fmt.Errorf("creating metadata wrapper: %w", err)
	}

	out, err := cmd.Flags().GetString("output")
	if err != nil {
		return fmt.Errorf("parsing output flag: %w", err)
	}

	data, err := json.Marshal(&metadata)
	if err != nil {
		return fmt.Errorf("marshalling metadata: %w", err)
	}

	if out == "" {
		fmt.Println(string(data))
	} else {
		if err := os.WriteFile(out, data, 0o644); err != nil {
			return fmt.Errorf("writing to file: %w", err)
		}
	}

	return nil
}
