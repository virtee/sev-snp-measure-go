/*
Copyright Edgeless Systems GmbH
Copyright 2022- IBM Inc. All rights reserved

SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"github.com/spf13/cobra"
)

// Execute executes the root command.
func Execute() error {
	return newRootCmd().Execute()
}

// newRootCmd creates the root command.
func newRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "sevsnpmeasure",
		Short: "Calculate SNP launch measurements from OVMF binaries",
		Long:  "Calculate SNP launch measurements from OVMF binaries.",
	}

	rootCmd.AddCommand(NewParseCmd())

	return rootCmd
}
