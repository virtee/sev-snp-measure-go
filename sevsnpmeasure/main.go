/*
Copyright Edgeless Systems GmbH

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"os"

	"github.com/virtee/sev-snp-measure-go/sevsnpmeasure/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}
