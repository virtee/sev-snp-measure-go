package main

import (
	"os"

	"edgelesssys/sev-snp-measure/sevsnpmeasure/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}
