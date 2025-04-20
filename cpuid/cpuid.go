/*
Copyright Edgeless Systems GmbH
Copyright 2022- IBM Inc. All rights reserved

SPDX-License-Identifier: Apache-2.0
*/

package cpuid

func cpuSig(family int, model int, stepping int) int {
	var familyLow, familyHigh, modelLow, modelHigh, steppingLow int

	if family > 0xf {
		familyLow = 0xf
		familyHigh = (family - 0x0f) & 0xff
	} else {
		familyLow = family
		familyHigh = 0
	}

	modelLow = model & 0xf
	modelHigh = (model >> 4) & 0xf

	steppingLow = stepping & 0xf

	return ((familyHigh << 20) |
		(modelHigh << 16) |
		(familyLow << 8) |
		(modelLow << 4) |
		steppingLow)
}

var CpuSigs = map[string]int{
	"EPYC":          cpuSig(23, 1, 2),
	"EPYC-v1":       cpuSig(23, 1, 2),
	"EPYC-v2":       cpuSig(23, 1, 2),
	"EPYC-IBPB":     cpuSig(23, 1, 2),
	"EPYC-v3":       cpuSig(23, 1, 2),
	"EPYC-v4":       cpuSig(23, 1, 2),
	"EPYC-Rome":     cpuSig(23, 49, 0),
	"EPYC-Rome-v1":  cpuSig(23, 49, 0),
	"EPYC-Rome-v2":  cpuSig(23, 49, 0),
	"EPYC-Rome-v3":  cpuSig(23, 49, 0),
	"EPYC-Milan":    cpuSig(25, 1, 1),
	"EPYC-Milan-v1": cpuSig(25, 1, 1),
	"EPYC-Milan-v2": cpuSig(25, 1, 1),
	"EPYC-Genoa":    cpuSig(25, 17, 0),
	"EPYC-Genoa-v1": cpuSig(25, 17, 0),
	"EPYC-Genoa-v2": cpuSig(25, 17, 0),
}
