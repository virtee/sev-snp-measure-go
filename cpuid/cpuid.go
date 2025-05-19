/*
Copyright Edgeless Systems GmbH
Copyright 2022- IBM Inc. All rights reserved

SPDX-License-Identifier: Apache-2.0
*/

package cpuid

import (
	"errors"
	"fmt"
)

var ErrSigInsufficientOptions = errors.New("specify at least one of signature, model or FMS")
var ErrSigMultipleCpuOptions = errors.New("specify only one of signature, model or FMS")

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

type CpuSpec struct {
	CpuSignature *uint32
	QemuCpuModel *string
	CpuFamily    *uint32
	CpuModel     *uint32
	CpuStepping  *uint32
}

func CpuSignature(sig uint32) CpuSpec {
	return CpuSpec{CpuSignature: &sig}
}

func QemuCpuModel(model string) CpuSpec {
	return CpuSpec{QemuCpuModel: &model}
}

func CpuFMS(family uint32, model uint32, stepping uint32) CpuSpec {
	return CpuSpec{CpuFamily: &family, CpuModel: &model, CpuStepping: &stepping}
}

func GetCpuSig(spec CpuSpec) (int, error) {
	var (
		signature                int
		suppliedSpecs            int
		hasSig, hasModel, hasFMS bool
	)

	if hasSig = spec.CpuSignature != nil; hasSig {
		suppliedSpecs++
	}

	if hasModel = spec.QemuCpuModel != nil; hasModel {
		suppliedSpecs++
	}

	if hasFMS = spec.CpuFamily != nil; hasFMS {
		suppliedSpecs++
	}

	if suppliedSpecs > 1 {
		return 0, ErrSigMultipleCpuOptions
	}

	if suppliedSpecs == 0 {
		return 0, ErrSigInsufficientOptions
	}

	if hasSig {
		signature = int(*spec.CpuSignature)
	}

	if hasModel {
		var ok bool
		signature, ok = CpuSigs[*spec.QemuCpuModel]
		if !ok {
			return 0, fmt.Errorf("unknown model %v", *spec.QemuCpuModel)
		}
	}

	if hasFMS {
		signature = cpuSig(int(*spec.CpuFamily), int(*spec.CpuModel), int(*spec.CpuStepping))
	}

	return signature, nil
}
