/*
Copyright Edgeless Systems GmbH
Copyright 2022- IBM Inc. All rights reserved

SPDX-License-Identifier: Apache-2.0
*/

package vmmtypes

type VMMType int

//go:generate stringer -type=VMMType
const (
	QEMU VMMType = iota
	EC2
)

// VMMTypeFromString returns the VMMType for the given string.
func VMMTypeFromString(s string) VMMType {
	switch s {
	case QEMU.String():
		return QEMU
	case EC2.String():
		return EC2
	default:
		return -1
	}
}
