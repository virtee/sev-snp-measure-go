/*
Copyright Edgeless Systems GmbH
Copyright 2022- IBM Inc. All rights reserved

SPDX-License-Identifier: Apache-2.0
*/

package vmmtypes

type VMMType int

const (
	QEMU VMMType = iota
	EC2
)
