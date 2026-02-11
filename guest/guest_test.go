/*
Copyright Edgeless Systems GmbH
Copyright 2022- IBM Inc. All rights reserved

SPDX-License-Identifier: Apache-2.0
*/

package guest

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/virtee/sev-snp-measure-go/ovmf"
	"github.com/virtee/sev-snp-measure-go/vmmtypes"
)

func TestLaunchDigestCPUSignatureHandling(t *testing.T) {
	wrapper := ovmf.MetadataWrapper{
		MetadataItems: nil,
		ResetEIP:      0,
		OVMFHash:      nil,
	}

	testCases := map[string]struct {
		vmmType           vmmtypes.VMMType
		vcpuType          string
		expectedErrSubstr string
	}{
		"ec2 ignores empty vcpu type": {
			vmmType:  vmmtypes.EC2,
			vcpuType: "",
		},
		"gce ignores empty vcpu type": {
			vmmType:  vmmtypes.GCE,
			vcpuType: "",
		},
		"qemu rejects unknown vcpu type": {
			vmmType:           vmmtypes.QEMU,
			vcpuType:          "",
			expectedErrSubstr: `failed to find VCPU signature for vcpu_type ""`,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			_, err := LaunchDigestFromMetadataWrapper(wrapper, 0x1, 2, tc.vmmType, tc.vcpuType, nil, nil, "")
			if tc.expectedErrSubstr == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tc.expectedErrSubstr)
			}
		})
	}
}

// TestLaunchDigestFromOVMF tests if the correct hashes are calculated when using a OVMF image as input.
func TestLaunchDigestFromOVMF(t *testing.T) {
	testCases := map[string]struct {
		ovmfPath      string
		ovmfHash      string
		vcpuCount     int
		vcpuType      string
		kernel        []byte
		initrd        []byte
		cmdline       string
		guestFeatures uint64
		vmmType       vmmtypes.VMMType
		expectedHash  string
		wantErr       bool
	}{
		"success bin 1": {
			ovmfPath: "testdata/ovmf_img_1.bin",
			// Created by running: ./sev-snp-measure.py --mode snp:ovmf-hash --ovmf ovmf_img_1.fd
			ovmfHash:      "a58211791a556a630a4319dc9e2ea96cc0e9784dd9f20a4fadf81b26c98d163fcdcb6703884bbbb80d7b1de45b3d84d0",
			vcpuCount:     2,
			vmmType:       vmmtypes.EC2,
			guestFeatures: 0x1,
			// Created by running: ./sev-snp-measure.py --mode snp --vcpus 2 --ovmf ovmf_img_1.fd --vmm-type ec2 --snp-ovmf-hash a58211791a556a630a4319dc9e2ea96cc0e9784dd9f20a4fadf81b26c98d163fcdcb6703884bbbb80d7b1de45b3d84d0
			expectedHash: "4c6e33087d08fa770259484dddbef367086a15c3e2cf10038dc97229d39c942671c2e22b300178f8de594a3f2fa59303",
		},
		"success bin 2": {
			ovmfPath: "testdata/ovmf_img_2.bin",
			// Created by running: ./sev-snp-measure.py --mode snp:ovmf-hash --ovmf ovmf_img_2.fd
			ovmfHash:      "2027a27bb9f7acfd280e4c7bd68a73973b94bf0756e5b282e004b9395f597b8d0eb4defa7d8f6549375aa4d2b146f0f3",
			vcpuCount:     2,
			vmmType:       vmmtypes.EC2,
			guestFeatures: 0x1,
			expectedHash:  "c2c84b9364fc9f0f54b04534768c860c6e0e386ad98b96e8b98eca46ac8971d05c531ba48373f054c880cfd1f4a0a84e",
		},
		"success with kernel": {
			ovmfPath:      "testdata/ovmf_AmdSev_suffix.bin",
			ovmfHash:      "086e2e9149ebf45abdc3445fba5b2da8270bdbb04094d7a2c37faaa4b24af3aa16aff8c374c2a55c467a50da6d466b74",
			vcpuCount:     1,
			vcpuType:      "EPYC-v4",
			kernel:        []byte{},
			initrd:        []byte{},
			cmdline:       "console=ttyS0 loglevel=7",
			guestFeatures: 0x1,
			vmmType:       vmmtypes.QEMU,
			expectedHash:  "6d287813eb5222d770f75005c664e34c204f385ce832cc2ce7d0d6f354454362f390ef83a92046c042e706363b4b08fa",
		},
		"snp_features_0x21_with_cmdline": {
			ovmfPath:      "testdata/ovmf_AmdSev_suffix.bin",
			ovmfHash:      "086e2e9149ebf45abdc3445fba5b2da8270bdbb04094d7a2c37faaa4b24af3aa16aff8c374c2a55c467a50da6d466b74",
			vcpuCount:     1,
			vcpuType:      "EPYC-v4",
			kernel:        []byte{},
			initrd:        []byte{},
			cmdline:       "console=ttyS0 loglevel=7",
			guestFeatures: 0x21,
			vmmType:       vmmtypes.QEMU,
			expectedHash:  "803f691094946e42068aaa3a8f9e26a5c89f36f7b73ecfb28c653360fe4b3aba7e534442e7e1e17895dfe778d0228977",
		},
		"snp_4_vcpus_features_0x21": {
			ovmfPath:      "testdata/ovmf_AmdSev_suffix.bin",
			ovmfHash:      "086e2e9149ebf45abdc3445fba5b2da8270bdbb04094d7a2c37faaa4b24af3aa16aff8c374c2a55c467a50da6d466b74",
			vcpuCount:     4,
			vcpuType:      "EPYC-v4",
			kernel:        []byte{},
			initrd:        []byte{},
			cmdline:       "",
			guestFeatures: 0x21,
			vmmType:       vmmtypes.QEMU,
			expectedHash:  "4953b1fb416fa874980e8442b3706d345926d5f38879134e00813c5d7abcbe78eafe7b422907be0b4698e2414a631942",
		},
		"success bin 3": {
			ovmfPath: "testdata/ovmf_img_1.bin",
			// Created by running: ./sev-snp-measure.py --mode snp:ovmf-hash --ovmf ovmf_img_1.fd
			ovmfHash:      "a58211791a556a630a4319dc9e2ea96cc0e9784dd9f20a4fadf81b26c98d163fcdcb6703884bbbb80d7b1de45b3d84d0",
			vcpuCount:     2,
			vmmType:       vmmtypes.GCE,
			guestFeatures: 0x1,
			// Created by running: ./sev-snp-measure.py --mode snp --vcpus 2 --ovmf ovmf_img_1.fd --vmm-type gce --snp-ovmf-hash a58211791a556a630a4319dc9e2ea96cc0e9784dd9f20a4fadf81b26c98d163fcdcb6703884bbbb80d7b1de45b3d84d0
			expectedHash: "92dd082c6f938452733ef95413d5b023f4a30b249ef5e65c96f090f84c96419004636f5289aa7de3e7948625c64fa67c",
		},
		"success bin 4": {
			ovmfPath: "testdata/ovmf_img_2.bin",
			// Created by running: ./sev-snp-measure.py --mode snp:ovmf-hash --ovmf ovmf_img_2.fd
			ovmfHash:      "2027a27bb9f7acfd280e4c7bd68a73973b94bf0756e5b282e004b9395f597b8d0eb4defa7d8f6549375aa4d2b146f0f3",
			vcpuCount:     2,
			vmmType:       vmmtypes.GCE,
			guestFeatures: 0x1,
			expectedHash:  "d0a87fc891933399c54853b455aef5dd348db04465cf726d891b2f5b3f95cd85f42d47236acde9cb29acc3b154d05ef8",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			hash, err := hex.DecodeString(tc.ovmfHash)
			require.NoError(err)

			ovmfObj, err := ovmf.New(tc.ovmfPath)
			require.NoError(err)

			guestFeatures := tc.guestFeatures

			launchDigest, err := LaunchDigestFromOVMF(ovmfObj, guestFeatures, tc.vcpuCount, hash, tc.vmmType, tc.vcpuType, tc.kernel, tc.initrd, tc.cmdline)
			if tc.wantErr {
				assert.Error(err)
			} else {
				assert.NoError(err)
				expectedHash, err := hex.DecodeString(tc.expectedHash)
				require.NoError(err)
				assert.True(bytes.Equal(launchDigest, expectedHash), fmt.Sprintf("expected hash %x, got %x", expectedHash, launchDigest))
			}
		})
	}
}

func TestLaunchDigestFromMetadataWrapper(t *testing.T) {
	testCases := map[string]struct {
		apiObjectPath  string
		vcpuCount      int
		vmmType        vmmtypes.VMMType
		expectedDigest string
		wantErr        bool
	}{
		"success bin 1": {
			apiObjectPath:  "testdata/ovmf_img_1.json",
			vcpuCount:      2,
			vmmType:        vmmtypes.EC2,
			expectedDigest: "4c6e33087d08fa770259484dddbef367086a15c3e2cf10038dc97229d39c942671c2e22b300178f8de594a3f2fa59303",
		},
		"success bin 2": {
			apiObjectPath:  "testdata/ovmf_img_2.json",
			vcpuCount:      2,
			vmmType:        vmmtypes.EC2,
			expectedDigest: "c2c84b9364fc9f0f54b04534768c860c6e0e386ad98b96e8b98eca46ac8971d05c531ba48373f054c880cfd1f4a0a84e",
		},
		"success bin 3": {
			apiObjectPath:  "testdata/ovmf_img_1.json",
			vcpuCount:      2,
			vmmType:        vmmtypes.GCE,
			expectedDigest: "92dd082c6f938452733ef95413d5b023f4a30b249ef5e65c96f090f84c96419004636f5289aa7de3e7948625c64fa67c",
		},
		"success bin 4": {
			apiObjectPath:  "testdata/ovmf_img_2.json",
			vcpuCount:      2,
			vmmType:        vmmtypes.GCE,
			expectedDigest: "d0a87fc891933399c54853b455aef5dd348db04465cf726d891b2f5b3f95cd85f42d47236acde9cb29acc3b154d05ef8",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			data, err := os.ReadFile(tc.apiObjectPath)
			require.NoError(err)

			var apiObject ovmf.MetadataWrapper
			err = json.Unmarshal(data, &apiObject)
			require.NoError(err)

			launchDigest, err := LaunchDigestFromMetadataWrapper(apiObject, 0x1, tc.vcpuCount, tc.vmmType, "", nil, nil, "")
			if tc.wantErr {
				assert.Error(err)
			} else {
				assert.NoError(err)
				expectedHash, err := hex.DecodeString(tc.expectedDigest)
				require.NoError(err)
				assert.True(bytes.Equal(launchDigest, expectedHash), fmt.Sprintf("expected hash %x, got %x", expectedHash, launchDigest))
			}
		})
	}
}

func TestOVMFHash(t *testing.T) {
	testCases := map[string]struct {
		ovmfPath string
		ovmfHash string
	}{
		"success bin 1": {
			ovmfPath: "testdata/ovmf_img_1.bin",
			ovmfHash: "a58211791a556a630a4319dc9e2ea96cc0e9784dd9f20a4fadf81b26c98d163fcdcb6703884bbbb80d7b1de45b3d84d0",
		},
		"success bin 2": {
			ovmfPath: "testdata/ovmf_img_2.bin",
			ovmfHash: "2027a27bb9f7acfd280e4c7bd68a73973b94bf0756e5b282e004b9395f597b8d0eb4defa7d8f6549375aa4d2b146f0f3",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			expectedHash, err := hex.DecodeString(tc.ovmfHash)
			require.NoError(err)

			ovmfObj, err := ovmf.New(tc.ovmfPath)
			require.NoError(err)

			hash, err := OVMFHash(ovmfObj)
			assert.NoError(err)
			assert.True(bytes.Equal(expectedHash, hash), fmt.Sprintf("expected hash %x, got %x", expectedHash, hash))
		})
	}
}
