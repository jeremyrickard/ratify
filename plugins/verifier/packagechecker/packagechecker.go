/*
Copyright The Ratify Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/blang/semver"
	utils "github.com/deislabs/ratify/plugins/verifier/spdx"
	log "github.com/sirupsen/logrus"

	"github.com/deislabs/ratify/pkg/common"
	"github.com/deislabs/ratify/pkg/ocispecs"
	"github.com/deislabs/ratify/pkg/referrerstore"
	_ "github.com/deislabs/ratify/pkg/referrerstore/oras"
	"github.com/deislabs/ratify/pkg/verifier"
	"github.com/deislabs/ratify/pkg/verifier/plugin/skel"
)

type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type PluginConfig struct {
	Name               string    `json:"name"`
	DisAllowedPackages []Package `json:"disAllowedPackages"`
}

type PluginInputConfig struct {
	Config PluginConfig `json:"config"`
}

func main() {
	skel.PluginMain("packagechecker", "1.0.0", VerifyReference, []string{"1.0.0"})
}

func parseInput(stdin []byte) (*PluginConfig, error) {
	conf := PluginInputConfig{}

	if err := json.Unmarshal(stdin, &conf); err != nil {
		return nil, fmt.Errorf("failed to parse stdin for input: %v", err)
	}

	return &conf.Config, nil
}

func VerifyReference(args *skel.CmdArgs, subjectReference common.Reference, descriptor ocispecs.ReferenceDescriptor, store referrerstore.ReferrerStore) (*verifier.VerifierResult, error) {
	input, err := parseInput(args.StdinData)
	if err != nil {
		return nil, err
	}

	badPackageLookup := map[string][]string{}
	for _, pkg := range input.DisAllowedPackages {
		pkgs, ok := badPackageLookup[pkg.Name]
		if !ok {
			pkgs = []string{}
			badPackageLookup[pkg.Name] = pkgs
		}
		badPackageLookup[pkg.Name] = append(pkgs, pkg.Version)
	}

	ctx := context.Background()
	referenceManifest, err := store.GetReferenceManifest(ctx, subjectReference, descriptor)
	if err != nil {
		return nil, err
	}

	for _, blobDesc := range referenceManifest.Blobs {
		refBlob, err := store.GetBlobContent(ctx, subjectReference, blobDesc.Digest)
		if err != nil {
			return nil, err
		}

		spdxDoc, err := utils.JSONBlobToSPDX(refBlob)
		if err != nil {
			return nil, err
		}

		for _, pkg := range spdxDoc.Packages {
			versions := badPackageLookup[pkg.PackageName]
			//_ = badPackageLookup[pkg.PackageName]
			matched, err := contains(versions, pkg.PackageVersion)
			if err != nil {
				return nil, err
			}
			if matched {
				return &verifier.VerifierResult{
					Name:      input.Name,
					IsSuccess: false,
					Message:   fmt.Sprintf("Package Check: FAILED. %s:%s", pkg.PackageName, pkg.PackageVersion),
				}, nil
			}
		}
	}

	return &verifier.VerifierResult{
		Name:      input.Name,
		IsSuccess: true,
		Message:   "Package Check: SUCCESS. All packages have allowed versions",
	}, nil
}

func contains(versions []string, version string) (bool, error) {
	for _, ver := range versions {
		if ver == version {
			return true, nil
		}
		v, err := semver.Parse(ver)
		if err != nil {
			return false, err
		}
		pkgVersion, err := semver.Parse(version)
		if err != nil {
			return false, err
		}
		log.Infof("target: %s", version)
		log.Infof("package ver: %s", ver)
		return v.GTE(pkgVersion), nil
	}
	return false, nil
}
