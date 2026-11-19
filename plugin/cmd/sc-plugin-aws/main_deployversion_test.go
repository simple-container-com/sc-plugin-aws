// SPDX-License-Identifier: MIT
// Copyright (c) Simple Container

package main

import (
	"testing"

	scpluginv1 "github.com/simple-container-com/api/pkg/plugin/proto/v1"
)

// TestDeployVersionReadFromHeader pins the field whose absence meant
// every plugin-deployed image was built with VERSION=latest.
//
// The provision input builder sets StackParams.Version from
// header.deploy_version (api#640). That value is the input to the
// VERSION build-arg SC injects on every image:
//
//	version: lo.If(deployParams.Version != "", …).Else("latest")
//
// so leaving it unset silently baked the literal string "latest" into
// any binary built with `-ldflags "-X main.version=${VERSION}"`.
// Live-caught on forge-storage, whose /healthz reported "latest" while
// the same run logged `Deploy version: 2026.11.19-fecb8f8`.
//
// The empty case matters just as much: against an older SC core the
// field is absent, and the driver's "latest" fallback must still be what
// happens rather than a crash or a bogus version.
func TestDeployVersionReadFromHeader(t *testing.T) {
	for name, tc := range map[string]struct {
		header *scpluginv1.RequestHeader
		want   string
	}{
		"populated": {
			header: &scpluginv1.RequestHeader{DeployVersion: "2026.11.19-fecb8f8"},
			want:   "2026.11.19-fecb8f8",
		},
		// An older SC core, or `sc provision` (which has no deploy
		// version at all).
		"absent": {header: &scpluginv1.RequestHeader{}, want: ""},
		"nil":    {header: nil, want: ""},
	} {
		if got := tc.header.GetDeployVersion(); got != tc.want {
			t.Errorf("%s: GetDeployVersion() = %q, want %q", name, got, tc.want)
		}
	}
}
