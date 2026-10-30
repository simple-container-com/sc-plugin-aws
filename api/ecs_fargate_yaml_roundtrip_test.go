// SPDX-License-Identifier: MIT
// Copyright (c) Simple Container

package aws

import (
	"testing"

	"gopkg.in/yaml.v3"

	. "github.com/onsi/gomega"
	"github.com/simple-container-com/api/pkg/api"
)

// TestEcsFargateConfig_YAMLRoundTrip is the regression test for the
// fleet-wide outage of 2026-10-30 where every `ecs-fargate` stack went
// down with:
//
//	sc-plugin-aws Provision panic:
//	duplicated key 'credentials' in struct aws.EcsFargateConfig
//	gopkg.in/yaml.v3@v3.0.1/decode.go:881
//
// The plugin bus's `decodeInputsAs` marshals the inputs map to YAML then
// unmarshals into a typed struct — the ecs-fargate config decoded through
// this path for the first time when forge-baas moved onto sc-plugin-aws.
// yaml.v3 rejects a struct that has two fields tagged with the same key,
// and `EcsFargateConfig` carried BOTH an explicit `api.Credentials` embed
// AND an `AccountConfig` embed whose own transitive embed also exposes
// `api.Credentials` — two `yaml:"credentials"` siblings.
//
// The in-tree deploy path didn't yaml-round-trip the struct the same way,
// so the duplication rode along silently until the plugin bus caught it.
// Keep this test green or every ecs-fargate deploy panics mid-RPC.
func TestEcsFargateConfig_YAMLRoundTrip(t *testing.T) {
	g := NewWithT(t)

	in := EcsFargateConfig{
		AccountConfig: AccountConfig{
			Account:         "123456789012",
			AccessKey:       "AKIA_TEST",
			SecretAccessKey: "secret-key",
			Region:          "eu-central-1",
			Credentials: api.Credentials{
				Credentials: `{"account":"123456789012","region":"eu-central-1"}`,
			},
		},
		Cpu:                512,
		Memory:             1024,
		EphemeralStorageGB: 20,
		Version:            "2026.10.30-abcdef1",
	}

	bytes, err := yaml.Marshal(in)
	g.Expect(err).NotTo(HaveOccurred(), "marshal: should serialize without error")

	var out EcsFargateConfig
	err = yaml.Unmarshal(bytes, &out)
	g.Expect(err).NotTo(HaveOccurred(),
		"unmarshal: yaml.v3 must not reject the struct as `duplicated key 'credentials'`")

	g.Expect(out.Account).To(Equal("123456789012"))
	g.Expect(out.Region).To(Equal("eu-central-1"))
	g.Expect(out.AccountConfig.Credentials.Credentials).To(Equal(in.AccountConfig.Credentials.Credentials),
		"the credentials blob must round-trip through yaml")
	g.Expect(out.Cpu).To(Equal(512))
	g.Expect(out.Memory).To(Equal(1024))
	g.Expect(out.Version).To(Equal("2026.10.30-abcdef1"))
}
