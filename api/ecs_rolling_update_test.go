// SPDX-License-Identifier: MIT
// Copyright (c) Simple Container

package aws

import (
	"testing"

	. "github.com/onsi/gomega"
	"github.com/samber/lo"
	"gopkg.in/yaml.v3"

	"github.com/simple-container-com/api/pkg/api"
)

func TestEcsFargateInput_DeploymentPercents(t *testing.T) {
	ru := func(minHealthy, max *int) *CloudExtras {
		return &CloudExtras{RollingUpdate: &EcsRollingUpdate{MinHealthyPercent: minHealthy, MaxPercent: max}}
	}
	for _, tc := range []struct {
		name     string
		update   FargateRollingUpdate
		extras   *CloudExtras
		min, max int
		err      string
	}{
		{name: "no cloudExtras keeps 100/200", min: 100, max: 200},
		{name: "cloudExtras without rollingUpdate keeps 100/200", extras: &CloudExtras{EnableHTTPS: true}, min: 100, max: 200},
		{name: "empty rollingUpdate keeps 100/200", extras: ru(nil, nil), min: 100, max: 200},
		{name: "converted Scale.Update is used", update: FargateRollingUpdate{MinHealthyPercent: 100, MaxPercent: 200}, min: 100, max: 200},
		{name: "explicit 0/100 honoured", extras: ru(lo.ToPtr(0), lo.ToPtr(100)), min: 0, max: 100},
		{name: "explicit 0/100 overrides converted defaults", update: FargateRollingUpdate{MinHealthyPercent: 100, MaxPercent: 200}, extras: ru(lo.ToPtr(0), lo.ToPtr(100)), min: 0, max: 100},
		{name: "min only", extras: ru(lo.ToPtr(50), nil), min: 50, max: 200},
		{name: "max only", extras: ru(nil, lo.ToPtr(150)), min: 100, max: 150},
		{name: "min below 0", extras: ru(lo.ToPtr(-1), lo.ToPtr(100)), err: "minHealthyPercent must be between 0 and 100"},
		{name: "min above 100", extras: ru(lo.ToPtr(101), nil), err: "minHealthyPercent must be between 0 and 100"},
		{name: "max below 100", extras: ru(lo.ToPtr(0), lo.ToPtr(99)), err: "maxPercent must be between 100 and 200"},
		{name: "max above 200", extras: ru(lo.ToPtr(0), lo.ToPtr(201)), err: "maxPercent must be between 100 and 200"},
		{name: "explicit 100/100 deadlock", extras: ru(lo.ToPtr(100), lo.ToPtr(100)), err: "cannot make progress"},
		{name: "max 100 with default min deadlocks", extras: ru(nil, lo.ToPtr(100)), err: "cannot make progress"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			RegisterTestingT(t)
			in := &EcsFargateInput{Scale: EcsFargateScale{Update: tc.update}, CloudExtras: tc.extras}
			minHealthy, max, err := in.DeploymentPercents()
			if tc.err != "" {
				Expect(err).To(MatchError(ContainSubstring(tc.err)))
				return
			}
			Expect(err).ToNot(HaveOccurred())
			Expect(minHealthy).To(Equal(tc.min))
			Expect(max).To(Equal(tc.max))
		})
	}
}

func TestToEcsFargateConfig_RollingUpdate(t *testing.T) {
	convert := func(clientYAML string) (*EcsFargateInput, error) {
		var stackCfg api.StackConfigCompose
		Expect(yaml.Unmarshal([]byte(clientYAML), &stackCfg)).To(Succeed())
		stackCfg.Runs = []string{"web"}
		out, err := ToEcsFargateConfig(validTemplateConfig(), composeWith(ingressService("web")), &stackCfg)
		if err != nil {
			return nil, err
		}
		return out.(*EcsFargateInput), nil
	}

	t.Run("unset keeps 100/200", func(t *testing.T) {
		RegisterTestingT(t)
		in, err := convert("cloudExtras:\n  enableHTTPS: true\n")
		Expect(err).ToNot(HaveOccurred())
		Expect(in.Scale.Update).To(Equal(FargateRollingUpdate{MinHealthyPercent: 100, MaxPercent: 200}))
		Expect(in.CloudExtras.RollingUpdate).To(BeNil())
		minHealthy, max, err := in.DeploymentPercents()
		Expect(err).ToNot(HaveOccurred())
		Expect([]int{minHealthy, max}).To(Equal([]int{100, 200}))
	})

	t.Run("explicit 0/100 from client.yaml", func(t *testing.T) {
		RegisterTestingT(t)
		in, err := convert("cloudExtras:\n  rollingUpdate:\n    minHealthyPercent: 0\n    maxPercent: 100\n")
		Expect(err).ToNot(HaveOccurred())
		minHealthy, max, err := in.DeploymentPercents()
		Expect(err).ToNot(HaveOccurred())
		Expect([]int{minHealthy, max}).To(Equal([]int{0, 100}))
	})

	t.Run("invalid combination rejected at conversion", func(t *testing.T) {
		RegisterTestingT(t)
		_, err := convert("cloudExtras:\n  rollingUpdate:\n    minHealthyPercent: 100\n    maxPercent: 100\n")
		Expect(err).To(MatchError(ContainSubstring("cannot make progress")))
	})
}
