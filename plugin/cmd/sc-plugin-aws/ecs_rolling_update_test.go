// SPDX-License-Identifier: MIT
// Copyright (c) Simple Container

package main

import (
	"encoding/json"
	"testing"

	"github.com/compose-spec/compose-go/types"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/simple-container-com/api/pkg/api"
	"github.com/simple-container-com/api/pkg/clouds/compose"
	awsApi "github.com/simple-container-com/sc-plugin-aws/api"
)

// cloudExtras.rollingUpdate must survive core -> plugin: core parses
// client.yaml into api.StackConfigCompose (cloudExtras stays untyped),
// JSON-encodes it, and the plugin JSON-decodes the Provision inputs. An
// explicit 0 must not collapse back to the 100% default.
func TestDecodeTypedConfig_EcsRollingUpdate(t *testing.T) {
	project := &types.Project{WorkingDir: "/offline", Services: types.Services{{
		Name: "blog", Image: "example.invalid/blog:v1",
		Labels: map[string]string{api.ComposeLabelIngressContainer: "true"},
		Ports:  []types.ServicePortConfig{{Target: 2368}},
	}}}
	convert := func(t *testing.T, clientYAML string) any {
		var client struct {
			Config api.StackConfigCompose `yaml:"config"`
		}
		require.NoError(t, yaml.Unmarshal([]byte(clientYAML), &client))
		// Core JSON-encodes the stack config before the plugin decodes it.
		b, err := json.Marshal(client.Config)
		require.NoError(t, err)
		var stackCfg api.StackConfigCompose
		require.NoError(t, json.Unmarshal(b, &stackCfg))
		out, err := awsApi.ToEcsFargateConfig(&awsApi.TemplateConfig{}, compose.Config{Project: project}, &stackCfg)
		require.NoError(t, err)
		return out
	}
	percents := func(t *testing.T, cfg any) []int {
		decoded, err := decodeTypedConfig(awsApi.TemplateTypeEcsFargate, requestInputs(t, cfg))
		require.NoError(t, err)
		minHealthy, max, err := decoded.(*awsApi.EcsFargateInput).DeploymentPercents()
		require.NoError(t, err)
		return []int{minHealthy, max}
	}

	t.Run("unset keeps 100/200", func(t *testing.T) {
		cfg := convert(t, "config:\n  runs: [blog]\n  cloudExtras:\n    restrictTaskIngress: true\n")
		require.Equal(t, []int{100, 200}, percents(t, cfg))
	})
	t.Run("no cloudExtras keeps 100/200", func(t *testing.T) {
		cfg := convert(t, "config:\n  runs: [blog]\n")
		require.Equal(t, []int{100, 200}, percents(t, cfg))
	})

	const stopThenStart = "config:\n  runs: [blog]\n  cloudExtras:\n    rollingUpdate:\n      minHealthyPercent: 0\n      maxPercent: 100\n"
	t.Run("explicit 0/100 via current converter", func(t *testing.T) {
		require.Equal(t, []int{0, 100}, percents(t, convert(t, stopThenStart)))
	})
	t.Run("explicit 0/100 via older core converter (raw stackConfig only)", func(t *testing.T) {
		// An older core's linked converter drops the unknown typed field and
		// hardcodes 100/200; the raw stackConfig.cloudExtras still carries it.
		var client struct {
			Config api.StackConfigCompose `yaml:"config"`
		}
		require.NoError(t, yaml.Unmarshal([]byte(stopThenStart), &client))
		legacy := map[string]any{
			"scale":       map[string]any{"update": map[string]any{"minHealthyPercent": 100, "maxPercent": 200}},
			"cloudExtras": map[string]any{},
			"stackConfig": client.Config,
		}
		require.Equal(t, []int{0, 100}, percents(t, legacy))
	})
	t.Run("invalid combination rejected after decode", func(t *testing.T) {
		decoded, err := decodeTypedConfig(awsApi.TemplateTypeEcsFargate, requestInputs(t, map[string]any{
			"stackConfig": map[string]any{"cloudExtras": map[string]any{"rollingUpdate": map[string]any{"maxPercent": 100}}},
		}))
		require.NoError(t, err)
		_, _, err = decoded.(*awsApi.EcsFargateInput).DeploymentPercents()
		require.ErrorContains(t, err, "cannot make progress")
	})
}
