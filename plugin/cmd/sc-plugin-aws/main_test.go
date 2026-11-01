// SPDX-License-Identifier: MIT
// Copyright (c) Simple Container

package main

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/compose-spec/compose-go/types"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/simple-container-com/api/pkg/api"
	"github.com/simple-container-com/api/pkg/clouds/compose"
	scpluginv1 "github.com/simple-container-com/api/pkg/plugin/proto/v1"
	awsApi "github.com/simple-container-com/sc-plugin-aws/api"
)

func TestDecodeTypedConfig_ComposeCloudExtras(t *testing.T) {
	b, err := os.ReadFile("testdata/compose-cloudextras.yaml")
	require.NoError(t, err)
	var client struct {
		Config api.StackConfigCompose `yaml:"config"`
	}
	require.NoError(t, yaml.Unmarshal(b, &client))

	project := &types.Project{WorkingDir: "/offline", Services: types.Services{{
		Name: "web", Image: "example.invalid/web:v1",
		Labels: map[string]string{api.ComposeLabelIngressContainer: "true"},
		Ports:  []types.ServicePortConfig{{Target: 8080}},
	}}}
	current, err := awsApi.ToEcsFargateConfig(&awsApi.TemplateConfig{}, compose.Config{Project: project}, &client.Config)
	require.NoError(t, err)

	// Captured from ToEcsFargateConfig in AWS api commit 4f8f024bc425,
	// linked by SC 2026.10.61. Its typed CloudExtras lacks the hardening
	// flags, but StackConfig still contains the original untyped block.
	b, err = os.ReadFile("testdata/ecs-cloudextras-sc-2026.10.61.json")
	require.NoError(t, err)
	var legacy map[string]any
	require.NoError(t, json.Unmarshal(b, &legacy))
	require.NotContains(t, legacy["cloudExtras"], "leastPrivilegeRoles")
	require.NotContains(t, legacy["cloudExtras"], "restrictTaskIngress")
	require.NotContains(t, legacy["cloudExtras"], "enableHTTPS")
	// Feed the exact client YAML through both versions' request shapes.
	legacy["stackConfig"] = client.Config

	for name, cfg := range map[string]any{"current core": current, "SC 2026.10.61": legacy} {
		t.Run(name, func(t *testing.T) {
			decoded, err := decodeTypedConfig(awsApi.TemplateTypeEcsFargate, requestInputs(t, cfg))
			require.NoError(t, err)
			in := decoded.(*awsApi.EcsFargateInput)
			require.Equal(t, "staging-app-innmind.alphamind.co", in.Domain)
			require.Equal(t, 1024, in.Config.Cpu)
			require.Equal(t, 2048, in.Config.Memory)
			require.Equal(t, []string{"mongodb"}, in.Uses())
			require.NotNil(t, in.CloudExtras)
			require.True(t, in.CloudExtras.LeastPrivilegeRoles)
			require.True(t, in.CloudExtras.RestrictTaskIngress)
			require.True(t, in.CloudExtras.EnableHTTPS)
			require.NotNil(t, in.CloudExtras.SecurityGroup)
			require.NotNil(t, in.CloudExtras.SecurityGroup.Ingress)
			require.NotNil(t, in.CloudExtras.SecurityGroup.Ingress.AllowOnlyCloudflare)
			require.True(t, *in.CloudExtras.SecurityGroup.Ingress.AllowOnlyCloudflare)
		})
	}
}

func TestDecodeTypedConfig_EcsCloudExtrasSources(t *testing.T) {
	for _, tc := range []struct {
		name   string
		config map[string]any
		want   *awsApi.CloudExtras
	}{
		{name: "absent"},
		{name: "no stackConfig", config: map[string]any{"cloudExtras": map[string]any{"enableHTTPS": true}}, want: &awsApi.CloudExtras{EnableHTTPS: true}},
		{name: "no raw extras", config: map[string]any{"stackConfig": map[string]any{}, "cloudExtras": map[string]any{"enableHTTPS": true}}, want: &awsApi.CloudExtras{EnableHTTPS: true}},
		{name: "raw extras only", config: map[string]any{"stackConfig": map[string]any{"cloudExtras": map[string]any{"nlbSecurityGroups": true, "disablePublicIPWithStaticEgress": true}}}, want: &awsApi.CloudExtras{NlbSecurityGroups: true, DisablePublicIPWithStaticEgress: true}},
		{name: "explicit false overrides typed value", config: map[string]any{
			"cloudExtras": map[string]any{"enableHTTPS": true, "awsRoles": []string{"s3:GetObject"}},
			"stackConfig": map[string]any{"cloudExtras": map[string]any{"enableHTTPS": false}},
		}, want: &awsApi.CloudExtras{AwsRoles: []string{"s3:GetObject"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			decoded, err := decodeTypedConfig(awsApi.TemplateTypeEcsFargate, requestInputs(t, tc.config))
			require.NoError(t, err)
			require.Equal(t, tc.want, decoded.(*awsApi.EcsFargateInput).CloudExtras)
		})
	}

	t.Run("malformed raw extras are rejected", func(t *testing.T) {
		_, err := decodeTypedConfig(awsApi.TemplateTypeEcsFargate, requestInputs(t, map[string]any{
			"stackConfig": map[string]any{"cloudExtras": map[string]any{"leastPrivilegeRoles": "invalid"}},
		}))
		require.ErrorContains(t, err, "stackConfig.cloudExtras")
	})
}

func TestDecodeTypedConfig_EcsContainerSecrets(t *testing.T) {
	// Old core's typed CloudExtras drops this new field; PR #5's raw
	// stackConfig transport must preserve empty lists (gateway gets none).
	for _, rawOnly := range []bool{false, true} {
		t.Run(map[bool]string{false: "typed", true: "old core raw extras"}[rawOnly], func(t *testing.T) {
			extras := map[string]any{"containerSecrets": map[string]any{
				"gateway": []any{}, "identity": []any{"SIGNING_KEY_PEM", "MONGO_URI"},
			}}
			cfg := map[string]any{"cloudExtras": extras}
			if rawOnly {
				cfg = map[string]any{"cloudExtras": map[string]any{}, "stackConfig": map[string]any{"cloudExtras": extras}}
			}
			decoded, err := decodeTypedConfig(awsApi.TemplateTypeEcsFargate, requestInputs(t, cfg))
			require.NoError(t, err)
			b, err := json.Marshal(decoded.(*awsApi.EcsFargateInput).CloudExtras)
			require.NoError(t, err)
			var got map[string]any
			require.NoError(t, json.Unmarshal(b, &got))
			require.Equal(t, extras["containerSecrets"], got["containerSecrets"])
		})
	}
	t.Run("malformed list is rejected", func(t *testing.T) {
		_, err := decodeTypedConfig(awsApi.TemplateTypeEcsFargate, requestInputs(t, map[string]any{
			"stackConfig": map[string]any{"cloudExtras": map[string]any{"containerSecrets": map[string]any{"identity": "SIGNING_KEY_PEM"}}},
		}))
		require.ErrorContains(t, err, "stackConfig.cloudExtras")
	})
}

// Match core's JSON -> InputValue serialization, including nested maps/lists.
// No plugin process, Pulumi engine, credentials or network access is needed.
func requestInputs(t *testing.T, cfg any) map[string]*scpluginv1.InputValue {
	t.Helper()
	b, err := json.Marshal(cfg)
	require.NoError(t, err)
	var raw map[string]any
	require.NoError(t, json.Unmarshal(b, &raw))
	var encode func(any) *scpluginv1.InputValue
	encode = func(v any) *scpluginv1.InputValue {
		switch v := v.(type) {
		case string:
			return &scpluginv1.InputValue{Value: &scpluginv1.InputValue_StringValue{StringValue: v}}
		case bool:
			return &scpluginv1.InputValue{Value: &scpluginv1.InputValue_BoolValue{BoolValue: v}}
		case float64:
			return &scpluginv1.InputValue{Value: &scpluginv1.InputValue_DoubleValue{DoubleValue: v}}
		case map[string]any:
			fields := make(map[string]*scpluginv1.InputValue, len(v))
			for k, item := range v {
				if iv := encode(item); iv != nil {
					fields[k] = iv
				}
			}
			return &scpluginv1.InputValue{Value: &scpluginv1.InputValue_MapValue{MapValue: &scpluginv1.InputMap{Fields: fields}}}
		case []any:
			items := make([]*scpluginv1.InputValue, len(v))
			for i, item := range v {
				items[i] = encode(item)
			}
			return &scpluginv1.InputValue{Value: &scpluginv1.InputValue_ListValue{ListValue: &scpluginv1.InputList{Items: items}}}
		default:
			return nil
		}
	}
	return encode(raw).GetMapValue().GetFields()
}
