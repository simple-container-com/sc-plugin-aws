// SPDX-License-Identifier: MIT
// Copyright (c) Simple Container

package main

import (
	"testing"

	pApi "github.com/simple-container-com/api/pkg/clouds/pulumi/api"
	scpluginv1 "github.com/simple-container-com/api/pkg/plugin/proto/v1"
	awsApi "github.com/simple-container-com/sc-plugin-aws/api"
	"github.com/stretchr/testify/require"
)

func TestProvisionCollectorEcsContainerSecrets(t *testing.T) {
	req := &scpluginv1.ProvisionRequest{
		ResourceType: awsApi.TemplateTypeEcsFargate,
		Inputs: requestInputs(t, map[string]any{
			"containers": []any{map[string]any{"name": "identity"}, map[string]any{"name": "gateway"}},
			// Exercise an older core, which only preserves the raw extras.
			"stackConfig": map[string]any{"cloudExtras": map[string]any{"containerSecrets": map[string]any{
				"gateway": []any{}, "identity": []any{"RESOURCE_PASSWORD"},
			}}},
		}),
		ComputeEnvVars: []*scpluginv1.ComputeEnvVariable{
			{Name: "RESOURCE_PASSWORD", Value: "resource-secret", Secret: true, ResourceName: "db", ResourceType: "mongodb", StackName: "parent"},
			{Name: "MONGO_DATABASE", Value: "app", Secret: false},
			nil,
		},
	}
	cfg, err := decodeTypedConfig(req.GetResourceType(), req.GetInputs())
	require.NoError(t, err)
	collector := newProvisionCollector(req, cfg)
	require.Equal(t, []pApi.ComputeEnvVariable{{Name: "RESOURCE_PASSWORD", Value: "resource-secret", Secret: true, ResourceName: "db", ResourceType: "mongodb", StackName: "parent"}}, collector.SecretEnvVariables())
	require.NoError(t, cfg.(*awsApi.EcsFargateInput).ValidateContainerSecrets([]string{collector.SecretEnvVariables()[0].Name}))
	require.Empty(t, collector.EnvVariables(), "plain env behavior stays as before")
	require.Empty(t, collector.ToResponse().GetEnvVars(), "incoming secrets are not outgoing compute mutations")

	for _, legacy := range []any{
		&awsApi.EcsFargateInput{},
		&awsApi.EcsFargateInput{CloudExtras: &awsApi.CloudExtras{}},
		&awsApi.EcsFargateInput{CloudExtras: &awsApi.CloudExtras{ContainerSecrets: map[string][]string{}}},
		&awsApi.LambdaInput{},
	} {
		c := newProvisionCollector(req, legacy)
		require.Empty(t, c.SecretEnvVariables(), "unconfigured stacks retain the existing empty input context")
		require.Empty(t, c.EnvVariables())
	}
}
