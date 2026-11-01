// SPDX-License-Identifier: MIT
// Copyright (c) Simple Container

package main

import (
	"testing"

	pApi "github.com/simple-container-com/api/pkg/clouds/pulumi/api"
	scpluginv1 "github.com/simple-container-com/api/pkg/plugin/proto/v1"
	"github.com/stretchr/testify/require"

	awsApi "github.com/simple-container-com/sc-plugin-aws/api"
)

// TestProvisionCollectorIncomingEnvVars locks in the invariant live-caught
// 2026-11-01 on forge-notifier run 41336224941: ProvisionRequest.compute_env_vars
// MUST be exposed via EnvVariables() + SecretEnvVariables() for ALL cfg
// types — Lambda, ECS, static-site, bucket. Pre-fix, the collector only
// extracted the SECRET subset for ECS stacks that also had a non-empty
// `cloudExtras.containerSecrets`; every other case got an empty collector,
// so a Lambda stack with `uses: [mongodb]` never received MONGO_USER /
// MONGO_PASSWORD on its container env.
func TestProvisionCollectorIncomingEnvVars(t *testing.T) {
	req := &scpluginv1.ProvisionRequest{
		ResourceType: awsApi.TemplateTypeAwsLambda,
		ComputeEnvVars: []*scpluginv1.ComputeEnvVariable{
			{Name: "MONGO_PASSWORD", Value: "pw", Secret: true, ResourceName: "mongodb", ResourceType: "mongodb-atlas", StackName: "infra"},
			{Name: "MONGO_USER", Value: "user", Secret: false, ResourceName: "mongodb", ResourceType: "mongodb-atlas", StackName: "infra"},
			{Name: "MONGO_DATABASE", Value: "app", Secret: false, ResourceName: "mongodb", ResourceType: "mongodb-atlas", StackName: "infra"},
			nil, // defensive: a nil entry must not crash
		},
	}
	// cfg is irrelevant to the pool population — exercise with Lambda, ECS, nil.
	for _, cfg := range []any{&awsApi.LambdaInput{}, &awsApi.EcsFargateInput{}, nil} {
		c := newProvisionCollector(req, cfg)
		require.Equal(t, []pApi.ComputeEnvVariable{
			{Name: "MONGO_PASSWORD", Value: "pw", Secret: true, ResourceName: "mongodb", ResourceType: "mongodb-atlas", StackName: "infra"},
		}, c.SecretEnvVariables(), "secret env vars must flow regardless of cfg type")
		require.Equal(t, []pApi.ComputeEnvVariable{
			{Name: "MONGO_USER", Value: "user", Secret: false, ResourceName: "mongodb", ResourceType: "mongodb-atlas", StackName: "infra"},
			{Name: "MONGO_DATABASE", Value: "app", Secret: false, ResourceName: "mongodb", ResourceType: "mongodb-atlas", StackName: "infra"},
		}, c.EnvVariables(), "plain env vars must flow regardless of cfg type")
		require.Empty(t, c.ToResponse().GetEnvVars(), "incoming env vars are not outgoing compute mutations")
	}
}

// TestProvisionCollectorEcsContainerSecrets locks in the ECS container-secrets
// flow: an ECS stack with `cloudExtras.containerSecrets` listing a name whose
// value arrives via ProvisionRequest.compute_env_vars uses the collector's
// SecretEnvVariables() to validate the referenced secret exists.
func TestProvisionCollectorEcsContainerSecrets(t *testing.T) {
	req := &scpluginv1.ProvisionRequest{
		ResourceType: awsApi.TemplateTypeEcsFargate,
		Inputs: requestInputs(t, map[string]any{
			"containers": []any{map[string]any{"name": "identity"}, map[string]any{"name": "gateway"}},
			"stackConfig": map[string]any{"cloudExtras": map[string]any{"containerSecrets": map[string]any{
				"gateway": []any{}, "identity": []any{"RESOURCE_PASSWORD"},
			}}},
		}),
		ComputeEnvVars: []*scpluginv1.ComputeEnvVariable{
			{Name: "RESOURCE_PASSWORD", Value: "resource-secret", Secret: true, ResourceName: "db", ResourceType: "mongodb", StackName: "parent"},
		},
	}
	cfg, err := decodeTypedConfig(req.GetResourceType(), req.GetInputs())
	require.NoError(t, err)
	collector := newProvisionCollector(req, cfg)
	require.Equal(t, []pApi.ComputeEnvVariable{
		{Name: "RESOURCE_PASSWORD", Value: "resource-secret", Secret: true, ResourceName: "db", ResourceType: "mongodb", StackName: "parent"},
	}, collector.SecretEnvVariables())
	require.NoError(t, cfg.(*awsApi.EcsFargateInput).ValidateContainerSecrets([]string{collector.SecretEnvVariables()[0].Name}))
	require.Empty(t, collector.ToResponse().GetEnvVars(), "incoming secrets are not outgoing compute mutations")
}
