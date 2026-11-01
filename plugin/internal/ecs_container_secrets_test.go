// SPDX-License-Identifier: MIT
// Copyright (c) Simple Container

package aws

import (
	"strings"
	"testing"

	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	sdk "github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/simple-container-com/api/pkg/api"
	pApi "github.com/simple-container-com/api/pkg/clouds/pulumi/api"
	clouds "github.com/simple-container-com/sc-plugin-aws/api"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func scopedSecretsInput(t *testing.T, extras string) *clouds.EcsFargateInput {
	t.Helper()
	in := compatibilityInput(nil, "", false)
	if extras != "" {
		require.NoError(t, yaml.Unmarshal([]byte(extras), &in.CloudExtras))
	}
	in.Secrets = map[string]string{
		"MONGO_URI": "stack-mongo", "SIGNING_KEY_PEM": "signing-key", "MAIL_URL": "smtp-url",
		"PROFILES_SERVICE_KEY": "profiles-key", "CATALOG_SERVICE_KEY": "catalog-key",
		"MATCH_SERVICE_KEY": "match-key", "BILLING_SERVICE_KEY": "billing-key", "AGENT_SERVICE_KEY": "agent-key",
	}
	in.Volumes = nil
	for _, name := range []string{"gateway", "identity", "profiles", "catalog", "match", "billing", "agent"} {
		in.Containers = append(in.Containers, clouds.EcsFargateContainer{
			Name: name, Port: 8080,
			Env: map[string]string{"APP_ENV": "staging", "PORT": "8080", "SIGNING_KEY_PEM": "must-not-fall-back-to-plaintext"},
		})
	}
	in.IngressContainer = in.Containers[0]
	return in
}

// Run the real cluster builder; only the Pulumi monitor/provider is mocked.
func renderScopedSecrets(t *testing.T, in *clouds.EcsFargateInput, wantError string) map[string]resource.PropertyMap {
	t.Helper()
	return renderEcsGraph(t, func(ctx *sdk.Context, stack api.Stack, params pApi.ProvisionParams, deploy api.StackParams, input *clouds.EcsFargateInput, ref *EcsFargateOutput) error {
		collector := params.ComputeContext.(*pApi.Collector)
		collector.AddSecretEnvVariableIfNotExist("MONGO_URI", "context-mongo", "mongodb", "db", "app")
		collector.AddSecretEnvVariableIfNotExist("RESOURCE_PASSWORD", "resource-password", "mongodb", "db", "app")
		collector.AddEnvVariableIfNotExist("MONGO_DATABASE", "app", "mongodb", "db", "app")
		for _, c := range input.Containers[1:] {
			ref.Images = append(ref.Images, &ECRImage{Container: c, DeployImageRef: sdk.String("example/app@sha256:abc").ToStringOutput()})
		}
		err := createEcsFargateCluster(ctx, stack, params, deploy, input, ref)
		if wantError != "" {
			require.ErrorContains(t, err, wantError)
			return nil
		}
		return err
	}, in)
}

func TestEcsContainerSecretsRecipients(t *testing.T) {
	all := []string{"MONGO_URI", "SIGNING_KEY_PEM", "MAIL_URL", "PROFILES_SERVICE_KEY", "CATALOG_SERVICE_KEY", "MATCH_SERVICE_KEY", "BILLING_SERVICE_KEY", "AGENT_SERVICE_KEY", "RESOURCE_PASSWORD"}
	for _, tc := range []struct {
		name, extras string
		want         map[string][]string
	}{
		{name: "legacy omitted"},
		{name: "legacy empty map", extras: "containerSecrets: {}"},
		{name: "partial opt in", extras: "containerSecrets: {gateway: [], identity: [SIGNING_KEY_PEM, SIGNING_KEY_PEM, RESOURCE_PASSWORD]}", want: map[string][]string{
			"gateway": {}, "identity": {"SIGNING_KEY_PEM", "RESOURCE_PASSWORD"},
		}},
		{name: "InnMind", extras: `containerSecrets:
  gateway: []
  identity: [MONGO_URI, SIGNING_KEY_PEM, MAIL_URL, PROFILES_SERVICE_KEY, CATALOG_SERVICE_KEY, MATCH_SERVICE_KEY, BILLING_SERVICE_KEY, AGENT_SERVICE_KEY]
  profiles: [MONGO_URI, PROFILES_SERVICE_KEY]
  catalog: [MONGO_URI, CATALOG_SERVICE_KEY]
  match: [MONGO_URI, MATCH_SERVICE_KEY, MAIL_URL]
  billing: [MONGO_URI, BILLING_SERVICE_KEY]
  agent: [MONGO_URI, AGENT_SERVICE_KEY]
`, want: map[string][]string{
			"gateway":  {},
			"identity": {"MONGO_URI", "SIGNING_KEY_PEM", "MAIL_URL", "PROFILES_SERVICE_KEY", "CATALOG_SERVICE_KEY", "MATCH_SERVICE_KEY", "BILLING_SERVICE_KEY", "AGENT_SERVICE_KEY"},
			"profiles": {"MONGO_URI", "PROFILES_SERVICE_KEY"}, "catalog": {"MONGO_URI", "CATALOG_SERVICE_KEY"},
			"match": {"MONGO_URI", "MATCH_SERVICE_KEY", "MAIL_URL"}, "billing": {"MONGO_URI", "BILLING_SERVICE_KEY"}, "agent": {"MONGO_URI", "AGENT_SERVICE_KEY"},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			graph := renderScopedSecrets(t, scopedSecretsInput(t, tc.extras), "")
			containers := graph["awsx:ecs:FargateService/app-prod-service"]["taskDefinitionArgs"].ObjectValue()["containers"].ObjectValue()
			require.Len(t, containers, 7)
			for name, c := range containers {
				want, scoped := tc.want[string(name)]
				if !scoped {
					want = all
				}
				var names []string
				for _, s := range c.ObjectValue()["secrets"].ArrayValue() {
					secretName := s.ObjectValue()["name"].StringValue()
					names = append(names, secretName)
					resourceName := "--prod--values----" + secretName
					if secretName == "RESOURCE_PASSWORD" {
						resourceName = "--prod--mongodb--db--RESOURCE_PASSWORD"
					}
					require.Equal(t, "arn:aws:test:eu-west-1:123456789012:"+resourceName, s.ObjectValue()["valueFrom"].StringValue())
				}
				require.ElementsMatch(t, want, names, "container %s", name)
				env := map[string]string{}
				for _, e := range c.ObjectValue()["environment"].ArrayValue() {
					env[e.ObjectValue()["name"].StringValue()] = e.ObjectValue()["value"].StringValue()
				}
				require.Equal(t, map[string]string{"APP_ENV": "staging", "PORT": "8080", "MONGO_DATABASE": "app", api.ComputeEnv.StackVersion: ""}, env)
			}
			var secretCount int
			for key := range graph {
				if strings.HasPrefix(key, "aws:secretsmanager/secret:Secret/") {
					secretCount++
				}
			}
			require.Equal(t, 9, secretCount, "each stack/context secret is created once")
			mongoValue := graph["aws:secretsmanager/secretVersion:SecretVersion/--prod--values----MONGO_URI"]["secretString"]
			require.True(t, mongoValue.IsSecret())
			require.Equal(t, "stack-mongo", mongoValue.SecretValue().Element.StringValue())
		})
	}
}

func TestEcsContainerSecretsRejectInvalidReferences(t *testing.T) {
	for _, tc := range []struct{ name, extras, err string }{
		{"unknown container", "containerSecrets: {identitty: []}", `unknown container "identitty"`},
		{"unknown secret", "containerSecrets: {identity: [SIGNING_KEY_PEM_TYPO]}", `unknown secret "SIGNING_KEY_PEM_TYPO"`},
		{"plain env is not a secret", "containerSecrets: {identity: [APP_ENV]}", `unknown secret "APP_ENV"`},
		{"empty name", "containerSecrets: {identity: ['']}", `unknown secret ""`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			graph := renderScopedSecrets(t, scopedSecretsInput(t, tc.extras), tc.err)
			for key := range graph {
				require.NotContains(t, key, "secretsmanager/")
				require.NotContains(t, key, "FargateService/")
			}
		})
	}
}
