// SPDX-License-Identifier: MIT
// Copyright (c) Simple Container

package aws

import (
	"testing"

	"github.com/simple-container-com/api/pkg/api"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestToEcsFargateContainerSecrets(t *testing.T) {
	var cfg api.StackConfigCompose
	require.NoError(t, yaml.Unmarshal([]byte(`runs: [web]
env: {APP_ENV: staging}
secrets: {SIGNING_KEY_PEM: test-key}
cloudExtras:
  containerSecrets:
    web: [SIGNING_KEY_PEM, RESOURCE_PASSWORD]
`), &cfg))
	out, err := ToEcsFargateConfig(validTemplateConfig(), composeWith(ingressService("web")), &cfg)
	require.NoError(t, err, "resource secret names are validated later, once compute context is available")
	b, err := yaml.Marshal(out.(*EcsFargateInput).CloudExtras)
	require.NoError(t, err)
	var raw map[string]any
	require.NoError(t, yaml.Unmarshal(b, &raw))
	require.Equal(t, map[string]any{"web": []any{"SIGNING_KEY_PEM", "RESOURCE_PASSWORD"}}, raw["containerSecrets"])
	require.Equal(t, map[string]string{"APP_ENV": "staging"}, out.(*EcsFargateInput).Containers[0].Env)
}

func TestToEcsFargateContainerSecretsUnknownContainer(t *testing.T) {
	var cfg api.StackConfigCompose
	require.NoError(t, yaml.Unmarshal([]byte("runs: [web]\ncloudExtras:\n  containerSecrets: {typo: []}\n"), &cfg))
	_, err := ToEcsFargateConfig(validTemplateConfig(), composeWith(ingressService("web")), &cfg)
	require.ErrorContains(t, err, `unknown container "typo"`)
}
