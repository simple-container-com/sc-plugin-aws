// SPDX-License-Identifier: MIT
// Copyright (c) Simple Container

package main

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/simple-container-com/api/pkg/api"
	scpluginv1 "github.com/simple-container-com/api/pkg/plugin/proto/v1"

	awsApi "github.com/simple-container-com/sc-plugin-aws/api"
)

// Core discovers plugin-owned types from Schema, so the new resource must be
// advertised both as a resource and as a compute processor, and dispatched.
func TestSesSmtpUser_AdvertisedAndDispatched(t *testing.T) {
	resp, err := (&awsPlugin{}).Schema(context.Background(), &scpluginv1.SchemaRequest{})
	require.NoError(t, err)
	require.Contains(t, resp.GetResourceTypes(), awsApi.ResourceTypeSesSmtpUser)
	require.Contains(t, resp.GetComputeProcessorTypes(), awsApi.ResourceTypeSesSmtpUser)
	require.Contains(t, provisionDispatch, awsApi.ResourceTypeSesSmtpUser)
	require.Contains(t, computeDispatch, awsApi.ResourceTypeSesSmtpUser)
}

// Core sends a plugin-owned resource's raw server.yaml config (PluginFieldConfig
// marshals Raw flat, with credentials resolved) as JSON-encoded inputs.
func TestDecodeTypedConfig_SesSmtpUser(t *testing.T) {
	creds := `{"account":"645119433725","accessKey":"x","secretAccessKey":"y","region":"eu-central-1"}`
	raw, err := json.Marshal(&api.PluginFieldConfig{
		TypeName:    awsApi.ResourceTypeSesSmtpUser,
		Credentials: creds,
		Raw: map[string]any{
			"account":          "645119433725",
			"identities":       []any{"innmind.com"},
			"configurationSet": "mautic",
			"fromAddresses":    []any{"*@innmind.com", "noreply@innmind.com"},
		},
	})
	require.NoError(t, err)
	var cfg map[string]any
	require.NoError(t, json.Unmarshal(raw, &cfg))

	decoded, err := decodeTypedConfig(awsApi.ResourceTypeSesSmtpUser, requestInputs(t, cfg))
	require.NoError(t, err)
	in := decoded.(*awsApi.SesSmtpUser)
	require.Equal(t, []string{"innmind.com"}, in.Identities)
	require.Equal(t, "mautic", in.ConfigurationSet)
	require.Equal(t, []string{"*@innmind.com", "noreply@innmind.com"}, in.FromAddresses)
	require.Equal(t, "645119433725", in.Account)
	require.Equal(t, creds, in.CredentialsValue())
	require.NoError(t, in.Validate())
}
