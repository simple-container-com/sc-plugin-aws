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

func TestSesConfigurationSet_AdvertisedAndDispatched(t *testing.T) {
	resp, err := (&awsPlugin{}).Schema(context.Background(), &scpluginv1.SchemaRequest{})
	require.NoError(t, err)
	require.Contains(t, resp.GetResourceTypes(), awsApi.ResourceTypeSesConfigurationSet)
	require.Contains(t, resp.GetComputeProcessorTypes(), awsApi.ResourceTypeSesConfigurationSet)
	require.Contains(t, provisionDispatch, awsApi.ResourceTypeSesConfigurationSet)
	require.Contains(t, computeDispatch, awsApi.ResourceTypeSesConfigurationSet)
}

func TestDecodeTypedConfig_SesConfigurationSet(t *testing.T) {
	creds := `{"account":"645119433725","accessKey":"x","secretAccessKey":"y","region":"eu-central-1"}`
	raw, err := json.Marshal(&api.PluginFieldConfig{
		TypeName:    awsApi.ResourceTypeSesConfigurationSet,
		Credentials: creds,
		Raw: map[string]any{
			"region":         "eu-central-1",
			"events":         []any{"BOUNCE", "COMPLAINT", "DELIVERY"},
			"httpsEndpoints": []any{"https://mautic.alphamind.co/mailer/callback"},
		},
	})
	require.NoError(t, err)
	var cfg map[string]any
	require.NoError(t, json.Unmarshal(raw, &cfg))

	decoded, err := decodeTypedConfig(awsApi.ResourceTypeSesConfigurationSet, requestInputs(t, cfg))
	require.NoError(t, err)
	in := decoded.(*awsApi.SesConfigurationSet)
	require.Equal(t, "eu-central-1", in.Region)
	require.Equal(t, []string{"BOUNCE", "COMPLAINT", "DELIVERY"}, in.Events)
	require.Equal(t, []string{"https://mautic.alphamind.co/mailer/callback"}, in.HttpsEndpoints)
	require.Equal(t, creds, in.CredentialsValue())
	require.NoError(t, in.Validate())
}

func TestDecodeTypedConfig_SesSmtpUserAPIAccess(t *testing.T) {
	raw, err := json.Marshal(&api.PluginFieldConfig{
		TypeName: awsApi.ResourceTypeSesSmtpUser,
		Raw: map[string]any{
			"identities":       []any{"innmind.com"},
			"configurationSet": "mautic-ses-events--prod",
			"apiAccess":        true,
		},
	})
	require.NoError(t, err)
	var cfg map[string]any
	require.NoError(t, json.Unmarshal(raw, &cfg))

	decoded, err := decodeTypedConfig(awsApi.ResourceTypeSesSmtpUser, requestInputs(t, cfg))
	require.NoError(t, err)
	in := decoded.(*awsApi.SesSmtpUser)
	require.True(t, in.APIAccess)
	require.Equal(t, "mautic-ses-events--prod", in.ConfigurationSet)
	require.NoError(t, in.Validate())
}
