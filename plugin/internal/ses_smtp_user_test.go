// SPDX-License-Identifier: MIT
// Copyright (c) Simple Container

package aws

import (
	"context"
	"encoding/json"
	"sync"
	"testing"

	sdkAws "github.com/pulumi/pulumi-aws/sdk/v6/go/aws"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	sdk "github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/stretchr/testify/require"

	"github.com/simple-container-com/api/pkg/api"
	"github.com/simple-container-com/api/pkg/api/logger"
	pApi "github.com/simple-container-com/api/pkg/clouds/pulumi/api"
	"github.com/simple-container-com/api/pkg/plugin/runtime"
	"github.com/simple-container-com/sc-plugin-aws/api"
)

// Vectors as used by terraform-provider-aws's access-key tests, cross-checked
// with the conversion script in the AWS SES developer guide.
func TestSesSmtpPasswordV4(t *testing.T) {
	for _, tc := range []struct{ region, secret, want string }{
		{"eu-central-1", "some+secret+key", "BMXhUYlu5Z3gSXVQORxlVa7XPaz91aGWdfHxvkOZdWZ2"},
		{"eu-central-1", "another+secret+key", "BBbphbrQmrKMx42d1N6+C7VINYEBGI5v9VsZeTxwskfh"},
		{"us-west-1", "some+secret+key", "BH+jbMzper5WwlwUar9E1ySBqHa9whi0GPo+sJ0mVYJj"},
		{"us-west-1", "another+secret+key", "BKVmjjMDFk/qqw8EROW99bjCS65PF8WKvK5bSr4Y6EqF"},
	} {
		require.Equal(t, tc.want, sesSmtpPasswordV4(tc.secret, tc.region), "%s/%s", tc.region, tc.secret)
	}
}

type sesPolicyDoc struct {
	Version   string
	Statement []struct {
		Effect    string
		Action    []string
		Resource  []string
		Condition map[string]map[string][]string
	}
}

func parseSesPolicy(t *testing.T, cfg *aws.SesSmtpUser, region, account string) sesPolicyDoc {
	t.Helper()
	doc, err := sesSmtpUserPolicy(cfg, region, account)
	require.NoError(t, err)
	var res sesPolicyDoc
	require.NoError(t, json.Unmarshal([]byte(doc), &res))
	return res
}

func TestSesSmtpUserPolicy_OnlySendRawEmailOnIdentities(t *testing.T) {
	doc := parseSesPolicy(t, &aws.SesSmtpUser{
		Identities: []string{"innmind.com", "arn:aws:ses:eu-central-1:111111111111:identity/other.com"},
	}, "eu-central-1", "645119433725")

	require.Equal(t, "2012-10-17", doc.Version)
	require.Len(t, doc.Statement, 1)
	s := doc.Statement[0]
	require.Equal(t, "Allow", s.Effect)
	require.Equal(t, []string{"ses:SendRawEmail"}, s.Action)
	require.Equal(t, []string{
		"arn:aws:ses:eu-central-1:645119433725:identity/innmind.com",
		"arn:aws:ses:eu-central-1:111111111111:identity/other.com",
	}, s.Resource)
	require.Nil(t, s.Condition)
}

func TestSesSmtpUserPolicy_ConfigurationSetAndFromAddresses(t *testing.T) {
	doc := parseSesPolicy(t, &aws.SesSmtpUser{
		Identities:       []string{"innmind.com"},
		ConfigurationSet: "mautic",
		FromAddresses:    []string{"*@innmind.com", " noreply@innmind.com "},
	}, "eu-central-1", "645119433725")

	s := doc.Statement[0]
	require.Equal(t, []string{
		"arn:aws:ses:eu-central-1:645119433725:identity/innmind.com",
		"arn:aws:ses:eu-central-1:645119433725:configuration-set/mautic",
	}, s.Resource)
	require.Equal(t, map[string]map[string][]string{
		"StringLike": {"ses:FromAddress": {"*@innmind.com", "noreply@innmind.com"}},
	}, s.Condition)
}

func TestSesSmtpUserPolicy_Partition(t *testing.T) {
	doc := parseSesPolicy(t, &aws.SesSmtpUser{Identities: []string{"example.cn"}}, "cn-north-1", "123456789012")
	require.Equal(t, []string{"arn:aws-cn:ses:cn-north-1:123456789012:identity/example.cn"}, doc.Statement[0].Resource)
}

func TestSesSmtpEnvVariablesAndTplExtension(t *testing.T) {
	vars := sesSmtpEnvVariables("mautic-ses--prod", "email-smtp.eu-central-1.amazonaws.com", "587", "AKIAEXAMPLE", "pw", "eu-central-1")
	got := map[string]sesSmtpEnvVariable{}
	for _, v := range vars {
		got[v.name] = v
	}
	for name, want := range map[string]struct {
		value  string
		secret bool
	}{
		"SMTP_MAUTIC_SES__PROD_HOST":     {"email-smtp.eu-central-1.amazonaws.com", false},
		"SMTP_MAUTIC_SES__PROD_PORT":     {"587", false},
		"SMTP_MAUTIC_SES__PROD_USER":     {"AKIAEXAMPLE", true},
		"SMTP_MAUTIC_SES__PROD_PASSWORD": {"pw", true},
		"SMTP_HOST":                      {"email-smtp.eu-central-1.amazonaws.com", false},
		"SMTP_PORT":                      {"587", false},
		"SMTP_USER":                      {"AKIAEXAMPLE", true},
		"SMTP_PASSWORD":                  {"pw", true},
		"SES_MAUTIC_SES__PROD_REGION":    {"eu-central-1", false},
		"SES_REGION":                     {"eu-central-1", false},
	} {
		require.Contains(t, got, name)
		require.Equal(t, want.value, got[name].value, name)
		require.Equal(t, want.secret, got[name].secret, name)
	}
	require.Len(t, vars, 10)

	ext := sesSmtpTplExtension(&aws.SesSmtpUser{}, "h", "587", "u", "p", "r")
	require.Equal(t, map[string]string{"smtp-user": "u", "smtp-password": "p", "smtp-host": "h", "smtp-port": "587", "region": "r"}, ext)
	ext = sesSmtpTplExtension(&aws.SesSmtpUser{ConfigurationSet: "mautic"}, "h", "587", "u", "p", "r")
	require.Equal(t, "mautic", ext["configuration-set"])
}

type sesMocks struct {
	mu        sync.Mutex
	resources map[string]resource.PropertyMap
	calls     []string
}

func (m *sesMocks) Call(args sdk.MockCallArgs) (resource.PropertyMap, error) {
	m.mu.Lock()
	m.calls = append(m.calls, args.Token)
	m.mu.Unlock()
	if args.Token == "aws:index/getCallerIdentity:getCallerIdentity" {
		return resource.NewPropertyMapFromMap(map[string]any{"accountId": "999999999999", "arn": "a", "userId": "u", "id": "i"}), nil
	}
	return args.Args, nil
}

func (m *sesMocks) NewResource(args sdk.MockResourceArgs) (string, resource.PropertyMap, error) {
	out := args.Inputs.Copy()
	switch args.TypeToken {
	case "aws:iam/user:User":
		out["name"] = resource.NewStringProperty(args.Name + "-1234567")
	case "aws:iam/accessKey:AccessKey":
		out["secret"] = resource.NewStringProperty("some+secret+key")
		out["sesSmtpPasswordV4"] = resource.NewStringProperty("provider-derived")
	}
	m.mu.Lock()
	if m.resources == nil {
		m.resources = map[string]resource.PropertyMap{}
	}
	m.resources[args.TypeToken] = out
	m.mu.Unlock()
	id := args.Name + "-id"
	if args.TypeToken == "aws:iam/accessKey:AccessKey" {
		id = "AKIAEXAMPLE"
	}
	return id, out, nil
}

func runSesSmtpUser(t *testing.T, cfg *aws.SesSmtpUser) (map[string]any, map[string]bool, *sesMocks) {
	t.Helper()
	mocks := &sesMocks{}
	values := map[string]any{}
	secrets := map[string]bool{}
	err := sdk.RunErr(func(ctx *sdk.Context) error {
		provider, err := sdkAws.NewProvider(ctx, "aws", &sdkAws.ProviderArgs{})
		if err != nil {
			return err
		}
		out, err := SesSmtpUser(ctx, api.Stack{Name: "alphamind-co"}, api.ResourceInput{
			Descriptor: &api.ResourceDescriptor{
				Type:   aws.ResourceTypeSesSmtpUser,
				Name:   "mautic-ses",
				Config: api.Config{Config: cfg},
			},
			StackParams: &api.StackParams{StackName: "alphamind-co", Environment: "prod"},
		}, pApi.ProvisionParams{Log: logger.New(), Provider: provider})
		if err != nil {
			return err
		}
		require.IsType(t, &SesSmtpUserOutput{}, out.Ref)
		exports, err := runtime.HarvestExports(context.Background(), ctx)
		if err != nil {
			return err
		}
		for k, v := range exports {
			values[k] = v.GetStringValue()
			secrets[k] = v.GetSecret()
		}
		return nil
	}, sdk.WithMocks("project", "stack", mocks))
	require.NoError(t, err)
	return values, secrets, mocks
}

func TestSesSmtpUser_ExportsAndSecrets(t *testing.T) {
	// Account comes from the config, region from the credentials blob, so the
	// provider-computed sesSmtpPasswordV4 (same region) is used.
	values, secrets, mocks := runSesSmtpUser(t, &aws.SesSmtpUser{
		AccountConfig: aws.AccountConfig{
			Account:     "645119433725",
			Credentials: api.Credentials{Credentials: `{"region":"eu-central-1","accessKey":"x","secretAccessKey":"y"}`},
		},
		Identities: []string{"innmind.com"},
	})

	require.Equal(t, "AKIAEXAMPLE", values["mautic-ses--prod-ses-smtp-username"])
	require.Equal(t, "provider-derived", values["mautic-ses--prod-ses-smtp-password"])
	require.Equal(t, "email-smtp.eu-central-1.amazonaws.com", values["mautic-ses--prod-ses-smtp-host"])
	require.Equal(t, "587", values["mautic-ses--prod-ses-smtp-port"])
	require.Equal(t, "eu-central-1", values["mautic-ses--prod-ses-region"])
	require.Contains(t, values, "mautic-ses--prod-ses-iam-user")

	require.True(t, secrets["mautic-ses--prod-ses-smtp-password"], "smtp password must be a secret in state")
	require.False(t, secrets["mautic-ses--prod-ses-smtp-host"])

	policy := mocks.resources["aws:iam/userPolicy:UserPolicy"]["policy"].StringValue()
	require.Contains(t, policy, "arn:aws:ses:eu-central-1:645119433725:identity/innmind.com")
	require.NotContains(t, mocks.calls, "aws:index/getCallerIdentity:getCallerIdentity")
	require.Equal(t, mocks.resources["aws:iam/user:User"]["name"], mocks.resources["aws:iam/accessKey:AccessKey"]["user"])
}

func TestSesSmtpUser_RegionDiffersFromProvider(t *testing.T) {
	// SES in a region other than the provider's: derive the password locally
	// for the SES region; the account is looked up from the caller identity.
	values, secrets, mocks := runSesSmtpUser(t, &aws.SesSmtpUser{
		AccountConfig: aws.AccountConfig{
			Region:      "us-west-1",
			Credentials: api.Credentials{Credentials: `{"region":"eu-central-1"}`},
		},
		Identities: []string{"innmind.com"},
	})
	require.Equal(t, "BH+jbMzper5WwlwUar9E1ySBqHa9whi0GPo+sJ0mVYJj", values["mautic-ses--prod-ses-smtp-password"])
	require.True(t, secrets["mautic-ses--prod-ses-smtp-password"])
	require.Equal(t, "email-smtp.us-west-1.amazonaws.com", values["mautic-ses--prod-ses-smtp-host"])
	require.Equal(t, "us-west-1", values["mautic-ses--prod-ses-region"])
	require.Contains(t, mocks.resources["aws:iam/userPolicy:UserPolicy"]["policy"].StringValue(),
		"arn:aws:ses:us-west-1:999999999999:identity/innmind.com")
}

func TestSesSmtpUser_RejectsInvalidConfig(t *testing.T) {
	for name, cfg := range map[string]*aws.SesSmtpUser{
		"no identities": {AccountConfig: aws.AccountConfig{Region: "eu-central-1"}},
		"no region":     {Identities: []string{"innmind.com"}},
	} {
		t.Run(name, func(t *testing.T) {
			err := sdk.RunErr(func(ctx *sdk.Context) error {
				_, err := SesSmtpUser(ctx, api.Stack{Name: "s"}, api.ResourceInput{
					Descriptor:  &api.ResourceDescriptor{Type: aws.ResourceTypeSesSmtpUser, Name: "mautic-ses", Config: api.Config{Config: cfg}},
					StackParams: &api.StackParams{StackName: "s", Environment: "prod"},
				}, pApi.ProvisionParams{Log: logger.New()})
				return err
			}, sdk.WithMocks("project", "stack", &sesMocks{}))
			require.Error(t, err)
		})
	}
}

type sesParentMocks struct {
	outputs map[string]string
	secret  []string
}

func (m *sesParentMocks) Call(args sdk.MockCallArgs) (resource.PropertyMap, error) {
	return args.Args, nil
}

func (m *sesParentMocks) NewResource(args sdk.MockResourceArgs) (string, resource.PropertyMap, error) {
	out := args.Inputs.Copy()
	if args.TypeToken == "pulumi:pulumi:StackReference" {
		outputs := resource.PropertyMap{}
		for k, v := range m.outputs {
			outputs[resource.PropertyKey(k)] = resource.NewStringProperty(v)
		}
		for _, k := range m.secret {
			outputs[resource.PropertyKey(k)] = resource.MakeSecret(outputs[resource.PropertyKey(k)])
		}
		out["outputs"] = resource.NewObjectProperty(outputs)
	}
	return args.Name + "-id", out, nil
}

// tplCollector records emitted env vars and tpl extensions on top of the
// plugin runtime collector.
type tplCollector struct {
	*runtime.Collector
	mu     sync.Mutex
	tpl    map[string]map[string]string
	env    map[string]string
	secret map[string]string
}

func (c *tplCollector) AddEnvVariableIfNotExist(name, value, _, _, _ string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.env[name] = value
}

func (c *tplCollector) AddSecretEnvVariableIfNotExist(name, value, _, _, _ string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.secret[name] = value
}

func (c *tplCollector) AddResourceTplExtension(resName string, values map[string]string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tpl[resName] = values
}

func TestSesSmtpUserComputeProcessor_EmitsSecretsAndTplExtension(t *testing.T) {
	prefix := "mautic-ses--prod-ses-"
	mocks := &sesParentMocks{
		outputs: map[string]string{
			prefix + "smtp-username": "AKIAEXAMPLE",
			prefix + "smtp-password": "BMXhUYlu5Z3gSXVQORxlVa7XPaz91aGWdfHxvkOZdWZ2",
			prefix + "smtp-host":     "email-smtp.eu-central-1.amazonaws.com",
			prefix + "smtp-port":     "587",
			prefix + "region":        "eu-central-1",
		},
		secret: []string{prefix + "smtp-password"},
	}
	collector := &tplCollector{
		Collector: &runtime.Collector{},
		tpl:       map[string]map[string]string{},
		env:       map[string]string{},
		secret:    map[string]string{},
	}
	err := sdk.RunErr(func(ctx *sdk.Context) error {
		_, err := SesSmtpUserComputeProcessor(ctx, api.Stack{Name: "mautic-innmind"}, api.ResourceInput{
			Descriptor: &api.ResourceDescriptor{
				Type:   aws.ResourceTypeSesSmtpUser,
				Name:   "mautic-ses",
				Config: api.Config{Config: &aws.SesSmtpUser{Identities: []string{"innmind.com"}, ConfigurationSet: "mautic"}},
			},
			StackParams: &api.StackParams{StackName: "mautic-innmind", Environment: "prod"},
		}, collector, pApi.ProvisionParams{
			Log:         logger.New(),
			ParentStack: &pApi.ParentInfo{StackName: "alphamind-co", FullReference: "organization/alphamind-co/alphamind-co--prod", UsesResource: true},
		})
		return err
	}, sdk.WithMocks("project", "stack", mocks))
	require.NoError(t, err)

	require.Equal(t, map[string]string{
		"smtp-user":         "AKIAEXAMPLE",
		"smtp-password":     "BMXhUYlu5Z3gSXVQORxlVa7XPaz91aGWdfHxvkOZdWZ2",
		"smtp-host":         "email-smtp.eu-central-1.amazonaws.com",
		"smtp-port":         "587",
		"region":            "eu-central-1",
		"configuration-set": "mautic",
	}, collector.tpl["mautic-ses"])

	require.Equal(t, "BMXhUYlu5Z3gSXVQORxlVa7XPaz91aGWdfHxvkOZdWZ2", collector.secret["SMTP_PASSWORD"])
	require.Equal(t, "AKIAEXAMPLE", collector.secret["SMTP_MAUTIC_SES__PROD_USER"])
	require.Equal(t, "email-smtp.eu-central-1.amazonaws.com", collector.env["SMTP_HOST"])
	require.NotContains(t, collector.env, "SMTP_PASSWORD")
}

func TestSesSmtpUserComputeProcessor_PasswordMustBeSecretInParent(t *testing.T) {
	prefix := "mautic-ses--prod-ses-"
	mocks := &sesParentMocks{outputs: map[string]string{
		prefix + "smtp-username": "AKIAEXAMPLE",
		prefix + "smtp-password": "plaintext",
	}}
	err := sdk.RunErr(func(ctx *sdk.Context) error {
		_, err := SesSmtpUserComputeProcessor(ctx, api.Stack{Name: "mautic-innmind"}, api.ResourceInput{
			Descriptor:  &api.ResourceDescriptor{Type: aws.ResourceTypeSesSmtpUser, Name: "mautic-ses", Config: api.Config{Config: &aws.SesSmtpUser{}}},
			StackParams: &api.StackParams{StackName: "mautic-innmind", Environment: "prod"},
		}, &runtime.Collector{}, pApi.ProvisionParams{
			Log:         logger.New(),
			ParentStack: &pApi.ParentInfo{StackName: "alphamind-co", FullReference: "organization/alphamind-co/alphamind-co--prod"},
		})
		return err
	}, sdk.WithMocks("project", "stack", mocks))
	require.ErrorContains(t, err, "smtp-password")
}
