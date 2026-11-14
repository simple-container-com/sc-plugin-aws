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
	vars := sesSmtpEnvVariables("mautic-ses--prod", "email-smtp.eu-central-1.amazonaws.com", "587", "AKIAEXAMPLE", "pw", "eu-central-1", nil)
	got := map[string]sesSmtpEnvVariable{}
	for _, v := range vars {
		got[v.name] = v
	}
	// Only resource-scoped names: no unscoped SMTP_* / SES_REGION.
	require.Equal(t, map[string]sesSmtpEnvVariable{
		"SMTP_MAUTIC_SES__PROD_HOST":     {"SMTP_MAUTIC_SES__PROD_HOST", "email-smtp.eu-central-1.amazonaws.com", false},
		"SMTP_MAUTIC_SES__PROD_PORT":     {"SMTP_MAUTIC_SES__PROD_PORT", "587", false},
		"SMTP_MAUTIC_SES__PROD_USER":     {"SMTP_MAUTIC_SES__PROD_USER", "AKIAEXAMPLE", true},
		"SMTP_MAUTIC_SES__PROD_PASSWORD": {"SMTP_MAUTIC_SES__PROD_PASSWORD", "pw", true},
		"SES_MAUTIC_SES__PROD_REGION":    {"SES_MAUTIC_SES__PROD_REGION", "eu-central-1", false},
	}, got)
	require.Len(t, vars, 5)

	ext := sesSmtpTplExtension(&aws.SesSmtpUser{}, "h", "587", "u", "p", "r", nil)
	require.Equal(t, map[string]string{"smtp-user": "u", "smtp-password": "p", "smtp-host": "h", "smtp-port": "587", "region": "r"}, ext)
	ext = sesSmtpTplExtension(&aws.SesSmtpUser{ConfigurationSet: "mautic"}, "h", "587", "u", "p", "r", nil)
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

func TestSesSmtpUser_RejectsInvalidConfigBeforeCreatingResources(t *testing.T) {
	creds := api.Credentials{Credentials: `{"region":"eu-central-1"}`}
	for name, tc := range map[string]struct {
		cfg     *aws.SesSmtpUser
		wantErr string
	}{
		"no identities": {&aws.SesSmtpUser{AccountConfig: aws.AccountConfig{Region: "eu-central-1"}}, "identities"},
		"no region":     {&aws.SesSmtpUser{Identities: []string{"innmind.com"}}, "region"},
		// af-south-1 is an SES region, but has no SMTP endpoint.
		"region without smtp endpoint":             {&aws.SesSmtpUser{AccountConfig: aws.AccountConfig{Region: "af-south-1", Credentials: creds}, Identities: []string{"innmind.com"}}, `region "af-south-1" has no Amazon SES SMTP endpoint`},
		"credentials region without smtp endpoint": {&aws.SesSmtpUser{AccountConfig: aws.AccountConfig{Credentials: api.Credentials{Credentials: `{"region":"il-central-1"}`}}, Identities: []string{"innmind.com"}}, `"il-central-1"`},
		"wildcard identity":                        {&aws.SesSmtpUser{AccountConfig: aws.AccountConfig{Credentials: creds}, Identities: []string{"innmind.com", "*"}}, "wildcard"},
		"wildcard identity arn":                    {&aws.SesSmtpUser{AccountConfig: aws.AccountConfig{Credentials: creds}, Identities: []string{"arn:aws:ses:eu-central-1:645119433725:identity/innmind.co?"}}, "wildcard"},
		"name with underscore":                     {&aws.SesSmtpUser{AccountConfig: aws.AccountConfig{Credentials: creds}, Name: "mail_a", Identities: []string{"innmind.com"}}, `name "mail_a"`},
		"name with uppercase":                      {&aws.SesSmtpUser{AccountConfig: aws.AccountConfig{Credentials: creds}, Name: "mailA", Identities: []string{"innmind.com"}}, `name "mailA"`},
	} {
		t.Run(name, func(t *testing.T) {
			mocks := &sesMocks{}
			err := sdk.RunErr(func(ctx *sdk.Context) error {
				_, err := SesSmtpUser(ctx, api.Stack{Name: "s"}, api.ResourceInput{
					Descriptor:  &api.ResourceDescriptor{Type: aws.ResourceTypeSesSmtpUser, Name: "mautic-ses", Config: api.Config{Config: tc.cfg}},
					StackParams: &api.StackParams{StackName: "s", Environment: "prod"},
				}, pApi.ProvisionParams{Log: logger.New()})
				return err
			}, sdk.WithMocks("project", "stack", mocks))
			require.ErrorContains(t, err, tc.wantErr)
			require.Empty(t, mocks.resources, "no IAM resource may be created for an invalid config")
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

// withSesParentOutputs adds the parent exports of one aws-ses-smtp-user.
func (m *sesParentMocks) withSesParentOutputs(resName, user, password, region string) *sesParentMocks {
	if m.outputs == nil {
		m.outputs = map[string]string{}
	}
	prefix := resName + "-ses-"
	m.outputs[prefix+"smtp-username"] = user
	m.outputs[prefix+"smtp-password"] = password
	m.outputs[prefix+"smtp-host"] = sesSmtpHost(region)
	m.outputs[prefix+"smtp-port"] = "587"
	m.outputs[prefix+"region"] = region
	m.secret = append(m.secret, prefix+"smtp-password")
	return m
}

// ifNotExistCollector mirrors SC core's consuming-stack collector
// (pkg/clouds/pulumi/api.Collector): the first value of an env var name wins
// and later ones are dropped. Drops are recorded so tests can assert none of
// a resource's credentials were silently shadowed.
type ifNotExistCollector struct {
	*runtime.Collector
	mu      sync.Mutex
	tpl     map[string]map[string]string
	env     map[string]string
	secret  map[string]string
	dropped []string
}

func newIfNotExistCollector() *ifNotExistCollector {
	return &ifNotExistCollector{
		Collector: &runtime.Collector{},
		tpl:       map[string]map[string]string{},
		env:       map[string]string{},
		secret:    map[string]string{},
	}
}

func (c *ifNotExistCollector) add(target map[string]string, name, value string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, inEnv := c.env[name]
	_, inSecret := c.secret[name]
	if inEnv || inSecret {
		c.dropped = append(c.dropped, name)
		return
	}
	target[name] = value
}

func (c *ifNotExistCollector) AddEnvVariableIfNotExist(name, value, _, _, _ string) {
	c.add(c.env, name, value)
}

func (c *ifNotExistCollector) AddSecretEnvVariableIfNotExist(name, value, _, _, _ string) {
	c.add(c.secret, name, value)
}

func (c *ifNotExistCollector) AddResourceTplExtension(resName string, values map[string]string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tpl[resName] = values
}

var sesTestParent = pApi.ParentInfo{StackName: "alphamind-co", FullReference: "organization/alphamind-co/alphamind-co--prod", UsesResource: true}

func runSesCompute(ctx *sdk.Context, collector pApi.ComputeContextCollector, parent pApi.ParentInfo, resName string, cfg *aws.SesSmtpUser) error {
	_, err := SesSmtpUserComputeProcessor(ctx, api.Stack{Name: "mautic-innmind"}, api.ResourceInput{
		Descriptor:  &api.ResourceDescriptor{Type: aws.ResourceTypeSesSmtpUser, Name: resName, Config: api.Config{Config: cfg}},
		StackParams: &api.StackParams{StackName: "mautic-innmind", Environment: "prod"},
	}, collector, pApi.ProvisionParams{Log: logger.New(), ParentStack: &parent})
	return err
}

func TestSesSmtpUserComputeProcessor_EmitsSecretsAndTplExtension(t *testing.T) {
	mocks := (&sesParentMocks{}).withSesParentOutputs("mautic-ses--prod", "AKIAEXAMPLE", "BMXhUYlu5Z3gSXVQORxlVa7XPaz91aGWdfHxvkOZdWZ2", "eu-central-1")
	collector := newIfNotExistCollector()
	err := sdk.RunErr(func(ctx *sdk.Context) error {
		return runSesCompute(ctx, collector, sesTestParent, "mautic-ses", &aws.SesSmtpUser{Identities: []string{"innmind.com"}, ConfigurationSet: "mautic"})
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

	require.Equal(t, map[string]string{
		"SMTP_MAUTIC_SES__PROD_USER":     "AKIAEXAMPLE",
		"SMTP_MAUTIC_SES__PROD_PASSWORD": "BMXhUYlu5Z3gSXVQORxlVa7XPaz91aGWdfHxvkOZdWZ2",
	}, collector.secret)
	require.Equal(t, map[string]string{
		"SMTP_MAUTIC_SES__PROD_HOST":  "email-smtp.eu-central-1.amazonaws.com",
		"SMTP_MAUTIC_SES__PROD_PORT":  "587",
		"SES_MAUTIC_SES__PROD_REGION": "eu-central-1",
	}, collector.env)
	require.Empty(t, collector.dropped)
}

// Two SES resources in one client's `uses:` must each keep their own
// credentials, with nothing shadowed by core's first-wins env semantics.
func TestSesSmtpUserComputeProcessor_TwoResourcesDoNotShadowEachOther(t *testing.T) {
	mocks := (&sesParentMocks{}).
		withSesParentOutputs("mail-a--prod", "AKIAA", "password-a", "eu-central-1").
		withSesParentOutputs("mail-b--prod", "AKIAB", "password-b", "us-east-1")
	collector := newIfNotExistCollector()
	err := sdk.RunErr(func(ctx *sdk.Context) error {
		if err := runSesCompute(ctx, collector, sesTestParent, "mail-a", &aws.SesSmtpUser{}); err != nil {
			return err
		}
		return runSesCompute(ctx, collector, sesTestParent, "mail-b", &aws.SesSmtpUser{})
	}, sdk.WithMocks("project", "stack", mocks))
	require.NoError(t, err)

	require.Empty(t, collector.dropped)
	require.Equal(t, "password-a", collector.secret["SMTP_MAIL_A__PROD_PASSWORD"])
	require.Equal(t, "password-b", collector.secret["SMTP_MAIL_B__PROD_PASSWORD"])
	require.Equal(t, "AKIAA", collector.secret["SMTP_MAIL_A__PROD_USER"])
	require.Equal(t, "AKIAB", collector.secret["SMTP_MAIL_B__PROD_USER"])
	require.Equal(t, "email-smtp.us-east-1.amazonaws.com", collector.env["SMTP_MAIL_B__PROD_HOST"])
	require.Equal(t, "password-a", collector.tpl["mail-a"]["smtp-password"])
	require.Equal(t, "password-b", collector.tpl["mail-b"]["smtp-password"])
	for _, unscoped := range []string{"SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASSWORD", "SES_REGION"} {
		require.NotContains(t, collector.env, unscoped)
		require.NotContains(t, collector.secret, unscoped)
	}
}

// `mail_a` would normalize to the same SMTP_MAIL_A__PROD_* names as `mail-a`
// and be silently shadowed; it is rejected instead.
func TestSesSmtpUserComputeProcessor_RejectsCollidingName(t *testing.T) {
	mocks := (&sesParentMocks{}).
		withSesParentOutputs("mail-a--prod", "AKIAA", "password-a", "eu-central-1").
		withSesParentOutputs("mail_a--prod", "AKIAB", "password-b", "eu-central-1")
	collector := newIfNotExistCollector()
	err := sdk.RunErr(func(ctx *sdk.Context) error {
		if err := runSesCompute(ctx, collector, sesTestParent, "mail-a", &aws.SesSmtpUser{}); err != nil {
			return err
		}
		return runSesCompute(ctx, collector, sesTestParent, "mail_a", &aws.SesSmtpUser{})
	}, sdk.WithMocks("project", "stack", mocks))
	require.ErrorContains(t, err, `name "mail_a"`)
	require.Empty(t, collector.dropped)
	require.NotContains(t, collector.tpl, "mail_a")
}

func TestSesSmtpUserComputeProcessor_RejectsDependencyConsumption(t *testing.T) {
	mocks := (&sesParentMocks{}).withSesParentOutputs("mautic-ses--prod", "AKIAEXAMPLE", "pw", "eu-central-1")
	parent := sesTestParent
	parent.UsesResource = false
	parent.DependsOnResource = &api.StackConfigDependencyResource{Name: "mailer", Owner: "alphamind-co/alphamind-co", Resource: "mautic-ses"}
	collector := newIfNotExistCollector()
	err := sdk.RunErr(func(ctx *sdk.Context) error {
		return runSesCompute(ctx, collector, parent, "mautic-ses", &aws.SesSmtpUser{})
	}, sdk.WithMocks("project", "stack", mocks))
	require.ErrorContains(t, err, "only supports `uses`")
	require.Empty(t, collector.tpl)
	require.Empty(t, collector.env)
	require.Empty(t, collector.secret)
}

func TestSesSmtpUserComputeProcessor_PasswordMustBeSecretInParent(t *testing.T) {
	mocks := &sesParentMocks{outputs: map[string]string{
		"mautic-ses--prod-ses-smtp-username": "AKIAEXAMPLE",
		"mautic-ses--prod-ses-smtp-password": "plaintext",
	}}
	err := sdk.RunErr(func(ctx *sdk.Context) error {
		return runSesCompute(ctx, newIfNotExistCollector(), sesTestParent, "mautic-ses", &aws.SesSmtpUser{})
	}, sdk.WithMocks("project", "stack", mocks))
	require.ErrorContains(t, err, "smtp-password")
}

type sesPolicyDocAny struct {
	Statement []struct {
		Sid       string
		Effect    string
		Action    []string
		Resource  any
		Condition map[string]map[string][]string
	}
}

func TestSesSmtpUserPolicy_APIAccess(t *testing.T) {
	doc, err := sesSmtpUserPolicy(&aws.SesSmtpUser{
		Identities:       []string{"innmind.com"},
		ConfigurationSet: "mautic-ses-events--prod",
		FromAddresses:    []string{"*@innmind.com"},
		APIAccess:        true,
	}, "eu-central-1", "645119433725")
	require.NoError(t, err)
	var p sesPolicyDocAny
	require.NoError(t, json.Unmarshal([]byte(doc), &p))
	require.Len(t, p.Statement, 2)

	send := p.Statement[0]
	require.Equal(t, []string{"ses:SendRawEmail", "ses:SendEmail"}, send.Action)
	// SES authorizes a send against the identity AND the configuration set.
	require.Equal(t, []any{
		"arn:aws:ses:eu-central-1:645119433725:identity/innmind.com",
		"arn:aws:ses:eu-central-1:645119433725:configuration-set/mautic-ses-events--prod",
	}, send.Resource)
	require.Equal(t, map[string]map[string][]string{"StringLike": {"ses:FromAddress": {"*@innmind.com"}}}, send.Condition)

	get := p.Statement[1]
	require.Equal(t, "Allow", get.Effect)
	require.Equal(t, []string{"ses:GetAccount"}, get.Action)
	require.Equal(t, "*", get.Resource)
	require.Nil(t, get.Condition)
}

func TestSesSmtpUserPolicy_NoAPIAccessUnchanged(t *testing.T) {
	doc := parseSesPolicy(t, &aws.SesSmtpUser{Identities: []string{"innmind.com"}, ConfigurationSet: "mautic"}, "eu-central-1", "645119433725")
	require.Len(t, doc.Statement, 1)
	require.Equal(t, []string{"ses:SendRawEmail"}, doc.Statement[0].Action)
}

func TestSesSmtpUser_APIAccessExports(t *testing.T) {
	values, secrets, _ := runSesSmtpUser(t, &aws.SesSmtpUser{
		AccountConfig: aws.AccountConfig{
			Account:     "645119433725",
			Credentials: api.Credentials{Credentials: `{"region":"eu-central-1"}`},
		},
		Identities: []string{"innmind.com"},
		APIAccess:  true,
	})
	require.Equal(t, "AKIAEXAMPLE", values["mautic-ses--prod-ses-api-access-key"])
	require.Equal(t, "some+secret+key", values["mautic-ses--prod-ses-api-secret-key"])
	require.True(t, secrets["mautic-ses--prod-ses-api-secret-key"], "api secret key must be a secret in state")
	require.False(t, secrets["mautic-ses--prod-ses-api-access-key"])
	// Existing outputs are unchanged.
	require.Equal(t, "AKIAEXAMPLE", values["mautic-ses--prod-ses-smtp-username"])
	require.True(t, secrets["mautic-ses--prod-ses-smtp-password"])

	values, _, _ = runSesSmtpUser(t, &aws.SesSmtpUser{
		AccountConfig: aws.AccountConfig{Account: "645119433725", Credentials: api.Credentials{Credentials: `{"region":"eu-central-1"}`}},
		Identities:    []string{"innmind.com"},
	})
	require.NotContains(t, values, "mautic-ses--prod-ses-api-access-key")
	require.NotContains(t, values, "mautic-ses--prod-ses-api-secret-key")
}

func (m *sesParentMocks) withSesApiParentOutputs(resName, accessKey, secretKey string, secret bool) *sesParentMocks {
	m.outputs[resName+"-ses-api-access-key"] = accessKey
	m.outputs[resName+"-ses-api-secret-key"] = secretKey
	if secret {
		m.secret = append(m.secret, resName+"-ses-api-secret-key")
	}
	return m
}

func TestSesSmtpUserComputeProcessor_APIAccess(t *testing.T) {
	mocks := (&sesParentMocks{}).
		withSesParentOutputs("mautic-ses--prod", "AKIAEXAMPLE", "pw", "eu-central-1").
		withSesApiParentOutputs("mautic-ses--prod", "AKIAEXAMPLE", "some+secret+key", true)
	collector := newIfNotExistCollector()
	err := sdk.RunErr(func(ctx *sdk.Context) error {
		return runSesCompute(ctx, collector, sesTestParent, "mautic-ses", &aws.SesSmtpUser{Identities: []string{"innmind.com"}, APIAccess: true})
	}, sdk.WithMocks("project", "stack", mocks))
	require.NoError(t, err)

	require.Equal(t, "AKIAEXAMPLE", collector.tpl["mautic-ses"]["access-key"])
	require.Equal(t, "some+secret+key", collector.tpl["mautic-ses"]["secret-key"])
	require.Equal(t, "pw", collector.tpl["mautic-ses"]["smtp-password"])
	require.Equal(t, map[string]string{
		"SMTP_MAUTIC_SES__PROD_USER":      "AKIAEXAMPLE",
		"SMTP_MAUTIC_SES__PROD_PASSWORD":  "pw",
		"SES_MAUTIC_SES__PROD_ACCESS_KEY": "AKIAEXAMPLE",
		"SES_MAUTIC_SES__PROD_SECRET_KEY": "some+secret+key",
	}, collector.secret)
	require.Empty(t, collector.dropped)
}

func TestSesSmtpUserComputeProcessor_APISecretMustBeSecretInParent(t *testing.T) {
	mocks := (&sesParentMocks{}).
		withSesParentOutputs("mautic-ses--prod", "AKIAEXAMPLE", "pw", "eu-central-1").
		withSesApiParentOutputs("mautic-ses--prod", "AKIAEXAMPLE", "plaintext", false)
	err := sdk.RunErr(func(ctx *sdk.Context) error {
		return runSesCompute(ctx, newIfNotExistCollector(), sesTestParent, "mautic-ses", &aws.SesSmtpUser{APIAccess: true})
	}, sdk.WithMocks("project", "stack", mocks))
	require.ErrorContains(t, err, "ses-api-secret-key")
}

func TestSesSmtpUserComputeProcessor_NoAPIKeysWithoutAPIAccess(t *testing.T) {
	mocks := (&sesParentMocks{}).withSesParentOutputs("mautic-ses--prod", "AKIAEXAMPLE", "pw", "eu-central-1")
	collector := newIfNotExistCollector()
	err := sdk.RunErr(func(ctx *sdk.Context) error {
		return runSesCompute(ctx, collector, sesTestParent, "mautic-ses", &aws.SesSmtpUser{})
	}, sdk.WithMocks("project", "stack", mocks))
	require.NoError(t, err)
	require.NotContains(t, collector.tpl["mautic-ses"], "access-key")
	require.NotContains(t, collector.tpl["mautic-ses"], "secret-key")
	require.NotContains(t, collector.secret, "SES_MAUTIC_SES__PROD_SECRET_KEY")
}
