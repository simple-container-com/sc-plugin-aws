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

const (
	tokSesConfigurationSet = "aws:sesv2/configurationSet:ConfigurationSet"
	tokSesEventDestination = "aws:sesv2/configurationSetEventDestination:ConfigurationSetEventDestination"
	tokSnsTopic            = "aws:sns/topic:Topic"
	tokSnsTopicPolicy      = "aws:sns/topicPolicy:TopicPolicy"
	tokSnsSubscription     = "aws:sns/topicSubscription:TopicSubscription"
	tokAwsProvider         = "pulumi:providers:aws"
)

// sesCsMocks records every created resource per type token.
type sesCsMocks struct {
	mu        sync.Mutex
	resources map[string][]resource.PropertyMap
	calls     []string
}

func (m *sesCsMocks) Call(args sdk.MockCallArgs) (resource.PropertyMap, error) {
	m.mu.Lock()
	m.calls = append(m.calls, args.Token)
	m.mu.Unlock()
	if args.Token == "aws:index/getCallerIdentity:getCallerIdentity" {
		return resource.NewPropertyMapFromMap(map[string]any{"accountId": "999999999999", "arn": "a", "userId": "u", "id": "i"}), nil
	}
	return args.Args, nil
}

func (m *sesCsMocks) NewResource(args sdk.MockResourceArgs) (string, resource.PropertyMap, error) {
	out := args.Inputs.Copy()
	if args.TypeToken == tokSnsTopic {
		out["arn"] = resource.NewStringProperty("arn:aws:sns:eu-central-1:645119433725:" + args.Name)
	}
	m.mu.Lock()
	if m.resources == nil {
		m.resources = map[string][]resource.PropertyMap{}
	}
	m.resources[args.TypeToken] = append(m.resources[args.TypeToken], out)
	m.mu.Unlock()
	return args.Name + "-id", out, nil
}

func (m *sesCsMocks) one(t *testing.T, token string) resource.PropertyMap {
	t.Helper()
	require.Len(t, m.resources[token], 1, token)
	return m.resources[token][0]
}

func runSesConfigurationSet(t *testing.T, cfg *aws.SesConfigurationSet) (map[string]any, *sesCsMocks) {
	t.Helper()
	mocks := &sesCsMocks{}
	values := map[string]any{}
	err := sdk.RunErr(func(ctx *sdk.Context) error {
		provider, err := sdkAws.NewProvider(ctx, "aws", &sdkAws.ProviderArgs{})
		if err != nil {
			return err
		}
		out, err := SesConfigurationSet(ctx, api.Stack{Name: "alphamind-co"}, api.ResourceInput{
			Descriptor: &api.ResourceDescriptor{
				Type:   aws.ResourceTypeSesConfigurationSet,
				Name:   "mautic-ses-events",
				Config: api.Config{Config: cfg},
			},
			StackParams: &api.StackParams{StackName: "alphamind-co", Environment: "prod"},
		}, pApi.ProvisionParams{Log: logger.New(), Provider: provider})
		if err != nil {
			return err
		}
		require.IsType(t, &SesConfigurationSetOutput{}, out.Ref)
		exports, err := runtime.HarvestExports(context.Background(), ctx)
		if err != nil {
			return err
		}
		for k, v := range exports {
			values[k] = v.GetStringValue()
			require.False(t, v.GetSecret(), "%s is not a secret", k)
		}
		return nil
	}, sdk.WithMocks("project", "stack", mocks))
	require.NoError(t, err)
	return values, mocks
}

type snsPolicyDoc struct {
	Version   string
	Statement []struct {
		Sid       string
		Effect    string
		Principal map[string]string
		Action    string
		Resource  string
		Condition map[string]map[string]string
	}
}

func TestSesEventsTopicPolicy(t *testing.T) {
	doc, err := sesEventsTopicPolicy("arn:aws:sns:eu-central-1:645119433725:t", "eu-central-1", "645119433725", "mautic-ses-events--prod")
	require.NoError(t, err)
	var p snsPolicyDoc
	require.NoError(t, json.Unmarshal([]byte(doc), &p))
	require.Equal(t, "2012-10-17", p.Version)
	require.Len(t, p.Statement, 1)
	s := p.Statement[0]
	require.Equal(t, "Allow", s.Effect)
	require.Equal(t, map[string]string{"Service": "ses.amazonaws.com"}, s.Principal)
	require.Equal(t, "sns:Publish", s.Action)
	require.Equal(t, "arn:aws:sns:eu-central-1:645119433725:t", s.Resource)
	require.Equal(t, map[string]map[string]string{"StringEquals": {
		"AWS:SourceAccount": "645119433725",
		"AWS:SourceArn":     "arn:aws:ses:eu-central-1:645119433725:configuration-set/mautic-ses-events--prod",
	}}, s.Condition)

	doc, err = sesEventsTopicPolicy("arn:aws-us-gov:sns:us-gov-west-1:1:t", "us-gov-west-1", "123456789012", "x--prod")
	require.NoError(t, err)
	require.Contains(t, doc, `"arn:aws-us-gov:ses:us-gov-west-1:123456789012:configuration-set/x--prod"`)
}

func TestSesConfigurationSet_ProvisionsDefaults(t *testing.T) {
	values, mocks := runSesConfigurationSet(t, &aws.SesConfigurationSet{
		AccountConfig: aws.AccountConfig{
			Account:     "645119433725",
			Credentials: api.Credentials{Credentials: `{"region":"eu-central-1","accessKey":"x","secretAccessKey":"y"}`},
		},
	})

	cs := mocks.one(t, tokSesConfigurationSet)
	require.Equal(t, "mautic-ses-events--prod", cs["configurationSetName"].StringValue())
	topicArn := mocks.one(t, tokSnsTopic)["arn"].StringValue()

	dest := mocks.one(t, tokSesEventDestination)
	require.Equal(t, "mautic-ses-events--prod", dest["configurationSetName"].StringValue())
	ed := dest["eventDestination"].ObjectValue()
	require.True(t, ed["enabled"].BoolValue())
	require.Equal(t, []resource.PropertyValue{resource.NewStringProperty("BOUNCE"), resource.NewStringProperty("COMPLAINT")}, ed["matchingEventTypes"].ArrayValue())
	require.Equal(t, topicArn, ed["snsDestination"].ObjectValue()["topicArn"].StringValue())

	policy := mocks.one(t, tokSnsTopicPolicy)
	require.Equal(t, topicArn, policy["arn"].StringValue())
	require.Contains(t, policy["policy"].StringValue(), `"AWS:SourceArn":"arn:aws:ses:eu-central-1:645119433725:configuration-set/mautic-ses-events--prod"`)
	require.Contains(t, policy["policy"].StringValue(), `"AWS:SourceAccount":"645119433725"`)

	require.Empty(t, mocks.resources[tokSnsSubscription], "no endpoints, no subscriptions")
	require.Len(t, mocks.resources[tokAwsProvider], 1, "same region: no extra provider")
	require.NotContains(t, mocks.calls, "aws:index/getCallerIdentity:getCallerIdentity")

	require.Equal(t, map[string]any{
		"mautic-ses-events--prod-ses-configuration-set":        "mautic-ses-events--prod",
		"mautic-ses-events--prod-ses-events-topic-arn":         topicArn,
		"mautic-ses-events--prod-ses-configuration-set-region": "eu-central-1",
	}, values)
}

func TestSesConfigurationSet_EventsEndpointsAndOtherRegion(t *testing.T) {
	endpoints := []string{"https://mautic.alphamind.co/mailer/callback", "https://other.example.com/hook"}
	values, mocks := runSesConfigurationSet(t, &aws.SesConfigurationSet{
		AccountConfig: aws.AccountConfig{
			Region:      "us-west-1",
			Credentials: api.Credentials{Credentials: `{"region":"eu-central-1","accessKey":"x","secretAccessKey":"y"}`},
		},
		Name:           "mail-events",
		Events:         []string{"BOUNCE", "COMPLAINT", "DELIVERY"},
		HttpsEndpoints: endpoints,
	})

	require.Equal(t, "mail-events--prod", mocks.one(t, tokSesConfigurationSet)["configurationSetName"].StringValue())
	ed := mocks.one(t, tokSesEventDestination)["eventDestination"].ObjectValue()
	require.Len(t, ed["matchingEventTypes"].ArrayValue(), 3)

	subs := mocks.resources[tokSnsSubscription]
	require.Len(t, subs, 2)
	got := map[string]bool{}
	for _, s := range subs {
		require.Equal(t, "https", s["protocol"].StringValue())
		require.True(t, s["endpointAutoConfirms"].BoolValue())
		require.Equal(t, float64(sesEventsSubscriptionConfirmationTimeoutMinutes), s["confirmationTimeoutInMinutes"].NumberValue())
		require.Equal(t, mocks.one(t, tokSnsTopic)["arn"].StringValue(), s["topic"].StringValue())
		got[s["endpoint"].StringValue()] = true
	}
	require.Equal(t, map[string]bool{endpoints[0]: true, endpoints[1]: true}, got)

	// SES region differs from the credentials' region: a dedicated provider
	// for us-west-1 carrying the same static keys; account from STS.
	providers := mocks.resources[tokAwsProvider]
	require.Len(t, providers, 2)
	require.Equal(t, "us-west-1", providers[1]["region"].StringValue())
	ak := providers[1]["accessKey"]
	if ak.IsSecret() {
		ak = ak.SecretValue().Element
	}
	require.Equal(t, "x", ak.StringValue())
	require.Contains(t, mocks.calls, "aws:index/getCallerIdentity:getCallerIdentity")
	require.Contains(t, mocks.one(t, tokSnsTopicPolicy)["policy"].StringValue(),
		"arn:aws:ses:us-west-1:999999999999:configuration-set/mail-events--prod")
	require.Equal(t, "us-west-1", values["mail-events--prod-ses-configuration-set-region"])
}

func TestSesEndpointIDIsStable(t *testing.T) {
	a := sesEndpointID("https://mautic.alphamind.co/mailer/callback")
	require.Len(t, a, 8)
	require.Equal(t, a, sesEndpointID("https://mautic.alphamind.co/mailer/callback"))
	require.NotEqual(t, a, sesEndpointID("https://mautic.alphamind.co/mailer/callback2"))
}

func TestSesConfigurationSet_RejectsInvalidConfigBeforeCreatingResources(t *testing.T) {
	creds := api.Credentials{Credentials: `{"region":"eu-central-1"}`}
	for name, tc := range map[string]struct {
		cfg     *aws.SesConfigurationSet
		wantErr string
	}{
		"no region":              {&aws.SesConfigurationSet{}, "region"},
		"region without smtp":    {&aws.SesConfigurationSet{AccountConfig: aws.AccountConfig{Region: "af-south-1", Credentials: creds}}, `region "af-south-1" has no Amazon SES SMTP endpoint`},
		"unknown event":          {&aws.SesConfigurationSet{AccountConfig: aws.AccountConfig{Credentials: creds}, Events: []string{"bounce"}}, "events[0]"},
		"http endpoint":          {&aws.SesConfigurationSet{AccountConfig: aws.AccountConfig{Credentials: creds}, HttpsEndpoints: []string{"http://x.example.com"}}, "httpsEndpoints[0]"},
		"name with underscore":   {&aws.SesConfigurationSet{AccountConfig: aws.AccountConfig{Credentials: creds}, Name: "mail_a"}, `name "mail_a"`},
		"configuration set long": {&aws.SesConfigurationSet{AccountConfig: aws.AccountConfig{Credentials: creds}, Name: "a123456789a123456789a123456789a123456789a123456789a123456789"}, "longer than 64"},
	} {
		t.Run(name, func(t *testing.T) {
			mocks := &sesCsMocks{}
			err := sdk.RunErr(func(ctx *sdk.Context) error {
				_, err := SesConfigurationSet(ctx, api.Stack{Name: "s"}, api.ResourceInput{
					Descriptor:  &api.ResourceDescriptor{Type: aws.ResourceTypeSesConfigurationSet, Name: "mautic-ses-events", Config: api.Config{Config: tc.cfg}},
					StackParams: &api.StackParams{StackName: "s", Environment: "prod"},
				}, pApi.ProvisionParams{Log: logger.New()})
				return err
			}, sdk.WithMocks("project", "stack", mocks))
			require.ErrorContains(t, err, tc.wantErr)
			require.Empty(t, mocks.resources, "no resource may be created for an invalid config")
		})
	}
}

// withSesConfigurationSetParentOutputs adds the parent exports of one aws-ses-configuration-set.
func (m *sesParentMocks) withSesConfigurationSetParentOutputs(resName, topicArn, region string) *sesParentMocks {
	if m.outputs == nil {
		m.outputs = map[string]string{}
	}
	m.outputs[resName+"-ses-configuration-set"] = resName
	m.outputs[resName+"-ses-events-topic-arn"] = topicArn
	m.outputs[resName+"-ses-configuration-set-region"] = region
	return m
}

func runSesCsCompute(ctx *sdk.Context, collector pApi.ComputeContextCollector, parent pApi.ParentInfo, resName string, cfg *aws.SesConfigurationSet) error {
	_, err := SesConfigurationSetComputeProcessor(ctx, api.Stack{Name: "mautic-innmind"}, api.ResourceInput{
		Descriptor:  &api.ResourceDescriptor{Type: aws.ResourceTypeSesConfigurationSet, Name: resName, Config: api.Config{Config: cfg}},
		StackParams: &api.StackParams{StackName: "mautic-innmind", Environment: "prod"},
	}, collector, pApi.ProvisionParams{Log: logger.New(), ParentStack: &parent})
	return err
}

func TestSesConfigurationSetComputeProcessor_EmitsEnvAndTplExtension(t *testing.T) {
	topicArn := "arn:aws:sns:eu-central-1:645119433725:mautic-ses-events--prod-ses-events-1234567"
	mocks := (&sesParentMocks{}).
		withSesConfigurationSetParentOutputs("mautic-ses-events--prod", topicArn, "eu-central-1").
		withSesParentOutputs("mautic-ses--prod", "AKIAEXAMPLE", "pw", "eu-central-1")
	collector := newIfNotExistCollector()
	err := sdk.RunErr(func(ctx *sdk.Context) error {
		if err := runSesCsCompute(ctx, collector, sesTestParent, "mautic-ses-events", &aws.SesConfigurationSet{}); err != nil {
			return err
		}
		// Used together with the SMTP user it belongs to: nothing shadowed.
		return runSesCompute(ctx, collector, sesTestParent, "mautic-ses", &aws.SesSmtpUser{ConfigurationSet: "mautic-ses-events--prod"})
	}, sdk.WithMocks("project", "stack", mocks))
	require.NoError(t, err)

	require.Equal(t, map[string]string{
		"configuration-set": "mautic-ses-events--prod",
		"sns-topic-arn":     topicArn,
		"region":            "eu-central-1",
	}, collector.tpl["mautic-ses-events"])
	require.Equal(t, "mautic-ses-events--prod", collector.tpl["mautic-ses"]["configuration-set"])
	require.Equal(t, "mautic-ses-events--prod", collector.env["SES_MAUTIC_SES_EVENTS__PROD_CONFIGURATION_SET"])
	require.Equal(t, topicArn, collector.env["SES_MAUTIC_SES_EVENTS__PROD_SNS_TOPIC_ARN"])
	require.Equal(t, "eu-central-1", collector.env["SES_MAUTIC_SES_EVENTS__PROD_REGION"])
	require.NotContains(t, collector.secret, "SES_MAUTIC_SES_EVENTS__PROD_SNS_TOPIC_ARN")
	require.Empty(t, collector.dropped)
}

func TestSesConfigurationSetComputeProcessor_RejectsDependencyConsumption(t *testing.T) {
	mocks := (&sesParentMocks{}).withSesConfigurationSetParentOutputs("mautic-ses-events--prod", "arn:aws:sns:eu-central-1:1:t", "eu-central-1")
	parent := sesTestParent
	parent.UsesResource = false
	parent.DependsOnResource = &api.StackConfigDependencyResource{Name: "events", Owner: "alphamind-co/alphamind-co", Resource: "mautic-ses-events"}
	collector := newIfNotExistCollector()
	err := sdk.RunErr(func(ctx *sdk.Context) error {
		return runSesCsCompute(ctx, collector, parent, "mautic-ses-events", &aws.SesConfigurationSet{})
	}, sdk.WithMocks("project", "stack", mocks))
	require.ErrorContains(t, err, "only supports `uses`")
	require.Empty(t, collector.tpl)
	require.Empty(t, collector.env)
}

func TestSesConfigurationSetComputeProcessor_MissingParentOutput(t *testing.T) {
	mocks := &sesParentMocks{outputs: map[string]string{"mautic-ses-events--prod-ses-configuration-set": "mautic-ses-events--prod"}}
	err := sdk.RunErr(func(ctx *sdk.Context) error {
		return runSesCsCompute(ctx, newIfNotExistCollector(), sesTestParent, "mautic-ses-events", &aws.SesConfigurationSet{})
	}, sdk.WithMocks("project", "stack", mocks))
	require.ErrorContains(t, err, "ses-events-topic-arn")
}
