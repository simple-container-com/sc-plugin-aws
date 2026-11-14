// SPDX-License-Identifier: MIT
// Copyright (c) Simple Container

package aws

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"
	"github.com/samber/lo"

	sdkAws "github.com/pulumi/pulumi-aws/sdk/v6/go/aws"
	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/sesv2"
	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/sns"
	sdk "github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/simple-container-com/api/pkg/api"
	pApi "github.com/simple-container-com/api/pkg/clouds/pulumi/api"
	"github.com/simple-container-com/api/pkg/util"
	"github.com/simple-container-com/sc-plugin-aws/api"
)

// sesEventsSubscriptionConfirmationTimeoutMinutes is how long provisioning
// waits for an HTTPS endpoint to confirm its SNS subscription.
const sesEventsSubscriptionConfirmationTimeoutMinutes = 5

// SesConfigurationSetOutput is the Ref of a provisioned aws-ses-configuration-set.
type SesConfigurationSetOutput struct {
	ConfigurationSet *sesv2.ConfigurationSet
	Topic            *sns.Topic
	TopicPolicy      *sns.TopicPolicy
	EventDestination *sesv2.ConfigurationSetEventDestination
	Subscriptions    []*sns.TopicSubscription
}

// SesConfigurationSet provisions an SES v2 configuration set, an SNS topic
// only SES (for this account and configuration set) may publish to, an
// event destination sending the configured events to the topic, and an
// https subscription per configured endpoint.
func SesConfigurationSet(ctx *sdk.Context, stack api.Stack, input api.ResourceInput, params pApi.ProvisionParams) (*api.ResourceOutput, error) {
	if input.Descriptor.Type != aws.ResourceTypeSesConfigurationSet {
		return nil, errors.Errorf("unsupported ses configuration set type %q", input.Descriptor.Type)
	}
	cfg, ok := input.Descriptor.Config.Config.(*aws.SesConfigurationSet)
	if !ok {
		return nil, errors.Errorf("failed to convert ses configuration set config for %q", input.Descriptor.Type)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	baseName := lo.If(cfg.Name == "", input.Descriptor.Name).Else(cfg.Name)
	resName := input.ToResName(baseName)
	if err := aws.ValidateSesConfigurationSetName(baseName, resName); err != nil {
		return nil, err
	}
	creds, err := sesCredentialsAccount(&cfg.AccountConfig)
	if err != nil {
		return nil, err
	}
	region := lo.If(cfg.Region != "", cfg.Region).Else(creds.Region)
	if region == "" {
		return nil, errors.Errorf("%s %q: `region` is not set and the aws credentials carry no region", aws.ResourceTypeSesConfigurationSet, input.Descriptor.Name)
	}
	if err := aws.ValidateSesConfigurationSetRegion(region); err != nil {
		return nil, err
	}
	events := cfg.EffectiveEvents()
	params.Log.Info(ctx.Context(), "configure ses configuration set %q (region %q, events %v, %d https endpoint(s))", resName, region, events, len(cfg.HttpsEndpoints))

	// SES and SNS are regional: the default provider is bound to the
	// credentials' region, so another SES region needs its own provider.
	provider := params.Provider
	if region != creds.Region {
		providerArgs := &sdkAws.ProviderArgs{Region: sdk.String(region)}
		applyAWSProviderCreds(providerArgs, creds.AccessKey, creds.SecretAccessKey)
		regionProvider, err := sdkAws.NewProvider(ctx, fmt.Sprintf("%s-ses-region-provider", resName), providerArgs)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to create %q provider for ses configuration set %q", region, resName)
		}
		provider = regionProvider
	}
	opts := []sdk.ResourceOption{sdk.Provider(provider)}
	var tags sdk.StringMap
	if input.StackParams != nil {
		tags = pApi.BuildTagsFromStackParams(*input.StackParams).ToAWSTags()
	}

	configSet, err := sesv2.NewConfigurationSet(ctx, fmt.Sprintf("%s-ses-configuration-set", resName), &sesv2.ConfigurationSetArgs{
		ConfigurationSetName: sdk.String(resName),
		Tags:                 tags,
	}, opts...)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to provision ses configuration set %q", resName)
	}

	topic, err := sns.NewTopic(ctx, fmt.Sprintf("%s-ses-events", resName), &sns.TopicArgs{
		Tags: tags,
	}, opts...)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to provision ses events topic for %q", resName)
	}

	accountID := lo.If(cfg.Account != "", cfg.Account).Else(creds.Account)
	var account sdk.StringOutput
	if accountID != "" {
		account = sdk.String(accountID).ToStringOutput()
	} else {
		account = sdkAws.GetCallerIdentityOutput(ctx, sdkAws.GetCallerIdentityOutputArgs{}, sdk.Provider(provider)).AccountId()
	}
	topicPolicy, err := sns.NewTopicPolicy(ctx, fmt.Sprintf("%s-ses-events-policy", resName), &sns.TopicPolicyArgs{
		Arn: topic.Arn,
		Policy: sdk.All(topic.Arn, account).ApplyT(func(args []any) (string, error) {
			return sesEventsTopicPolicy(args[0].(string), region, args[1].(string), resName)
		}).(sdk.StringOutput),
	}, opts...)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to provision ses events topic policy for %q", resName)
	}

	// SES checks it may publish to the topic when the destination is
	// created, so the topic policy must exist first.
	destination, err := sesv2.NewConfigurationSetEventDestination(ctx, fmt.Sprintf("%s-ses-events-sns", resName), &sesv2.ConfigurationSetEventDestinationArgs{
		ConfigurationSetName: configSet.ConfigurationSetName,
		EventDestinationName: sdk.String("sns"),
		EventDestination: &sesv2.ConfigurationSetEventDestinationEventDestinationArgs{
			Enabled:            sdk.Bool(true),
			MatchingEventTypes: sdk.ToStringArray(events),
			SnsDestination: &sesv2.ConfigurationSetEventDestinationEventDestinationSnsDestinationArgs{
				TopicArn: topic.Arn,
			},
		},
	}, append(opts, sdk.DependsOn([]sdk.Resource{topicPolicy}))...)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to provision ses event destination for %q", resName)
	}

	subscriptions := make([]*sns.TopicSubscription, 0, len(cfg.HttpsEndpoints))
	for _, endpoint := range cfg.HttpsEndpoints {
		// Named by endpoint, not position, so reordering the list does not
		// replace (and re-confirm) every subscription.
		sub, err := sns.NewTopicSubscription(ctx, fmt.Sprintf("%s-ses-events-https-%s", resName, sesEndpointID(endpoint)), &sns.TopicSubscriptionArgs{
			Topic:                        topic.Arn,
			Protocol:                     sdk.String("https"),
			Endpoint:                     sdk.String(endpoint),
			EndpointAutoConfirms:         sdk.Bool(true),
			ConfirmationTimeoutInMinutes: sdk.Int(sesEventsSubscriptionConfirmationTimeoutMinutes),
		}, opts...)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to subscribe %q to ses events of %q", endpoint, resName)
		}
		subscriptions = append(subscriptions, sub)
	}

	ctx.Export(toSesConfigurationSetNameExport(resName), configSet.ConfigurationSetName)
	ctx.Export(toSesEventsTopicArnExport(resName), topic.Arn)
	ctx.Export(toSesConfigurationSetRegionExport(resName), sdk.String(region))

	return &api.ResourceOutput{Ref: &SesConfigurationSetOutput{
		ConfigurationSet: configSet,
		Topic:            topic,
		TopicPolicy:      topicPolicy,
		EventDestination: destination,
		Subscriptions:    subscriptions,
	}}, nil
}

// SesConfigurationSetComputeProcessor hands a configuration set's name, SNS
// topic ARN and region to a consuming stack (`uses: [<resource>]`) as
// SES_<RES>_* env vars and as
// `${resource:<resource>.configuration-set|sns-topic-arn|region}`.
func SesConfigurationSetComputeProcessor(ctx *sdk.Context, stack api.Stack, input api.ResourceInput, collector pApi.ComputeContextCollector, params pApi.ProvisionParams) (*api.ResourceOutput, error) {
	if params.ParentStack == nil {
		return nil, errors.Errorf("parent stack must not be nil for compute processor for %q", stack.Name)
	}
	parentStackName := params.ParentStack.StackName

	cfg, ok := input.Descriptor.Config.Config.(*aws.SesConfigurationSet)
	if !ok {
		return nil, errors.Errorf("failed to convert ses configuration set config for %q", input.Descriptor.Type)
	}
	// As for aws-ses-smtp-user, only `uses:` is supported.
	if !params.ParentStack.UsesResource {
		return nil, errors.Errorf("%s %q only supports `uses`, but it wasn't explicitly declared as being used by %q",
			aws.ResourceTypeSesConfigurationSet, input.Descriptor.Name, stack.Name)
	}
	baseName := lo.If(cfg.Name == "", input.Descriptor.Name).Else(cfg.Name)
	resName := input.ToResName(baseName)
	if err := aws.ValidateSesConfigurationSetName(baseName, resName); err != nil {
		return nil, err
	}

	params.Log.Info(ctx.Context(), "getting parent's (%q) outputs for ses configuration set %q", params.ParentStack.FullReference, resName)
	parentRef, err := sdk.NewStackReference(ctx, fmt.Sprintf("%s--%s--%s--ses-configuration-set-ref", stack.Name, params.ParentStack.StackName, input.Descriptor.Name), &sdk.StackReferenceArgs{
		Name: sdk.String(params.ParentStack.FullReference).ToStringOutput(),
	})
	if err != nil {
		return nil, err
	}

	read := func(export string) (string, error) {
		v, err := pApi.GetParentOutput(parentRef, export, params.ParentStack.FullReference, false)
		if err != nil {
			return "", errors.Wrapf(err, "failed to get %q from parent stack for %q", export, stack.Name)
		} else if v == "" {
			return "", errors.Errorf("%q is empty in parent stack for %q", export, stack.Name)
		}
		return v, nil
	}
	configSetName, err := read(toSesConfigurationSetNameExport(resName))
	if err != nil {
		return nil, err
	}
	topicArn, err := read(toSesEventsTopicArnExport(resName))
	if err != nil {
		return nil, err
	}
	region, err := read(toSesConfigurationSetRegionExport(resName))
	if err != nil {
		return nil, err
	}

	collector.AddOutput(ctx, parentRef.Name.ApplyT(func(refName any) any {
		for _, v := range sesConfigurationSetEnvVariables(resName, configSetName, topicArn, region) {
			collector.AddEnvVariableIfNotExist(v.name, v.value, input.Descriptor.Type, input.Descriptor.Name, parentStackName)
		}
		collector.AddResourceTplExtension(input.Descriptor.Name, map[string]string{
			"configuration-set": configSetName,
			"sns-topic-arn":     topicArn,
			"region":            region,
		})
		return nil
	}))

	return &api.ResourceOutput{Ref: parentStackName}, nil
}

// sesConfigurationSetEnvVariables lists the (non-secret) env vars injected
// into consumers, all scoped to the resource (SES_<RES>_*).
func sesConfigurationSetEnvVariables(resName, configSetName, topicArn, region string) []sesSmtpEnvVariable {
	return []sesSmtpEnvVariable{
		{util.ToEnvVariableName(fmt.Sprintf("SES_%s_CONFIGURATION_SET", resName)), configSetName, false},
		{util.ToEnvVariableName(fmt.Sprintf("SES_%s_SNS_TOPIC_ARN", resName)), topicArn, false},
		{util.ToEnvVariableName(fmt.Sprintf("SES_%s_REGION", resName)), region, false},
	}
}

// sesEventsTopicPolicy lets only SES publish to the topic, and only on
// behalf of this account's configuration set (confused-deputy guard, per
// https://docs.aws.amazon.com/ses/latest/dg/event-publishing-add-event-destination-sns.html).
func sesEventsTopicPolicy(topicArn, region, account, configSetName string) (string, error) {
	doc, err := json.Marshal(map[string]any{
		"Version": "2012-10-17",
		"Statement": []any{map[string]any{
			"Sid":       "AllowSesPublish",
			"Effect":    "Allow",
			"Principal": map[string]any{"Service": "ses.amazonaws.com"},
			"Action":    "sns:Publish",
			"Resource":  topicArn,
			"Condition": map[string]any{
				"StringEquals": map[string]any{
					"AWS:SourceAccount": account,
					"AWS:SourceArn":     sesConfigurationSetArn(region, account, configSetName),
				},
			},
		}},
	})
	if err != nil {
		return "", err
	}
	return string(doc), nil
}

func sesConfigurationSetArn(region, account, name string) string {
	return fmt.Sprintf("arn:%s:ses:%s:%s:configuration-set/%s", awsPartition(region), region, account, name)
}

func sesEndpointID(endpoint string) string {
	sum := sha256.Sum256([]byte(endpoint))
	return hex.EncodeToString(sum[:])[:8]
}

func toSesConfigurationSetNameExport(resName string) string {
	return fmt.Sprintf("%s-ses-configuration-set", resName)
}

func toSesEventsTopicArnExport(resName string) string {
	return fmt.Sprintf("%s-ses-events-topic-arn", resName)
}

func toSesConfigurationSetRegionExport(resName string) string {
	return fmt.Sprintf("%s-ses-configuration-set-region", resName)
}
