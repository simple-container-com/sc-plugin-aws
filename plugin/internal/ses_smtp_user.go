// SPDX-License-Identifier: MIT
// Copyright (c) Simple Container

package aws

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"github.com/samber/lo"

	sdkAws "github.com/pulumi/pulumi-aws/sdk/v6/go/aws"
	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/iam"
	sdk "github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/simple-container-com/api/pkg/api"
	pApi "github.com/simple-container-com/api/pkg/clouds/pulumi/api"
	"github.com/simple-container-com/api/pkg/util"
	"github.com/simple-container-com/sc-plugin-aws/api"
)

// SesSmtpUserOutput is the Ref of a provisioned aws-ses-smtp-user.
type SesSmtpUserOutput struct {
	User         *iam.User
	Policy       *iam.UserPolicy
	AccessKey    *iam.AccessKey
	SmtpPassword sdk.StringOutput
}

// SesSmtpUser provisions an IAM user that may only send through SES
// (ses:SendRawEmail on the configured identities), an access key for it,
// and exports the SMTP credentials consumed by SesSmtpUserComputeProcessor.
func SesSmtpUser(ctx *sdk.Context, stack api.Stack, input api.ResourceInput, params pApi.ProvisionParams) (*api.ResourceOutput, error) {
	if input.Descriptor.Type != aws.ResourceTypeSesSmtpUser {
		return nil, errors.Errorf("unsupported ses smtp user type %q", input.Descriptor.Type)
	}
	cfg, ok := input.Descriptor.Config.Config.(*aws.SesSmtpUser)
	if !ok {
		return nil, errors.Errorf("failed to convert ses smtp user config for %q", input.Descriptor.Type)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	baseName := lo.If(cfg.Name == "", input.Descriptor.Name).Else(cfg.Name)
	if err := aws.ValidateSesSmtpUserName(baseName); err != nil {
		return nil, err
	}
	resName := input.ToResName(baseName)
	creds, err := sesCredentialsAccount(&cfg.AccountConfig)
	if err != nil {
		return nil, err
	}
	region := lo.If(cfg.Region != "", cfg.Region).Else(creds.Region)
	if region == "" {
		return nil, errors.Errorf("%s %q: `region` is not set and the aws credentials carry no region", aws.ResourceTypeSesSmtpUser, input.Descriptor.Name)
	}
	// Fail before creating IAM resources: an SMTP password and host for a
	// region without an SMTP endpoint would be unusable.
	if err := aws.ValidateSesSmtpRegion(region); err != nil {
		return nil, err
	}
	params.Log.Info(ctx.Context(), "configure ses smtp user %q (region %q, identities %v)", resName, region, cfg.Identities)

	opts := []sdk.ResourceOption{sdk.Provider(params.Provider)}
	var tags sdk.StringMap
	if input.StackParams != nil {
		tags = pApi.BuildTagsFromStackParams(*input.StackParams).ToAWSTags()
	}

	user, err := iam.NewUser(ctx, fmt.Sprintf("%s-ses-smtp-user", resName), &iam.UserArgs{
		ForceDestroy: sdk.BoolPtr(true),
		Tags:         tags,
	}, opts...)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to provision ses smtp user %q", resName)
	}
	ctx.Export(toSesIamUserExport(resName), user.Name)

	accountID := lo.If(cfg.Account != "", cfg.Account).Else(creds.Account)
	var account sdk.StringOutput
	if accountID != "" {
		account = sdk.String(accountID).ToStringOutput()
	} else {
		account = sdkAws.GetCallerIdentityOutput(ctx, sdkAws.GetCallerIdentityOutputArgs{}, sdk.Provider(params.Provider)).AccountId()
	}
	policy, err := iam.NewUserPolicy(ctx, fmt.Sprintf("%s-ses-smtp-send", resName), &iam.UserPolicyArgs{
		User: user.Name,
		Policy: account.ApplyT(func(acc string) (string, error) {
			return sesSmtpUserPolicy(cfg, region, acc)
		}).(sdk.StringOutput),
	}, opts...)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to provision ses send policy for %q", resName)
	}

	accessKey, err := iam.NewAccessKey(ctx, fmt.Sprintf("%s-ses-smtp-access-key", resName), &iam.AccessKeyArgs{
		User: user.Name,
	}, opts...)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to provision ses smtp access key for %q", resName)
	}

	// The provider derives sesSmtpPasswordV4 for ITS region. When the SES
	// region differs from the credentials' region, derive it locally for the
	// SES region with the same documented SigV4 algorithm.
	smtpPassword := accessKey.SesSmtpPasswordV4
	if region != creds.Region {
		smtpPassword = accessKey.Secret.ApplyT(func(secret string) string {
			return sesSmtpPasswordV4(secret, region)
		}).(sdk.StringOutput)
	}
	smtpPassword = sdk.ToSecret(smtpPassword).(sdk.StringOutput)

	ctx.Export(toSesSmtpUsernameExport(resName), accessKey.ID())
	ctx.Export(toSesSmtpPasswordExport(resName), smtpPassword)
	ctx.Export(toSesSmtpHostExport(resName), sdk.String(sesSmtpHost(region)))
	ctx.Export(toSesSmtpPortExport(resName), sdk.String(strconv.Itoa(aws.SesSmtpUserDefaultPort)))
	ctx.Export(toSesRegionExport(resName), sdk.String(region))
	if cfg.APIAccess {
		ctx.Export(toSesApiAccessKeyExport(resName), accessKey.ID())
		ctx.Export(toSesApiSecretKeyExport(resName), sdk.ToSecret(accessKey.Secret))
	}

	return &api.ResourceOutput{Ref: &SesSmtpUserOutput{
		User:         user,
		Policy:       policy,
		AccessKey:    accessKey,
		SmtpPassword: smtpPassword,
	}}, nil
}

// SesSmtpUserComputeProcessor reads the parent stack's SMTP exports and hands
// them to a consuming stack (`uses: [<resource>]`) as env vars and as
// `${resource:<resource>.smtp-user|smtp-password|smtp-host|smtp-port|region}`
// (plus `access-key|secret-key` with `apiAccess`).
func SesSmtpUserComputeProcessor(ctx *sdk.Context, stack api.Stack, input api.ResourceInput, collector pApi.ComputeContextCollector, params pApi.ProvisionParams) (*api.ResourceOutput, error) {
	if params.ParentStack == nil {
		return nil, errors.Errorf("parent stack must not be nil for compute processor for %q", stack.Name)
	}
	parentStackName := params.ParentStack.StackName

	cfg, ok := input.Descriptor.Config.Config.(*aws.SesSmtpUser)
	if !ok {
		return nil, errors.Errorf("failed to convert ses smtp user config for %q", input.Descriptor.Type)
	}
	// Like the RDS processors, only `uses:` is supported: consuming the
	// credentials as a `dependencies:` entry is rejected explicitly rather
	// than handed out under the dependency's name.
	if !params.ParentStack.UsesResource {
		return nil, errors.Errorf("%s %q only supports `uses`, but it wasn't explicitly declared as being used by %q",
			aws.ResourceTypeSesSmtpUser, input.Descriptor.Name, stack.Name)
	}
	baseName := lo.If(cfg.Name == "", input.Descriptor.Name).Else(cfg.Name)
	if err := aws.ValidateSesSmtpUserName(baseName); err != nil {
		return nil, err
	}
	resName := input.ToResName(baseName)

	suffix := lo.If(params.ParentStack.DependsOnResource != nil, "--"+lo.FromPtr(params.ParentStack.DependsOnResource).Name).Else("")
	params.Log.Info(ctx.Context(), "getting parent's (%q) outputs for ses smtp user %q (%q)", params.ParentStack.FullReference, resName, suffix)
	parentRef, err := sdk.NewStackReference(ctx, fmt.Sprintf("%s--%s--%s%s--ses-smtp-ref", stack.Name, params.ParentStack.StackName, input.Descriptor.Name, suffix), &sdk.StackReferenceArgs{
		Name: sdk.String(params.ParentStack.FullReference).ToStringOutput(),
	})
	if err != nil {
		return nil, err
	}

	read := func(export string, secret bool) (string, error) {
		v, err := pApi.GetParentOutput(parentRef, export, params.ParentStack.FullReference, secret)
		if err != nil {
			return "", errors.Wrapf(err, "failed to get %q from parent stack for %q", export, stack.Name)
		} else if v == "" {
			return "", errors.Errorf("%q is empty in parent stack for %q", export, stack.Name)
		}
		return v, nil
	}
	smtpUser, err := read(toSesSmtpUsernameExport(resName), false)
	if err != nil {
		return nil, err
	}
	smtpPassword, err := read(toSesSmtpPasswordExport(resName), true)
	if err != nil {
		return nil, err
	}
	smtpHost, err := read(toSesSmtpHostExport(resName), false)
	if err != nil {
		return nil, err
	}
	smtpPort, err := read(toSesSmtpPortExport(resName), false)
	if err != nil {
		return nil, err
	}
	region, err := read(toSesRegionExport(resName), false)
	if err != nil {
		return nil, err
	}
	var apiKeys *sesApiKeys
	if cfg.APIAccess {
		accessKey, err := read(toSesApiAccessKeyExport(resName), false)
		if err != nil {
			return nil, err
		}
		secretKey, err := read(toSesApiSecretKeyExport(resName), true)
		if err != nil {
			return nil, err
		}
		apiKeys = &sesApiKeys{accessKey: accessKey, secretKey: secretKey}
	}

	collector.AddOutput(ctx, parentRef.Name.ApplyT(func(refName any) any {
		for _, v := range sesSmtpEnvVariables(resName, smtpHost, smtpPort, smtpUser, smtpPassword, region, apiKeys) {
			if v.secret {
				collector.AddSecretEnvVariableIfNotExist(v.name, v.value, input.Descriptor.Type, input.Descriptor.Name, parentStackName)
			} else {
				collector.AddEnvVariableIfNotExist(v.name, v.value, input.Descriptor.Type, input.Descriptor.Name, parentStackName)
			}
		}
		collector.AddResourceTplExtension(input.Descriptor.Name, sesSmtpTplExtension(cfg, smtpHost, smtpPort, smtpUser, smtpPassword, region, apiKeys))
		return nil
	}))

	return &api.ResourceOutput{Ref: parentStackName}, nil
}

// sesApiKeys are the SES API credentials handed out with `apiAccess`.
type sesApiKeys struct {
	accessKey string
	secretKey string
}

type sesSmtpEnvVariable struct {
	name   string
	value  string
	secret bool
}

// sesSmtpEnvVariables lists the env vars injected into consumers. They are
// all scoped to the resource (SMTP_<RES>_*, SES_<RES>_REGION). There are
// deliberately no unscoped SMTP_* / SES_REGION vars: SC keeps the first value
// of a duplicate env name, so with two SES resources in `uses:` they would
// silently point at whichever was processed first. With `apiAccess` the API
// key pair is added as SES_<RES>_ACCESS_KEY / SES_<RES>_SECRET_KEY, both
// secret like the SMTP user and password.
func sesSmtpEnvVariables(resName, host, port, user, password, region string, apiKeys *sesApiKeys) []sesSmtpEnvVariable {
	prefix := fmt.Sprintf("SMTP_%s_", resName)
	vars := []sesSmtpEnvVariable{
		{util.ToEnvVariableName(prefix + "HOST"), host, false},
		{util.ToEnvVariableName(prefix + "PORT"), port, false},
		{util.ToEnvVariableName(prefix + "USER"), user, true},
		{util.ToEnvVariableName(prefix + "PASSWORD"), password, true},
		{util.ToEnvVariableName(fmt.Sprintf("SES_%s_REGION", resName)), region, false},
	}
	if apiKeys != nil {
		vars = append(vars,
			sesSmtpEnvVariable{util.ToEnvVariableName(fmt.Sprintf("SES_%s_ACCESS_KEY", resName)), apiKeys.accessKey, true},
			sesSmtpEnvVariable{util.ToEnvVariableName(fmt.Sprintf("SES_%s_SECRET_KEY", resName)), apiKeys.secretKey, true},
		)
	}
	return vars
}

func sesSmtpTplExtension(cfg *aws.SesSmtpUser, host, port, user, password, region string, apiKeys *sesApiKeys) map[string]string {
	ext := map[string]string{
		"smtp-user":     user,
		"smtp-password": password,
		"smtp-host":     host,
		"smtp-port":     port,
		"region":        region,
	}
	if cfg.ConfigurationSet != "" {
		ext["configuration-set"] = cfg.ConfigurationSet
	}
	if apiKeys != nil {
		ext["access-key"] = apiKeys.accessKey
		ext["secret-key"] = apiKeys.secretKey
	}
	return ext
}

// sesCredentialsAccount decodes the `${auth:...}` credentials blob, if any,
// for its region and account. The provider is built from the same blob.
func sesCredentialsAccount(account *aws.AccountConfig) (aws.AccountConfig, error) {
	var creds aws.AccountConfig
	if account.CredentialsValue() == "" {
		return creds, nil
	}
	if err := api.ConvertAuth(account, &creds); err != nil {
		return creds, errors.Wrap(err, "failed to convert aws account config")
	}
	return creds, nil
}

func sesSmtpUserPolicy(cfg *aws.SesSmtpUser, region, account string) (string, error) {
	partition := awsPartition(region)
	resources := lo.Map(cfg.Identities, func(id string, _ int) string {
		id = strings.TrimSpace(id)
		if strings.HasPrefix(id, "arn:") {
			return id
		}
		return fmt.Sprintf("arn:%s:ses:%s:%s:identity/%s", partition, region, account, id)
	})
	if cfg.ConfigurationSet != "" {
		resources = append(resources, sesConfigurationSetArn(region, account, cfg.ConfigurationSet))
	}
	// SES authorizes a send against every resource it involves: the
	// identity and, when the message uses one, the configuration set. Both
	// are listed, and the same statement (and ses:FromAddress condition)
	// covers the API's ses:SendEmail when apiAccess is on.
	actions := []string{"ses:SendRawEmail"}
	if cfg.APIAccess {
		actions = append(actions, "ses:SendEmail")
	}
	statement := map[string]any{
		"Sid":      "SesSmtpSendRawEmail",
		"Effect":   "Allow",
		"Action":   actions,
		"Resource": resources,
	}
	if len(cfg.FromAddresses) > 0 {
		statement["Condition"] = map[string]any{
			"StringLike": map[string]any{
				"ses:FromAddress": lo.Map(cfg.FromAddresses, func(a string, _ int) string { return strings.TrimSpace(a) }),
			},
		}
	}
	statements := []any{statement}
	if cfg.APIAccess {
		// ses:GetAccount (sending quota and status) supports no resource
		// scoping, so it gets its own statement on `*`.
		statements = append(statements, map[string]any{
			"Sid":      "SesApiGetAccount",
			"Effect":   "Allow",
			"Action":   []string{"ses:GetAccount"},
			"Resource": "*",
		})
	}
	doc, err := json.Marshal(map[string]any{
		"Version":   "2012-10-17",
		"Statement": statements,
	})
	if err != nil {
		return "", err
	}
	return string(doc), nil
}

func awsPartition(region string) string {
	switch {
	case strings.HasPrefix(region, "cn-"):
		return "aws-cn"
	case strings.HasPrefix(region, "us-gov-"):
		return "aws-us-gov"
	default:
		return "aws"
	}
}

func sesSmtpHost(region string) string {
	return fmt.Sprintf("email-smtp.%s.amazonaws.com", region)
}

// sesSmtpPasswordV4 converts an IAM secret access key into an SES SMTP
// password for region, per
// https://docs.aws.amazon.com/ses/latest/dg/smtp-credentials.html#smtp-credentials-convert
// (the same algorithm behind aws.iam.AccessKey.sesSmtpPasswordV4).
func sesSmtpPasswordV4(secret, region string) string {
	sign := func(key []byte, msg string) []byte {
		h := hmac.New(sha256.New, key)
		h.Write([]byte(msg))
		return h.Sum(nil)
	}
	sig := sign([]byte("AWS4"+secret), "11111111")
	for _, msg := range []string{region, "ses", "aws4_request", "SendRawEmail"} {
		sig = sign(sig, msg)
	}
	return base64.StdEncoding.EncodeToString(append([]byte{0x04}, sig...))
}

func toSesIamUserExport(resName string) string {
	return fmt.Sprintf("%s-ses-iam-user", resName)
}

func toSesSmtpUsernameExport(resName string) string {
	return fmt.Sprintf("%s-ses-smtp-username", resName)
}

func toSesSmtpPasswordExport(resName string) string {
	return fmt.Sprintf("%s-ses-smtp-password", resName)
}

func toSesSmtpHostExport(resName string) string {
	return fmt.Sprintf("%s-ses-smtp-host", resName)
}

func toSesSmtpPortExport(resName string) string {
	return fmt.Sprintf("%s-ses-smtp-port", resName)
}

func toSesRegionExport(resName string) string {
	return fmt.Sprintf("%s-ses-region", resName)
}

func toSesApiAccessKeyExport(resName string) string {
	return fmt.Sprintf("%s-ses-api-access-key", resName)
}

func toSesApiSecretKeyExport(resName string) string {
	return fmt.Sprintf("%s-ses-api-secret-key", resName)
}
