// SPDX-License-Identifier: MIT
// Copyright (c) Simple Container

package aws

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/apigatewayv2"
	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/cloudwatch"
	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/iam"
	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/lambda"
	sdk "github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/samber/lo"
	"github.com/simple-container-com/api/pkg/api"
	pApi "github.com/simple-container-com/api/pkg/clouds/pulumi/api"
	"github.com/simple-container-com/api/pkg/util"

	"github.com/simple-container-com/sc-plugin-aws/api"
)

type LambdaOutput struct {
	sdk.Output
}

// componentEndpointURLKey mirrors pApi.ComponentEndpointURLKey — the
// output-key convention SC core reads to wire DNS for Component
// resources that declare ingress.hostname. Duplicated as a local
// constant (rather than imported) to avoid a hard dependency on
// a specific SC core minor release; a value drift between the two
// is a build-time catch because both are referenced by string in
// the same deploy binary and would mis-match loudly. See
// forge/docs/design/2026-11-17/component-parent-dns-wiring/.
const componentEndpointURLKey = "_endpoint_url"

func Lambda(ctx *sdk.Context, stack api.Stack, input api.ResourceInput, params pApi.ProvisionParams) (*api.ResourceOutput, error) {
	if input.Descriptor.Type != aws.TemplateTypeAwsLambda {
		return nil, errors.Errorf("unsupported template type %q", input.Descriptor.Type)
	}
	if input.StackParams == nil {
		return nil, errors.Errorf("missing deploy params for %q in stack %q", input.Descriptor.Type, stack.Name)
	}
	deployParams := *input.StackParams

	ref := &LambdaOutput{}
	output := &api.ResourceOutput{Ref: ref}

	crInput, ok := input.Descriptor.Config.Config.(*aws.LambdaInput)
	if !ok {
		return output, errors.Errorf("failed to convert aws-lambda config for %q in stack %q in %q", input.Descriptor.Type, stack.Name, deployParams.Environment)
	}
	// This in-place ConvertAuth re-reads the credentials blob over
	// crInput.AccountConfig; capture the (template-level) boundary first and
	// re-assert it after so "template wins" holds consistently with the other
	// constructors, and so a future switch to the fresh-struct idiom can't
	// silently drop it. json.Unmarshal already leaves absent fields untouched;
	// this makes the intent explicit and survives a dual (template+auth) decl.
	tplBoundary := crInput.AccountConfig.PermissionsBoundary
	if err := api.ConvertAuth(crInput, &crInput.AccountConfig); err != nil {
		return nil, errors.Wrapf(err, "failed to convert auth config to aws.AccountConfig")
	}
	crInput.AccountConfig.KeepBoundary(tplBoundary)
	stackConfig := crInput.StackConfig

	// SC Components side-channel (slice 1a.1, design doc §#19 path (b),
	// api #601). When this Lambda is being dispatched as a Component (operator
	// server.yaml declares `type: <component-type>, config: {deployTo: lambda,
	// image: ..., env: ..., signingKey: ...}`), api core populates
	// `input.ComponentRaw` with the component's .Raw map. Overlay the
	// component's image/env/ingress/signingKey onto stackConfig so the rest of
	// this function (buildAndPushDockerImageV2, env injection, Function URL
	// DNS) sees them. The plugin's Schema advertises `supports_component:
	// [aws-lambda]`; api core's parse-time validator refuses dispatch unless
	// this opt-in is present.
	if input.ComponentRaw != nil {
		if err := applyComponentRawToSingleImage(&stackConfig, input.ComponentRaw); err != nil {
			return nil, errors.Wrapf(err, "lambda component dispatch for %q in %q: overlay ComponentRaw", stack.Name, deployParams.Environment)
		}
	}

	// resScope is the name prefix for EVERY AWS resource and stack
	// export this template produces.
	//
	// For a client-stack deploy it is the stack name, and it MUST stay
	// that: every existing deployment's Pulumi state entries and
	// physical resource names (the ECR repository, the execution role,
	// the function, the log group, the `<stack>-<env>-function-url`
	// export every `uses:` consumer resolves) are keyed on it. Changing
	// it there would replace the whole fleet.
	//
	// For a Component dispatch it is `<stack>-<component>`, because a
	// PARENT stack can host N Components dispatched into this same
	// template. With the stack name alone, the second Component
	// collides with the first on every name above — the ECR repository
	// first and loudest:
	//
	//	error: Duplicate resource URN
	//	'urn:pulumi:infra::forge::aws:ecr/repository:Repository::infra-infra'
	//
	// and, had it got past that, silently on the
	// `<stack>-<env>-function-url` export (a map set, so last writer
	// wins) — which is the value SC core resolves to point a
	// Component's `ingress.hostname` at. Two Components would have
	// fought over one DNS target with no error at all.
	//
	// Live-caught 2026-11-19 declaring `my-observatory` alongside the
	// already-deployed `my-backup` on forge/infra (forge run
	// 44463662474). The ecs-fargate path already scopes per container
	// (`stack.Name + "/" + container.Name`); this brings the lambda
	// path to the same footing.
	componentName := lambdaComponentName(input)
	if lambdaWantsLegacyResourceNames(input) {
		// Grandfather: this Component was deployed BEFORE the scoping
		// above existed, so its live resources are named from the stack
		// alone. Turning scoping on for it is a pure rename, and Pulumi
		// matches by name — so the plan would be an independent create
		// plus an independent DELETE of each live resource. SC core's
		// own destructive-rename guard refuses that plan, correctly
		// (forge run 44466834062 listed 14 resources, including the
		// live Lambda serving backup.simple-forge.com).
		//
		// So the FIRST Component on a stack keeps its names by
		// declaring this, and every later one gets scoped names and
		// does not collide with it. The operator pays one documented
		// line on exactly the one grandfathered resource rather than a
		// reviewed-destroy deploy, and `SC_ALLOW_DESTRUCTIVE_REPLACE`
		// stays unspent — an escape hatch used routinely stops being
		// read.
		//
		// Dropping the flag later is a deliberate choice to take the
		// replace (new Function URL, fresh log group; nothing stateful
		// moves, since buckets and databases are separate resources).
		params.Log.Info(ctx.Context(),
			"lambda component %q: legacyResourceNames set — keeping un-scoped names derived from stack %q",
			componentName, stack.Name)
		componentName = ""
	}
	resScope := lambdaResourceScope(stack.Name, componentName)
	if componentName != "" {
		params.Log.Info(ctx.Context(),
			"lambda component dispatch: scoping resource names to %q (component %q on parent stack %q)",
			resScope, componentName, stack.Name)
	}

	awsCloudExtras := &aws.CloudExtras{}
	if stackConfig.CloudExtras != nil {
		var err error
		awsCloudExtras, err = api.ConvertDescriptor(stackConfig.CloudExtras, awsCloudExtras)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to convert cloudExtras field to AWS Cloud extras format")
		}
	}

	cloudExtras := lo.FromPtr(awsCloudExtras)
	lambdaRoutingType := cloudExtras.LambdaRoutingType
	if lambdaRoutingType == "" {
		lambdaRoutingType = aws.LambdaRoutingApiGw
	}
	params.Log.Info(ctx.Context(), "lambda will use routing type: %q", lambdaRoutingType)

	opts := []sdk.ResourceOption{
		sdk.Provider(params.Provider),
		sdk.DependsOn(params.ComputeContext.Dependencies()),
	}

	tags := pApi.BuildTagsFromStackParams(deployParams).ToAWSTags()

	// Pre-built image rewrap: operator declared `image.name` without
	// `dockerfile`/`context`. AWS Lambda refuses non-ECR source images
	// (`InvalidParameterValueException: Source image X is not valid`),
	// so we can't just hand the public ref through as ImageUri.
	// Instead: generate a tiny `FROM ${SOURCE_IMAGE}` Dockerfile on
	// disk, build+push to ECR via the normal path, and point the
	// Lambda at the ECR URI. Same pattern as the cloud-helpers
	// alert image in alerts.go.
	//
	// Covers Components dispatched into aws-lambda whose config
	// holds a pre-built public registry ref (e.g. the backup plugin's
	// `simplecontainer/sc-component-backup:latest`) — slice 1a/5 of
	// sc-components-platform.
	dockerfilePath := stackConfig.Image.Dockerfile
	buildContext := stackConfig.Image.Context
	buildArgs := lo.FromPtr(stackConfig.Image.Build).Args
	if stackConfig.Image.Name != "" && dockerfilePath == "" && buildContext == "" {
		params.Log.Info(ctx.Context(), "lambda: rewrapping pre-built image %q via a FROM-only Dockerfile pushed to ECR", stackConfig.Image.Name)
		tmpDir, err := os.MkdirTemp("", fmt.Sprintf("sc-aws-lambda-rewrap-%s-", resScope))
		if err != nil {
			return nil, errors.Wrapf(err, "failed to create tmpdir for rewrap Dockerfile")
		}
		dockerfilePath = filepath.Join(tmpDir, "Dockerfile")
		if werr := os.WriteFile(dockerfilePath, []byte("ARG SOURCE_IMAGE\nFROM ${SOURCE_IMAGE}\n"), 0o600); werr != nil {
			return nil, errors.Wrapf(werr, "failed to write rewrap Dockerfile")
		}
		buildContext = tmpDir
		if buildArgs == nil {
			buildArgs = map[string]string{}
		}
		buildArgs["SOURCE_IMAGE"] = stackConfig.Image.Name
	}

	// The image/ECR name is the one place resScope is NOT the right
	// input: createEcrRegistry already prefixes with the stack name
	// (`<stack>-<name>` → `awsResName` → `<stack>-<name>-ecr`), so
	// handing it resScope yields `infra-infra-my-backup-ecr`. Hand it
	// the bare component name instead and the repository reads
	// `infra-my-backup-ecr` — unique within the stack, and legible in
	// an ECR console listing, which is where an operator meets it.
	// Non-component deploys keep passing stack.Name, so their existing
	// `<stack>-<stack>-ecr` repository is untouched.
	imageName := resScope
	if componentName != "" {
		imageName = componentName
	}
	image, err := buildAndPushDockerImageV2(ctx, stack, params, deployParams, dockerImage{
		name:       imageName,
		dockerfile: dockerfilePath,
		context:    buildContext,
		args:       buildArgs,
		version:    lo.If(deployParams.Version != "", deployParams.Version).Else("latest"),
	})
	if err != nil {
		return nil, errors.Wrapf(err, "failed to build and push image for lambda in stack %q env %q", stack.Name, deployParams.Environment)
	}
	opts = append(opts, image.addOpts...)

	secretEnvVariables := lo.Filter(params.ComputeContext.SecretEnvVariables(), func(s pApi.ComputeEnvVariable, _ int) bool {
		return stackConfig.Secrets[s.Name] == ""
	})
	contextEnvVariables := lo.Filter(params.ComputeContext.EnvVariables(), func(v pApi.ComputeEnvVariable, _ int) bool {
		return stackConfig.Env[v.Name] == ""
	})

	// Create IAM Role for Lambda Function
	lambdaExecutionRoleName := fmt.Sprintf("%s-execution-role", resScope)
	params.Log.Info(ctx.Context(), "configure lambda execution role %q for %q in %q...", lambdaExecutionRoleName, stack.Name, deployParams.Environment)
	lambdaExecutionRole, err := iam.NewRole(ctx, lambdaExecutionRoleName, &iam.RoleArgs{
		Tags:                tags,
		PermissionsBoundary: permissionsBoundaryPtr(crInput.AccountConfig.PermissionsBoundary),
		AssumeRolePolicy: sdk.String(`{
			"Version": "2012-10-17",
			"Statement": [{
				"Effect": "Allow",
				"Principal": {
					"Service": "lambda.amazonaws.com"
				},
				"Action": "sts:AssumeRole"
			}]
		}`),
	}, opts...)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create iam role")
	}

	// Attach the necessary AWS managed policies to the role created
	rolePolicyAttachmentName := fmt.Sprintf("%s-policy-attachment", resScope)
	params.Log.Info(ctx.Context(), "configure role policy attachment %q for %q in %q...", rolePolicyAttachmentName, stack.Name, deployParams.Environment)
	_, err = iam.NewRolePolicyAttachment(ctx, rolePolicyAttachmentName, &iam.RolePolicyAttachmentArgs{
		Role:      lambdaExecutionRole.Name,
		PolicyArn: sdk.String("arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"),
	}, opts...)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create iam policy attachment")
	}

	// Custom policy allowing to read secrets
	lambdaRoles := []string{
		"secretsmanager:GetSecretValue",
		"secretsmanager:DescribeSecret",
		"logs:CreateLogStream",
		"logs:CreateLogGroup",
		"logs:DescribeLogStreams",
		"logs:PutLogEvents",
		"ec2:DescribeNetworkInterfaces",
		"ec2:CreateNetworkInterface",
		"ec2:DeleteNetworkInterface",
		"ec2:DescribeInstances",
		"ec2:AttachNetworkInterface",
	}
	params.Log.Info(ctx.Context(), "adding extra roles %q for lambda %q...", strings.Join(awsCloudExtras.AwsRoles, ","), stack.Name)
	lambdaRoles = append(lambdaRoles, awsCloudExtras.AwsRoles...)
	extraPolicyName := fmt.Sprintf("%s-xpolicy", resScope)
	params.Log.Info(ctx.Context(), "configure extra policy %q for %q in %q...", extraPolicyName, stack.Name, deployParams.Environment)
	extraPolicy, err := iam.NewPolicy(ctx, extraPolicyName, &iam.PolicyArgs{
		Description: sdk.String(fmt.Sprintf("Allows reading secrets in lambda for stack %s", stack.Name)),
		Name:        sdk.String(extraPolicyName),
		Tags:        tags,
		Policy: sdk.All().ApplyT(func(args []interface{}) (sdk.StringOutput, error) {
			policy := map[string]interface{}{
				"Version": "2012-10-17",
				"Statement": []map[string]any{
					{
						"Effect":   "Allow",
						"Resource": "*",
						"Action":   lambdaRoles,
					},
				},
			}
			policyJSON, err := json.Marshal(policy)
			if err != nil {
				return sdk.StringOutput{}, err
			}
			return sdk.String(policyJSON).ToStringOutput(), nil
		}).(sdk.StringOutput),
	}, opts...)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create extra policy for lambda role")
	}

	extraPolicyAttachmentName := fmt.Sprintf("%s-xp-attach", resScope)
	params.Log.Info(ctx.Context(), "configure IAM policy attachment %q for %q in %q...", extraPolicyAttachmentName, stack.Name, deployParams.Environment)
	_, err = iam.NewRolePolicyAttachment(ctx, extraPolicyAttachmentName, &iam.RolePolicyAttachmentArgs{
		Role:      lambdaExecutionRole.Name,
		PolicyArn: extraPolicy.Arn,
	}, opts...)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create extra policy attachment for lambda role")
	}

	// SECRETS — two modes:
	//
	//   - Legacy per-key (default; cloudExtras.secretsBundle nil or
	//     disabled): one SecretsManager secret + one Lambda env var per
	//     declared ${secret:…}. Hits the 4KB Lambda env cap at ~40
	//     secrets (see roadmap `conductor-lambda-env-4kb-cap`).
	//
	//   - Bundle (cloudExtras.secretsBundle set, design 2026-10-17):
	//     ONE SecretsManager secret with a JSON {envName → plaintext}
	//     payload + ONE env var `FORGE_SECRETS_BUNDLE_ARN`. The
	//     service's bootstrap calls `awsutil.LoadSecretBundle(ctx)`
	//     (SDK) to parse + os.Setenv each key before anything reads
	//     a secret env. ~16× budget headroom vs the per-key path.
	// SecretsManager names are built from StackParams.StackName
	// (toSecretName → `<stack>--<env>--<resType>--<resName>--<var>`),
	// so they collide between Components for exactly the same reason
	// the resource names above did — and worse than a loud duplicate
	// URN: two Components that each map a field to the same env var
	// (`signingKey → SERVICE_JWT_SECRET` is the fleet's own convention,
	// declared by both sc-backup and sc-observatory) would resolve to
	// ONE SecretsManager secret, and whichever provisioned last would
	// overwrite the other's value. Both services would then validate
	// JWTs with the same key while believing they had their own.
	//
	// Scope via a local StackParams copy so `toSecretName` is reached
	// with the component-qualified name, without changing its
	// signature or the ecs-fargate / alerts callers. Tags and env
	// variables keep deriving from the REAL deployParams — a resource's
	// owning stack is still `infra`, and `SIMPLE_CONTAINER_STACK_NAME`
	// must keep reporting the stack the service was deployed from.
	secretParams := deployParams
	if componentName != "" {
		secretParams.StackName = resScope
	}

	var secrets []*CreatedSecret
	if cloudExtras.SecretsBundle.IsEnabled() {
		// Bundle mode. Build the same {envName → plaintext} set the
		// legacy path would emit as per-key secrets, pack as one JSON
		// SecretVersion, surface ONE ARN env.
		ctxVars := make([]secretValue, 0, len(secretEnvVariables))
		for _, v := range secretEnvVariables {
			ctxVars = append(ctxVars, secretValue{Name: v.Name, Value: v.Value})
		}
		bundle, berr := createSecretsBundle(ctx, secretParams, cloudExtras.SecretsBundle, ctxVars, stackConfig.Secrets, tags, opts...)
		if berr != nil {
			return nil, errors.Wrapf(berr, "failed to create secrets bundle for stack %q in %q", stack.Name, deployParams.Environment)
		}
		secrets = append(secrets, bundle)
		params.Log.Info(ctx.Context(),
			"secrets bundle mode: %d entries → 1 SecretsManager secret + 1 env var (%s) in stack %q in %q",
			len(ctxVars)+len(stackConfig.Secrets), bundleEnvName, stack.Name, deployParams.Environment)
	} else {
		ctxSecrets, cerr := util.MapErr(secretEnvVariables, func(v pApi.ComputeEnvVariable, _ int) (*CreatedSecret, error) {
			return createSecret(ctx, toSecretName(secretParams, v.ResourceType, v.ResourceName, v.Name, stackConfig.Version), v.Name, v.Value, tags, opts...)
		})
		if cerr != nil {
			return nil, errors.Wrapf(cerr, "failed to create context secrets for stack %q in %q", stack.Name, deployParams.Environment)
		}
		secrets = append(secrets, ctxSecrets...)
		for name, value := range stackConfig.Secrets {
			s, serr := createSecret(ctx, toSecretName(secretParams, "values", "", name, stackConfig.Version), name, value, tags, opts...)
			if serr != nil {
				return nil, errors.Wrapf(serr, "failed to create secret")
			}
			secrets = append(secrets, s)
		}
		params.Log.Info(ctx.Context(), "configure secrets in SecretsManager for %d secrets in stack %q in %q...", len(secrets), stack.Name, deployParams.Environment)
	}

	lambdaSizeMb := lo.If(stackConfig.MaxMemory == nil, 128).Else(lo.FromPtr(stackConfig.MaxMemory))

	invokeMode := cloudExtras.LambdaInvokeMode
	if invokeMode == "" {
		invokeMode = aws.LambdaInvokeModeBuffered
	}

	// ENV VARIABLES
	envVariables := sdk.StringMap{
		api.ComputeEnv.StackName:                   sdk.String(stack.Name),
		api.ComputeEnv.StackEnv:                    sdk.String(deployParams.Environment),
		api.ComputeEnv.StackVersion:                sdk.String(deployParams.Version),
		"SIMPLE_CONTAINER_AWS_LAMBDA_ROUTING_TYPE": sdk.String(lambdaRoutingType),
		"SIMPLE_CONTAINER_AWS_LAMBDA_SIZE_MB":      sdk.String(strconv.Itoa(lambdaSizeMb)),
		"SIMPLE_CONTAINER_AWS_LAMBDA_INVOKE_MODE":  sdk.String(invokeMode),
	}
	for envVar, envVal := range params.BaseEnvVariables {
		envVariables[envVar] = sdk.String(envVal)
	}
	for _, envVar := range contextEnvVariables {
		envVariables[envVar.Name] = sdk.String(envVar.Value)
	}

	for _, secret := range secrets {
		envVariables[secret.EnvVar] = secret.Secret.Arn
	}
	for name, value := range params.BaseEnvVariables {
		envVariables[name] = sdk.String(value)
	}
	for k := range lo.Assign(stackConfig.Env) {
		if _, found := lo.Find(secrets, func(s *CreatedSecret) bool {
			return s.EnvVar == k
		}); found {
			delete(stackConfig.Env, k)
		}
	}
	for name, value := range stackConfig.Env {
		envVariables[name] = sdk.String(value)
	}

	accessLogGroupName := fmt.Sprintf("%s-access-logs", resScope)
	params.Log.Info(ctx.Context(), "configure cloudwatch access log group for %q in %q...", stack.Name, deployParams.Environment)
	logGroup, err := cloudwatch.NewLogGroup(ctx, accessLogGroupName, &cloudwatch.LogGroupArgs{
		Name: sdk.String(accessLogGroupName),
		Tags: tags,
	}, opts...)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create access logs group for api gateway")
	}

	lambdaName := fmt.Sprintf("%s-callback", resScope)
	lambdaFuncArgs := lambda.FunctionArgs{
		PackageType: sdk.String("Image"),
		Role:        lambdaExecutionRole.Arn,
		ImageUri:    image.deployImageRef,
		Tags:        tags,
		MemorySize:  sdk.IntPtr(lambdaSizeMb),
		Timeout:     sdk.IntPtr(lo.If(stackConfig.Timeout != nil, lo.FromPtr(stackConfig.Timeout)).Else(10)),
		EphemeralStorage: lambda.FunctionEphemeralStorageArgs{
			Size: sdk.IntPtr(lo.If(stackConfig.MaxEphemeralStorage != nil, lo.FromPtr(stackConfig.MaxEphemeralStorage)).Else(1024)),
		},
		LoggingConfig: lambda.FunctionLoggingConfigArgs{
			LogFormat:      sdk.String("JSON"),
			LogGroup:       sdk.String(accessLogGroupName),
			SystemLogLevel: sdk.String("DEBUG"),
		},
		Environment: lambda.FunctionEnvironmentArgs{
			Variables: envVariables,
		},
	}

	if lo.FromPtr(stackConfig.StaticEgressIP) {
		staticEgressOut, err := provisionVpcWithStaticEgress(ctx, lambdaName, &StaticEgressIPIn{
			Params:        params,
			Provider:      params.Provider,
			AccountConfig: crInput.AccountConfig,
			SecurityGroup: cloudExtras.SecurityGroup,
			StackParams:   deployParams,
		}, opts...)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to provision static egress IP for lambda")
		}

		params.Log.Info(ctx.Context(), "configure private route table association for lambda %s...", lambdaName)
		lambdaFuncArgs.VpcConfig = lambda.FunctionVpcConfigArgs{
			SubnetIds:        sdk.StringArray{staticEgressOut.SubnetID},
			SecurityGroupIds: sdk.StringArray{staticEgressOut.SecurityGroupID},
		}
	}

	params.Log.Info(ctx.Context(), "configure lambda function for %q in %q...", stack.Name, deployParams.Environment)
	lambdaFunc, err := lambda.NewFunction(ctx, lambdaName, &lambdaFuncArgs, opts...)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create lambda function")
	}
	ctx.Export(fmt.Sprintf("%s-%s-lambda-arn", resScope, deployParams.Environment), lambdaFunc.Arn)
	opts = append(opts, sdk.DependsOn([]sdk.Resource{lambdaFunc}))

	if lambdaRoutingType == aws.LambdaRoutingApiGw {
		// Create an HTTP API Gateway for the Lambda Function
		params.Log.Info(ctx.Context(), "configure API gateway for %q in %q...", stack.Name, deployParams.Environment)
		apiGwName := fmt.Sprintf("%s-api-gw", resScope)
		apiGw, err := apigatewayv2.NewApi(ctx, apiGwName, &apigatewayv2.ApiArgs{
			Name: sdk.String(apiGwName),
			// RouteKey:     sdk.String("$default"), // TODO: figure out whether this will work
			ProtocolType: sdk.String("HTTP"),
			Tags:         tags,
		}, opts...)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to create API gateway for lambda")
		}

		// Create an integration between the HTTP API Gateway and the Lambda Function
		params.Log.Info(ctx.Context(), "configure API gateway lambda integration for %q in %q...", stack.Name, deployParams.Environment)
		integration, err := apigatewayv2.NewIntegration(ctx, fmt.Sprintf("%s-api-lambda-integration", resScope),
			&apigatewayv2.IntegrationArgs{
				ApiId:           apiGw.ID(),
				IntegrationType: sdk.String("AWS_PROXY"),
				IntegrationUri:  lambdaFunc.InvokeArn,
			}, opts...)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to create API gateway lambda integration")
		}

		// Create a route for the HTTP API Gateway for invoking the Lambda Function
		params.Log.Info(ctx.Context(), "configure API gateway route for %q in %q...", stack.Name, deployParams.Environment)
		routeName := fmt.Sprintf("%s-route", resScope)
		route, err := apigatewayv2.NewRoute(ctx, routeName, &apigatewayv2.RouteArgs{
			ApiId:         apiGw.ID(),
			OperationName: sdk.String("ANY"),
			RouteKey:      sdk.String("ANY /{proxy+}"), // Define the catch-all route
			Target: integration.ID().ApplyT(func(id string) string {
				return fmt.Sprintf("integrations/%s", id)
			}).(sdk.StringOutput),
		}, opts...)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to create API gateway route for lambda")
		}

		// Grant the API Gateway permission to invoke the Lambda function
		_, err = lambda.NewPermission(ctx, fmt.Sprintf("%s-permission", resScope), &lambda.PermissionArgs{
			Action:    sdk.String("lambda:InvokeFunction"),
			Function:  lambdaFunc.Arn,
			Principal: sdk.String("apigateway.amazonaws.com"),
			SourceArn: sdk.All(apiGw.ExecutionArn, route.RouteKey).ApplyT(func(args []any) string {
				executionArn, _ := args[0], args[1]
				return fmt.Sprintf("%s/*/*/{proxy+}", executionArn)
			}).(sdk.StringOutput),
		}, opts...)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to create permission for api gateway to invoke lambda")
		}

		// Define the stage. This is the URL path where your API will be accessible
		params.Log.Info(ctx.Context(), "configure API gateway stage for %q in %q...", stack.Name, deployParams.Environment)
		_, err = apigatewayv2.NewStage(ctx, fmt.Sprintf("%s-http-stage", resScope), &apigatewayv2.StageArgs{
			ApiId: apiGw.ID(),
			Name:  sdk.String(lo.If(stackConfig.BasePath == "", "api").Else(stackConfig.BasePath)),
			Tags:  tags,
			Description: route.ID().ApplyT(func(routeId string) string {
				return fmt.Sprintf("stage for route %s", routeId)
			}).(sdk.StringOutput),
			AutoDeploy: sdk.Bool(true),
			AccessLogSettings: apigatewayv2.StageAccessLogSettingsArgs{
				DestinationArn: logGroup.Arn,
				Format:         sdk.String(`{ "requestId":"$context.requestId", "ip": "$context.identity.sourceIp", "caller":"$context.identity.caller", "user":"$context.identity.user", "requestTime":"$context.requestTime", "httpMethod":"$context.httpMethod", "resourcePath":"$context.resourcePath", "status":"$context.status", "protocol":"$context.protocol", "responseLength":"$context.responseLength", "integrationError":"$context.integrationErrorMessage"}`),
			},
		}, opts...)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to create API gateway stage")
		}

		ctx.Export(fmt.Sprintf("%s-%s-function-url", resScope, deployParams.Environment), apiGw.ApiEndpoint)
		// Component-dispatch convention (api PR #635, v>=TBD): publish
		// the Lambda's public URL under the standardized key so SC core
		// can wire DNS for a Component declaring ingress.hostname. SC
		// core reads this from the harvested ProvisionResponse.Outputs
		// and calls ProvisionDomainForEndpoint itself (template plugin
		// stays cloud-blind of the registrar). Published unconditionally
		// — a client-stack deploy (non-Component) just has an extra
		// export the compute processor ignores. See
		// forge/docs/design/2026-11-17/component-parent-dns-wiring/.
		ctx.Export(componentEndpointURLKey, apiGw.ApiEndpoint)
		if stackConfig.Domain != "" {
			_, err := provisionDNSForLambda(ctx, stack, params, lambdaName, stackConfig.Domain, apiGw.ApiEndpoint)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to provision DNS for lambda")
			}
		}
	} else if lambdaRoutingType == aws.LambdaRoutingFunctionUrl {
		functionUrlName := fmt.Sprintf("%s-url", lambdaName)
		params.Log.Info(ctx.Context(), "configure lambda function url for %q in %q...", stack.Name, deployParams.Environment)
		functionUrl, err := lambda.NewFunctionUrl(ctx, functionUrlName, &lambda.FunctionUrlArgs{
			AuthorizationType: sdk.String("NONE"),
			FunctionName:      lambdaFunc.Name,
			InvokeMode:        sdk.String(invokeMode),
		}, opts...)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to create lambda function url")
		}

		// Add permissions to allow anonymous invocation via function URL
		// AWS requires BOTH lambda:InvokeFunctionUrl AND lambda:InvokeFunction permissions
		// for Function URLs with AuthorizationType: "NONE" to work properly
		//
		// These three resources — the FunctionUrl and both Permissions —
		// are SERIALIZED, not run in parallel. All three mutate the same
		// Lambda's resource policy (pulumi-aws's FunctionUrl create
		// issues an AddPermission of its own), and Lambda refuses
		// concurrent updates to one function:
		//
		//	adding Lambda Function URL (…-callback-9fe22ae) permission:
		//	operation error Lambda: AddPermission, StatusCode: 409,
		//	ResourceConflictException: The function could not be updated
		//	due to a concurrent update operation.
		//
		// Live-caught 2026-11-19 provisioning the second Component on
		// forge/infra (forge run 44472020656). It is a race, so it had
		// been passing by luck: three AddPermission calls fired at once
		// against a function created moments earlier. Chaining them
		// costs two sequential API calls on first create and nothing
		// afterwards, which is the right trade against a deploy that
		// fails roughly whenever AWS is slow.

		// Permission 1: lambda:InvokeFunctionUrl with FunctionUrlAuthType condition
		urlPermissionName := fmt.Sprintf("%s-url-permission", lambdaName)
		urlPermission, err := lambda.NewPermission(ctx, urlPermissionName, &lambda.PermissionArgs{
			Action:              sdk.String("lambda:InvokeFunctionUrl"),
			Function:            lambdaFunc.Name,
			Principal:           sdk.String("*"),
			FunctionUrlAuthType: sdk.String("NONE"),
		}, append(opts, sdk.DependsOn([]sdk.Resource{functionUrl}))...)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to create lambda function url permission")
		}

		// Permission 2: lambda:InvokeFunction with InvokedViaFunctionUrl condition
		// This ensures function can only be invoked through the function URL
		invokePermissionName := fmt.Sprintf("%s-invoke-permission", lambdaName)
		_, err = lambda.NewPermission(ctx, invokePermissionName, &lambda.PermissionArgs{
			Action:    sdk.String("lambda:InvokeFunction"),
			Function:  lambdaFunc.Name,
			Principal: sdk.String("*"),
			// Note: Pulumi doesn't support lambda:InvokedViaFunctionUrl condition yet
			// This permission allows invocation through function URL
		}, append(opts, sdk.DependsOn([]sdk.Resource{urlPermission}))...)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to create lambda function url permission")
		}
		ctx.Export(fmt.Sprintf("%s-%s-function-url", resScope, deployParams.Environment), functionUrl.FunctionUrl)
		// Component-dispatch convention (api PR #635, v>=TBD): publish
		// the Function URL under the standardized key so SC core can
		// wire DNS for a Component declaring ingress.hostname. See
		// comment at the APIGW path above for the full rationale.
		ctx.Export(componentEndpointURLKey, functionUrl.FunctionUrl)
		if stackConfig.Domain != "" {
			_, err := provisionDNSForLambda(ctx, stack, params, lambdaName, stackConfig.Domain, functionUrl.FunctionUrl)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to provision DNS for lambda")
			}
		}
	}

	schedules := make([]aws.LambdaSchedule, 0)
	if cloudExtras.LambdaSchedule != nil {
		schedules = append(schedules, *cloudExtras.LambdaSchedule)
	}
	schedules = append(schedules, cloudExtras.LambdaSchedules...)
	schedulesByName := lo.GroupBy(schedules, func(s aws.LambdaSchedule) string {
		return s.Name
	})
	if _, found := lo.Find(lo.Entries(schedulesByName), func(s lo.Entry[string, []aws.LambdaSchedule]) bool {
		return len(s.Value) > 1
	}); found {
		return nil, errors.Errorf("schedules must have unique names")
	}
	for _, schedule := range schedules {
		if err := provisionScheduleForLambda(ctx, stack, params, lambdaName, lambdaFunc, schedule, tags, opts); err != nil {
			return nil, errors.Wrapf(err, "failed to provision schedule %q for lambda", schedule.Name)
		}
	}

	return output, nil
}

func provisionDNSForLambda(ctx *sdk.Context, stack api.Stack, params pApi.ProvisionParams, lambdaName, domain string, endpointUrl sdk.StringOutput) (*api.ResourceOutput, error) {
	// Belt-and-suspenders: a parent-stack Component dispatch that
	// somehow reached this code path (SC core's pre-dispatch strip of
	// `ingress.hostname` is the primary guard; this catches
	// pre-strip-era callers or a future dispatcher that forgets the
	// strip) sees params.Registrar nil because the Registrar is a
	// Pulumi-native object that cannot cross the plugin bus. Refuse
	// with a clear diagnostic rather than nil-deref at line 548.
	// Live-caught 2026-11-17 on backup-smoke-tier4 provision-preview
	// run 44114692253.
	if params.Registrar == nil {
		return nil, errors.New(
			"params.Registrar is nil in sc-plugin-aws (plugin-dispatched " +
				"Lambda path): registrar cannot cross the plugin bus. " +
				"If this is a Component resource with ingress.hostname, " +
				"ensure SC core is recent enough to strip ingress.hostname " +
				"before dispatch and wire DNS itself via " +
				"ComponentEndpointURLKey; see " +
				"forge/docs/design/2026-11-17/component-parent-dns-wiring/",
		)
	}
	// the lambda function URL is a full URL, the registrar wants a bare hostname
	endpointHost := endpointUrl.ApplyT(func(epUrl string) (string, error) {
		parsed, err := url.Parse(epUrl)
		if err != nil {
			return "", errors.Wrapf(err, "failed to parse URL %q", epUrl)
		}
		return parsed.Host, nil
	}).(sdk.StringOutput)

	return params.Registrar.ProvisionDomainForEndpoint(ctx, stack, pApi.DomainEndpoint{
		Name:       lambdaName,
		Domain:     domain,
		TargetHost: endpointHost,
	})
}

func provisionScheduleForLambda(ctx *sdk.Context, stack api.Stack, params pApi.ProvisionParams,
	lambdaName string, lambdaFunc *lambda.Function, schedule aws.LambdaSchedule, tags sdk.StringMap, opts []sdk.ResourceOption,
) error {
	if schedule.Expression == "" {
		return errors.Errorf("cron expression must be specified for schedule %q", schedule.Name)
	}
	if schedule.Request == "" {
		return errors.Errorf("API Gateway request must be specified for schedule %q to work properly", schedule.Name)
	}

	expression := schedule.Expression
	params.Log.Info(ctx.Context(), "configure cron schedule for lambda %s with expression %q...", lambdaName, expression)
	scheduleName := fmt.Sprintf("%s%s-schedule", lambdaName, lo.If(schedule.Name != "", fmt.Sprintf("-%s", schedule.Name)).Else(""))
	scheduleRule, err := cloudwatch.NewEventRule(ctx, scheduleName, &cloudwatch.EventRuleArgs{
		ScheduleExpression: sdk.String(expression),
		Tags:               tags,
	}, opts...)
	if err != nil {
		return errors.Wrapf(err, "failed to create aws lambda schedule")
	}

	scheduleTargetName := fmt.Sprintf("%s-target", scheduleName)
	params.Log.Info(ctx.Context(), "configure cloudwatch event target to trigger lambda %s on schedule: %q...", lambdaName, scheduleTargetName)
	_, err = cloudwatch.NewEventTarget(ctx, scheduleTargetName, &cloudwatch.EventTargetArgs{
		Rule:     scheduleRule.Name,
		Arn:      lambdaFunc.Arn,
		Input:    sdk.String(schedule.Request),
		TargetId: sdk.String(scheduleTargetName),
	}, opts...)
	if err != nil {
		return errors.Wrapf(err, "failed to create schedule target for lambda")
	}

	params.Log.Info(ctx.Context(), "configure permission for schedule to invoke lambda %s...", lambdaName)
	permissionName := fmt.Sprintf("%s-permission", scheduleName)
	_, err = lambda.NewPermission(ctx, permissionName, &lambda.PermissionArgs{
		Action:    sdk.String("lambda:InvokeFunction"),
		Function:  lambdaFunc.Arn,
		Principal: sdk.String("events.amazonaws.com"),
		SourceArn: scheduleRule.Arn,
	}, opts...)
	if err != nil {
		return errors.Wrapf(err, "failed to create permission for schedule to invoke lambda")
	}
	return nil
}

// lambdaComponentName returns the Component resource name when this
// provision is a Component dispatch, and "" for an ordinary
// client-stack deploy.
//
// Both conditions matter. ComponentRaw is the side-channel SC core
// populates only on dispatch, so it is the authoritative signal;
// Descriptor.Name alone is set on every provision (it is the template
// name for a client stack) and keying on it would re-scope — and thus
// replace — every deployed lambda in the fleet.
func lambdaComponentName(input api.ResourceInput) string {
	if input.ComponentRaw == nil || input.Descriptor == nil {
		return ""
	}
	return input.Descriptor.Name
}

// lambdaResourceScope is the prefix for every resource name, physical
// name and stack export the aws-lambda template emits.
//
// Kept as a pure function so the naming contract is pinned by a test
// rather than only by a live deploy: the client-stack case must return
// the bare stack name forever (every existing Pulumi state entry and
// AWS physical name depends on it), and the Component case must differ
// per component (see the long comment at the call site for what
// collides otherwise).
func lambdaResourceScope(stackName, componentName string) string {
	if componentName == "" {
		return stackName
	}
	return fmt.Sprintf("%s-%s", stackName, componentName)
}

// lambdaWantsLegacyResourceNames reports whether the operator asked
// this Component to keep the pre-scoping resource names.
//
// Only meaningful on a Component dispatch; a client-stack deploy is
// never scoped in the first place, so the flag is ignored there rather
// than silently accepted as if it did something.
//
// Accepts a real bool or the string spellings YAML produces when a
// value arrives quoted, because `legacyResourceNames: "true"` failing
// SILENTLY would mean a destroyed Lambda — the one failure mode this
// flag exists to prevent.
func lambdaWantsLegacyResourceNames(input api.ResourceInput) bool {
	if input.ComponentRaw == nil {
		return false
	}
	switch v := input.ComponentRaw["legacyResourceNames"].(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(v, "true") || v == "1"
	default:
		return false
	}
}
