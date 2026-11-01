// SPDX-License-Identifier: MIT
// Copyright (c) Simple Container

package aws

import (
	"encoding/json"
	"fmt"
	awsProvider "github.com/pulumi/pulumi-aws/sdk/v6/go/aws"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	sdk "github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/simple-container-com/api/pkg/api"
	"github.com/simple-container-com/api/pkg/api/logger"
	pApi "github.com/simple-container-com/api/pkg/clouds/pulumi/api"
	clouds "github.com/simple-container-com/sc-plugin-aws/api"
	"reflect"
	"strings"
	"sync"
	"testing"
)

type compatibilityMocks struct {
	mu     sync.Mutex
	inputs map[string]resource.PropertyMap
}

func (m *compatibilityMocks) Call(a sdk.MockCallArgs) (resource.PropertyMap, error) {
	out := a.Args.Copy()
	if a.Token == "aws:index/getAvailabilityZones:getAvailabilityZones" {
		out["names"] = resource.NewArrayProperty([]resource.PropertyValue{resource.NewStringProperty("eu-west-1a")})
	}
	return out, nil
}
func (m *compatibilityMocks) NewResource(a sdk.MockResourceArgs) (string, resource.PropertyMap, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	in := a.Inputs.Copy()
	// origin/main already changes this timestamp on every deployment.
	if tags, ok := in["tags"]; ok && tags.IsObject() {
		v := tags.ObjectValue().Copy()
		delete(v, "deployTime")
		in["tags"] = resource.NewObjectProperty(v)
	}
	m.inputs[a.TypeToken+"/"+a.Name] = in
	out := a.Inputs.Copy()
	if a.TypeToken == "aws:acm/certificate:Certificate" {
		out["domainValidationOptions"] = resource.NewArrayProperty([]resource.PropertyValue{resource.NewObjectProperty(resource.NewPropertyMapFromMap(map[string]any{
			"domainName": "app.example.com", "resourceRecordName": "_token.app.example.com.", "resourceRecordType": "CNAME", "resourceRecordValue": "_token.acm-validations.aws.",
		}))})
	}

	out["arn"] = resource.NewStringProperty("arn:aws:test:eu-west-1:123456789012:" + a.Name)
	if _, ok := out["name"]; !ok {
		out["name"] = resource.NewStringProperty(a.Name)
	}
	out["dnsName"] = resource.NewStringProperty("lb.example.net")
	out["cidrBlock"] = resource.NewStringProperty("172.31.0.0/20")
	for key, typ := range map[string]string{"loadBalancer": "aws:lb/loadBalancer:LoadBalancer", "defaultTargetGroup": "aws:lb/targetGroup:TargetGroup", "service": "aws:ecs/service:Service"} {
		urn := resource.URN("urn:pulumi:stack::project::" + typ + "::" + a.Name + "-" + key)
		out[resource.PropertyKey(key)] = resource.NewResourceReferenceProperty(resource.ResourceReference{URN: urn, ID: resource.NewStringProperty(a.Name + "-" + key)})
	}
	return a.Name, out, nil
}

type ecsBuilder func(*sdk.Context, api.Stack, pApi.ProvisionParams, api.StackParams, *clouds.EcsFargateInput, *EcsFargateOutput) error

func renderEcsGraph(t *testing.T, builder ecsBuilder, input *clouds.EcsFargateInput) map[string]resource.PropertyMap {
	t.Helper()
	mocks := &compatibilityMocks{inputs: map[string]resource.PropertyMap{}}
	err := sdk.RunErr(func(ctx *sdk.Context) error {
		// Stand in for provider-created AWSX children so resource references resolve.
		for name, typ := range map[string]string{
			"app-prod-alb-loadBalancer":       "aws:lb/loadBalancer:LoadBalancer",
			"app-prod-alb-defaultTargetGroup": "aws:lb/targetGroup:TargetGroup",
			"app-prod-service-service":        "aws:ecs/service:Service",
		} {
			if err := ctx.RegisterResource(typ, name, sdk.Map{}, &sdk.CustomResourceState{}); err != nil {
				return err
			}
		}
		log := logger.New()
		provider, err := awsProvider.NewProvider(ctx, "aws", nil)
		if err != nil {
			return err
		}
		return builder(ctx, api.Stack{Name: "app"}, pApi.ProvisionParams{Provider: provider, Log: log, Registrar: &ecsTLSRegistrar{}, ComputeContext: pApi.NewComputeContextCollector(ctx.Context(), log, "app", "prod")}, api.StackParams{Environment: "prod"}, input, &EcsFargateOutput{Images: []*ECRImage{{Container: input.IngressContainer, ImageName: sdk.String("example/app:v1").ToStringOutput(), DeployImageRef: sdk.String("example/app@sha256:abc").ToStringOutput()}}})
	}, sdk.WithMocks("project", "stack", mocks))
	if err != nil {
		t.Fatal(err)
	}
	return mocks.inputs
}

func compatibilityInput(extras *clouds.CloudExtras, domain string, static bool) *clouds.EcsFargateInput {
	return &clouds.EcsFargateInput{Domain: domain, CloudExtras: extras,
		StackConfig:      &api.StackConfigCompose{StaticEgressIP: &static},
		Secrets:          map[string]string{"API_TOKEN": "test-secret"},
		IngressContainer: clouds.EcsFargateContainer{Name: "app", Port: 8080},
		Volumes:          []clouds.EcsFargateVolume{{Name: "data"}}}
}

func TestEcsUnchangedConfigMatchesOriginMain(t *testing.T) {
	cidrs := []string{"203.0.113.0/24"}
	for _, extras := range []*clouds.CloudExtras{nil, {}, {LoadBalancerType: clouds.LoadBalancerTypeNlb}, {AwsRoles: []string{"s3:GetObject"}, SecurityGroup: &clouds.SecurityGroup{Ingress: &clouds.SecurityGroupRule{CidrBlocks: &cidrs}}}} {
		for _, domain := range []string{"", "app.example.com"} {
			for _, static := range []bool{false, true} {
				label, _ := json.Marshal(extras)
				t.Run(fmt.Sprintf("%s/domain=%s/static=%t", label, domain, static), func(t *testing.T) {
					want := renderEcsGraph(t, originMainEcsFargateCluster, compatibilityInput(extras, domain, static))
					got := renderEcsGraph(t, createEcsFargateCluster, compatibilityInput(extras, domain, static))
					if !reflect.DeepEqual(want, got) {
						w, _ := json.MarshalIndent(want, "", "  ")
						g, _ := json.MarshalIndent(got, "", "  ")
						t.Fatalf("default graph differs from origin/main\nwant %s\ngot %s", w, g)
					}
				})
			}
		}
	}
}

func TestEcsHardeningIsIndependentOptIn(t *testing.T) {
	for _, tc := range []struct {
		name                       string
		extras                     clouds.CloudExtras
		role, network, nlb, public bool
	}{
		{name: "roles", extras: clouds.CloudExtras{LeastPrivilegeRoles: true}, role: true, public: true},
		{name: "task ingress", extras: clouds.CloudExtras{RestrictTaskIngress: true}, network: true, public: true},
		{name: "nlb", extras: clouds.CloudExtras{LoadBalancerType: clouds.LoadBalancerTypeNlb, NlbSecurityGroups: true}, nlb: true, public: true},
		{name: "private egress", extras: clouds.CloudExtras{DisablePublicIPWithStaticEgress: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			graph := renderEcsGraph(t, createEcsFargateCluster, compatibilityInput(&tc.extras, "app.example.com", true))
			_, role := graph["aws:iam/role:Role/app-prod-task-role"]
			_, efs := graph["aws:ec2/securityGroup:SecurityGroup/app-prod-efs-sg"]
			if role != tc.role || efs != tc.network {
				t.Fatalf("unexpected role/network hardening: role=%t efs=%t", role, efs)
			}
			for key, props := range graph {
				if strings.Contains(key, "certificate") || strings.Contains(key, "-https") {
					t.Fatalf("unrequested TLS resource %s", key)
				}
				if strings.HasPrefix(key, "awsx:ecs:FargateService/") {
					if props["networkConfiguration"].ObjectValue()["assignPublicIp"].BoolValue() != tc.public {
						t.Fatal("public IP changed without opt in")
					}
					roles := props["taskDefinitionArgs"].ObjectValue()
					equal := reflect.DeepEqual(roles["executionRole"], roles["taskRole"])
					if equal == tc.role {
						t.Fatal("runtime role split does not match opt in")
					}
				}
				if strings.HasPrefix(key, "aws:lb/loadBalancer:LoadBalancer/app-prod-nlb") {
					_, hasSG := props["securityGroups"]
					if hasSG != tc.nlb {
						t.Fatal("NLB security groups do not match opt in")
					}
				}
			}
		})
	}
}

func TestEcsHTTPSRequiresExplicitOptIn(t *testing.T) {
	graph := renderEcsGraph(t, createEcsFargateCluster, compatibilityInput(&clouds.CloudExtras{EnableHTTPS: true}, "app.example.com", false))
	for _, key := range []string{"aws:acm/certificate:Certificate/app-prod-certificate", "aws:acm/certificateValidation:CertificateValidation/app-prod-certificate-validation", "aws:lb/listener:Listener/app-prod-https"} {
		if _, ok := graph[key]; !ok {
			t.Fatalf("opted-in TLS resource missing: %s", key)
		}
	}
	alb := graph["awsx:lb:ApplicationLoadBalancer/app-prod-alb"]
	listener := alb["listener"].ObjectValue()
	if listener["port"].NumberValue() != 80 || listener["protocol"].StringValue() != "HTTP" {
		t.Fatal("existing HTTP listener port/protocol changed")
	}
	if _, ok := alb["listeners"]; ok {
		t.Fatal("HTTP listener moved to a different AWSX identity")
	}
	if listener["defaultActions"].ArrayValue()[0].ObjectValue()["type"].StringValue() != "redirect" {
		t.Fatal("opted-in redirect missing")
	}
}
