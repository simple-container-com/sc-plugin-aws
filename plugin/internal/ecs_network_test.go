// SPDX-License-Identifier: MIT
// Copyright (c) Simple Container

package aws

import (
	"testing"

	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/ec2"
	sdk "github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	clouds "github.com/simple-container-com/sc-plugin-aws/api"
)

func TestEcsTasksOnlyAcceptLoadBalancerPorts(t *testing.T) {
	container := clouds.EcsFargateContainer{Port: 8080, LivenessProbe: clouds.EcsFargateProbe{HttpGet: clouds.ProbeHttpGet{Port: 8081}}}
	rules := ecsTaskIngress(container, sdk.String("sg-lb"))
	if len(rules) != 2 {
		t.Fatalf("expected app and health-check rules, got %d", len(rules))
	}
	for i, input := range rules {
		rule := input.(ec2.SecurityGroupIngressArgs)
		port := sdk.Int(8080 + i)
		if rule.FromPort != port || rule.ToPort != port || rule.Protocol != sdk.String("tcp") {
			t.Fatalf("unexpected ports: %+v", rule)
		}
		if rule.CidrBlocks != nil || rule.Ipv6CidrBlocks != nil || rule.Self != nil {
			t.Fatalf("task has non-LB ingress: %+v", rule)
		}
		groups := rule.SecurityGroups.(sdk.StringArray)
		if len(groups) != 1 || groups[0] != sdk.String("sg-lb") {
			t.Fatalf("wrong task source: %v", groups)
		}
	}
	container.LivenessProbe.HttpGet.Port = 8080
	if len(ecsTaskIngress(container, sdk.String("sg-lb"))) != 1 {
		t.Fatal("duplicate port rules")
	}
}

func TestEcsLoadBalancerCIDRsDoNotLeaveIPv6Open(t *testing.T) {
	cidrs := []string{"203.0.113.0/24"}
	rules, err := ecsLoadBalancerIngress(&clouds.SecurityGroup{Ingress: &clouds.SecurityGroupRule{CidrBlocks: &cidrs}})
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range rules {
		rule := input.(ec2.SecurityGroupIngressArgs)
		if len(rule.Ipv6CidrBlocks.(sdk.StringArray)) != 0 {
			t.Fatal("IPv4 restriction leaves IPv6 open")
		}
		if rule.FromPort != sdk.Int(80) || rule.ToPort != sdk.Int(80) {
			t.Fatal("ALB exposes non-listener port")
		}
	}
	empty := []string{}
	rules, err = ecsLoadBalancerIngress(&clouds.SecurityGroup{Ingress: &clouds.SecurityGroupRule{CidrBlocks: &empty}})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 0 {
		t.Fatal("explicit empty CIDRs must deny ingress")
	}
}
