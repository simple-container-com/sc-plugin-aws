// SPDX-License-Identifier: MIT
// Copyright (c) Simple Container

package aws

import (
	"fmt"
	"net"

	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/ec2"
	sdk "github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	clouds "github.com/simple-container-com/sc-plugin-aws/api"
)

func ecsTaskIngress(container clouds.EcsFargateContainer, source sdk.StringInput) ec2.SecurityGroupIngressArray {
	ports := []int{container.Port}
	if p := container.LivenessProbe.HttpGet.Port; p > 0 && p != container.Port {
		ports = append(ports, p)
	}
	rules := ec2.SecurityGroupIngressArray{}
	for _, port := range ports {
		rules = append(rules, ec2.SecurityGroupIngressArgs{
			Description: sdk.String("Load balancer to application/health-check port"),
			Protocol:    sdk.String("tcp"), FromPort: sdk.Int(port), ToPort: sdk.Int(port),
			SecurityGroups: sdk.StringArray{source},
		})
	}
	return rules
}

func ecsLoadBalancerIngress(group *clouds.SecurityGroup) (ec2.SecurityGroupIngressArray, error) {
	ipv4, ipv6 := []string{"0.0.0.0/0"}, []string{"::/0"}
	if group != nil && group.Ingress != nil {
		ingress := group.Ingress
		if ingress.CidrBlocks != nil || ingress.Ipv6CidrBlocks != nil || (ingress.AllowOnlyCloudflare != nil && *ingress.AllowOnlyCloudflare) {
			// Setting either address family restricts both. Never retain an open IPv6 bypass.
			ipv4, ipv6 = nil, nil
			if ingress.CidrBlocks != nil {
				ipv4 = append(ipv4, *ingress.CidrBlocks...)
			}
			if ingress.Ipv6CidrBlocks != nil {
				ipv6 = append(ipv6, *ingress.Ipv6CidrBlocks...)
			}
			if ingress.AllowOnlyCloudflare != nil && *ingress.AllowOnlyCloudflare {
				ips, err := getCloudflareIPs()
				if err != nil {
					return nil, err
				}
				ipv4, ipv6 = append(ipv4, ips.IPv4Cidrs...), append(ipv6, ips.IPv6Cidrs...)
			}
		}
	}
	for _, block := range append(append([]string{}, ipv4...), ipv6...) {
		if _, _, err := net.ParseCIDR(block); err != nil {
			return nil, fmt.Errorf("invalid load balancer CIDR %q: %w", block, err)
		}
	}
	rules := ec2.SecurityGroupIngressArray{}
	if len(ipv4)+len(ipv6) > 0 {
		rules = append(rules, ec2.SecurityGroupIngressArgs{
			Description: sdk.String("Load balancer listener"),
			Protocol:    sdk.String("tcp"), FromPort: sdk.Int(80), ToPort: sdk.Int(80),
			CidrBlocks: sdk.ToStringArray(ipv4), Ipv6CidrBlocks: sdk.ToStringArray(ipv6),
		})
	}
	return rules, nil
}
