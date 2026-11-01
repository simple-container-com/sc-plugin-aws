// SPDX-License-Identifier: MIT
// Copyright (c) Simple Container

package aws

import (
	"fmt"

	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/acm"
	lbV6 "github.com/pulumi/pulumi-aws/sdk/v6/go/aws/lb"
	"github.com/pulumi/pulumi-awsx/sdk/v2/go/awsx/lb"
	sdk "github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/simple-container-com/api/pkg/api"
	pApi "github.com/simple-container-com/api/pkg/clouds/pulumi/api"
)

func createEcsCertificate(ctx *sdk.Context, name, domain string, registrar pApi.Registrar, tags sdk.StringMap, opts ...sdk.ResourceOption) (sdk.StringOutput, error) {
	if registrar == nil {
		return sdk.StringOutput{}, fmt.Errorf("a DNS registrar is required for ECS domain %q", domain)
	}
	certificate, err := acm.NewCertificate(ctx, name+"-certificate", &acm.CertificateArgs{
		DomainName: sdk.String(domain), ValidationMethod: sdk.String("DNS"), Tags: tags,
	}, opts...)
	if err != nil {
		return sdk.StringOutput{}, err
	}
	// A single domain needs one CNAME. Registrar record names are plain strings,
	// so register it after ACM has supplied its validation option. Thread the
	// returned Output through to the waiter, including across the plugin bus.
	fqdn := certificate.DomainValidationOptions.ApplyT(func(options []acm.CertificateDomainValidationOption) (sdk.StringOutput, error) {
		if len(options) != 1 {
			return sdk.StringOutput{}, fmt.Errorf("expected one ACM DNS validation option for %q, got %d", domain, len(options))
		}
		option := options[0]
		if option.ResourceRecordName == nil || option.ResourceRecordType == nil || option.ResourceRecordValue == nil {
			return sdk.StringOutput{}, fmt.Errorf("incomplete ACM validation option for %q", domain)
		}
		record, err := registrar.NewRecord(ctx, api.DnsRecord{
			Name: *option.ResourceRecordName, Type: *option.ResourceRecordType,
			Value:    *option.ResourceRecordValue,
			ValueOut: sdk.String(*option.ResourceRecordValue).ToStringOutput(), Proxied: false,
		})
		if err != nil {
			return sdk.StringOutput{}, fmt.Errorf("create ACM validation DNS record: %w", err)
		}
		if record == nil || record.Ref == nil {
			return sdk.StringOutput{}, fmt.Errorf("registrar returned no ACM validation record for %q", domain)
		}
		return sdk.All(record.Ref).ApplyT(func([]any) string { return *option.ResourceRecordName }).(sdk.StringOutput), nil
	}).(sdk.StringOutput)
	validated, err := acm.NewCertificateValidation(ctx, name+"-certificate-validation", &acm.CertificateValidationArgs{
		CertificateArn: certificate.Arn, ValidationRecordFqdns: sdk.StringArray{fqdn},
	}, opts...)
	if err != nil {
		return sdk.StringOutput{}, err
	}
	return validated.CertificateArn, nil
}

// Configuring the single HTTP listener preserves AWSX's existing <name>-0
// listener identity and leaves the default target group on HTTP.
func ecsHTTPListener(https bool) *lb.ListenerArgs {
	if !https {
		return nil
	}
	return &lb.ListenerArgs{
		Port: sdk.Int(80), Protocol: sdk.String("HTTP"),
		DefaultActions: lbV6.ListenerDefaultActionArray{lbV6.ListenerDefaultActionArgs{
			Type: sdk.String("redirect"),
			Redirect: &lbV6.ListenerDefaultActionRedirectArgs{
				Protocol: sdk.String("HTTPS"), Port: sdk.String("443"), StatusCode: sdk.String("HTTP_301"),
			},
		}},
	}
}
