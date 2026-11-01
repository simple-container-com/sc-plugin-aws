// SPDX-License-Identifier: MIT
// Copyright (c) Simple Container

package aws

import (
	"errors"
	lbV6 "github.com/pulumi/pulumi-aws/sdk/v6/go/aws/lb"
	"sync"
	"testing"

	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	sdk "github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/simple-container-com/api/pkg/api"
	pApi "github.com/simple-container-com/api/pkg/clouds/pulumi/api"
)

type ecsTLSMocks struct {
	mu         sync.Mutex
	validation bool
}

func (m *ecsTLSMocks) Call(args sdk.MockCallArgs) (resource.PropertyMap, error) {
	return args.Args, nil
}
func (m *ecsTLSMocks) NewResource(args sdk.MockResourceArgs) (string, resource.PropertyMap, error) {
	out := args.Inputs.Copy()
	if args.TypeToken == "aws:acm/certificate:Certificate" {
		out["arn"] = resource.NewStringProperty("arn:aws:acm:eu-west-1:123456789012:certificate/test")
		out["domainValidationOptions"] = resource.NewArrayProperty([]resource.PropertyValue{resource.NewObjectProperty(resource.NewPropertyMapFromMap(map[string]any{
			"domainName": "app.example.com", "resourceRecordName": "_token.app.example.com.", "resourceRecordType": "CNAME", "resourceRecordValue": "_token.acm-validations.aws.",
		}))})
	}
	if args.TypeToken == "aws:acm/certificateValidation:CertificateValidation" {
		m.mu.Lock()
		m.validation = true
		m.mu.Unlock()
		fqdns := args.Inputs["validationRecordFqdns"].ArrayValue()
		if len(fqdns) != 1 || fqdns[0].StringValue() != "_token.app.example.com." {
			return "", nil, errors.New("ACM validation missing DNS record dependency")
		}
	}
	return args.Name, out, nil
}

type ecsTLSRegistrar struct {
	pApi.Registrar
	record api.DnsRecord
	fail   bool
}

func (r *ecsTLSRegistrar) NewRecord(ctx *sdk.Context, record api.DnsRecord) (*api.ResourceOutput, error) {
	r.record = record
	if r.fail {
		return nil, errors.New("registrar rejected record")
	}
	// Match the real scCoreRegistrar bridge: it awaits a typed StringOutput.
	ready := record.ValueOut.ApplyT(func(value string) (string, error) {
		if value != record.Value {
			return "", errors.New("validation CNAME value lost")
		}
		return "record-id", nil
	})
	return &api.ResourceOutput{Ref: ready}, nil
}

func TestEcsCertificateUsesDNSOnlyRegistrarRecord(t *testing.T) {
	mocks := &ecsTLSMocks{}
	registrar := &ecsTLSRegistrar{}
	err := sdk.RunErr(func(ctx *sdk.Context) error {
		_, err := createEcsCertificate(ctx, "stack", "app.example.com", registrar, nil)
		return err
	}, sdk.WithMocks("project", "stack", mocks))
	if err != nil {
		t.Fatal(err)
	}
	if registrar.record.Name != "_token.app.example.com." || registrar.record.Type != "CNAME" || registrar.record.Proxied || registrar.record.Value != "_token.acm-validations.aws." {
		t.Fatalf("wrong validation record: %+v", registrar.record)
	}
	mocks.mu.Lock()
	defer mocks.mu.Unlock()
	if !mocks.validation {
		t.Fatal("certificate issuance not awaited")
	}
}

func TestEcsCertificateRequiresRegistrar(t *testing.T) {
	err := sdk.RunErr(func(ctx *sdk.Context) error {
		_, err := createEcsCertificate(ctx, "stack", "app.example.com", nil, nil)
		return err
	}, sdk.WithMocks("project", "stack", &ecsTLSMocks{}))
	if err == nil {
		t.Fatal("missing registrar accepted")
	}
}

func TestEcsCertificatePropagatesRegistrarFailure(t *testing.T) {
	err := sdk.RunErr(func(ctx *sdk.Context) error {
		_, err := createEcsCertificate(ctx, "stack", "app.example.com", &ecsTLSRegistrar{fail: true}, nil)
		return err
	}, sdk.WithMocks("project", "stack", &ecsTLSMocks{}))
	if err == nil {
		t.Fatal("registrar failure ignored")
	}
}

func TestEcsHTTPRedirectPreservesPathAndQuery(t *testing.T) {
	if ecsHTTPListener(false) != nil {
		t.Fatal("domainless stacks must retain AWSX HTTP defaults")
	}
	listener := ecsHTTPListener(true)
	if listener.Port != sdk.Int(80) || listener.Protocol != sdk.String("HTTP") {
		t.Fatal("HTTP listener identity changed")
	}
	action := listener.DefaultActions.(lbV6.ListenerDefaultActionArray)[0].(lbV6.ListenerDefaultActionArgs)
	if action.Type != sdk.String("redirect") {
		t.Fatal("HTTP forwards plaintext")
	}
	redirect := action.Redirect.(*lbV6.ListenerDefaultActionRedirectArgs)
	if redirect.Protocol != sdk.String("HTTPS") || redirect.Port != sdk.String("443") || redirect.StatusCode != sdk.String("HTTP_301") {
		t.Fatalf("incorrect redirect: %+v", redirect)
	}
	if redirect.Host != nil || redirect.Path != nil || redirect.Query != nil {
		t.Fatal("redirect should preserve host/path/query")
	}
	rules, err := ecsLoadBalancerIngress(nil, true)
	if err != nil || len(rules) != 2 {
		t.Fatalf("missing HTTPS ingress: %v, %v", rules, err)
	}
}
