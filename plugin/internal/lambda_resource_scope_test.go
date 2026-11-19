// SPDX-License-Identifier: MIT
// Copyright (c) Simple Container

package aws

import (
	"testing"

	. "github.com/onsi/gomega"
	"github.com/simple-container-com/api/pkg/api"
)

// TestLambdaResourceScope_ClientStackIsUnprefixed is the regression guard that
// matters most here: every lambda already deployed from a service repo's own
// stack has Pulumi state entries and AWS physical names (ECR repository,
// execution role, function, log group) keyed on the BARE stack name, plus a
// `<stack>-<env>-function-url` export that every `uses:` consumer resolves.
//
// If this ever returns a prefixed value for a non-component deploy, the next
// `sc deploy` of every service in the fleet replaces its entire lambda stack
// and changes its Function URL. The scoping below must stay opt-in.
func TestLambdaResourceScope_ClientStackIsUnprefixed(t *testing.T) {
	RegisterTestingT(t)
	Ω(lambdaResourceScope("forge-storage", "")).To(Equal("forge-storage"))
	Ω(lambdaResourceScope("infra", "")).To(Equal("infra"))
}

// TestLambdaResourceScope_ComponentsAreDistinct pins the fix for forge run
// 44463662474: declaring a second Component on a parent stack failed with
//
//	error: Duplicate resource URN
//	'urn:pulumi:infra::forge::aws:ecr/repository:Repository::infra-infra'
//
// because every name derived from the stack name alone. Two Components on one
// parent stack must produce two disjoint name sets.
func TestLambdaResourceScope_ComponentsAreDistinct(t *testing.T) {
	RegisterTestingT(t)
	backup := lambdaResourceScope("infra", "my-backup")
	observatory := lambdaResourceScope("infra", "my-observatory")

	Ω(backup).To(Equal("infra-my-backup"))
	Ω(observatory).To(Equal("infra-my-observatory"))
	Ω(backup).NotTo(Equal(observatory))

	// And neither may collide with the client-stack form, which is what
	// produced `infra-infra` for the ECR repository (`<scope>-<scope>`).
	Ω(backup).NotTo(Equal(lambdaResourceScope("infra", "")))
}

// TestLambdaComponentName_RequiresComponentRaw asserts the dispatch signal is
// ComponentRaw and not Descriptor.Name.
//
// Descriptor.Name is populated on EVERY provision — for a client stack it is
// the template name — so keying the scope on it alone would silently re-scope
// and therefore replace every deployed lambda in the fleet. ComponentRaw is
// set only by SC core's component sidecar.
func TestLambdaComponentName_RequiresComponentRaw(t *testing.T) {
	RegisterTestingT(t)

	// Client stack: a descriptor name, but no ComponentRaw.
	Ω(lambdaComponentName(api.ResourceInput{
		Descriptor: &api.ResourceDescriptor{Name: "stack-per-app"},
	})).To(BeEmpty())

	// Component dispatch: both present.
	Ω(lambdaComponentName(api.ResourceInput{
		Descriptor:   &api.ResourceDescriptor{Name: "my-observatory"},
		ComponentRaw: map[string]any{"deployTo": "lambda"},
	})).To(Equal("my-observatory"))

	// Defensive: ComponentRaw without a descriptor must not panic.
	Ω(lambdaComponentName(api.ResourceInput{
		ComponentRaw: map[string]any{"deployTo": "lambda"},
	})).To(BeEmpty())
}

// TestLambdaWantsLegacyResourceNames covers the grandfather flag.
//
// The string spellings are not pedantry. A quoted `legacyResourceNames:
// "true"` that silently read as false would turn the next provision of
// an already-deployed Component into a rename — i.e. an independent
// create plus a DELETE of its live Lambda. Accepting the string shapes
// is cheaper than that failure, and the flag only ever has to err
// toward "keep the live resources".
func TestLambdaWantsLegacyResourceNames(t *testing.T) {
	RegisterTestingT(t)

	Ω(lambdaWantsLegacyResourceNames(api.ResourceInput{})).To(BeFalse())
	Ω(lambdaWantsLegacyResourceNames(api.ResourceInput{
		ComponentRaw: map[string]any{},
	})).To(BeFalse())
	Ω(lambdaWantsLegacyResourceNames(api.ResourceInput{
		ComponentRaw: map[string]any{"legacyResourceNames": false},
	})).To(BeFalse())

	for _, truthy := range []any{true, "true", "True", "TRUE", "1"} {
		Ω(lambdaWantsLegacyResourceNames(api.ResourceInput{
			ComponentRaw: map[string]any{"legacyResourceNames": truthy},
		})).To(BeTrue(), "%v should enable legacy names", truthy)
	}

	// A shape that is neither bool nor a truthy string must not enable
	// it — defaulting to legacy names on a NEW component would put it
	// back in collision with the grandfathered one.
	Ω(lambdaWantsLegacyResourceNames(api.ResourceInput{
		ComponentRaw: map[string]any{"legacyResourceNames": 1},
	})).To(BeFalse())
}
