// SPDX-License-Identifier: MIT
// Copyright (c) Simple Container

package aws

import (
	"encoding/json"
	"testing"

	. "github.com/onsi/gomega"

	"github.com/simple-container-com/sc-plugin-aws/api"
)

// roundtripCloudExtras mirrors the shape of api.ConvertDescriptor used
// when SC core hands a client-stack's cloudExtras map to the plugin:
// a JSON marshal-unmarshal using the struct's json tags. A tag typo or
// missing `omitempty` here would silently drop the knob on the far side
// of the plugin bus.
func roundtripCloudExtras(raw map[string]any, out *aws.CloudExtras) error {
	buf, err := json.Marshal(raw)
	if err != nil {
		return err
	}
	return json.Unmarshal(buf, out)
}

// TestResolveLambdaConcurrency_Unset is the default-preserving case: unset
// cloudExtras fields must produce a nil/nil/false triple so the lambda path
// stays bit-identical to pre-knob deploys — no ReservedConcurrentExecutions
// on FunctionArgs, no alias, no ProvisionedConcurrencyConfig, no Qualifier
// on the Function URL / APIGW integration / Permissions. Any drift here
// re-shapes every existing deployed Lambda the next time it is deployed.
func TestResolveLambdaConcurrency_Unset(t *testing.T) {
	RegisterTestingT(t)

	reserved, provisioned, wantsAlias, err := resolveLambdaConcurrency(aws.CloudExtras{})
	Ω(err).ToNot(HaveOccurred())
	Ω(reserved).To(BeNil())
	Ω(provisioned).To(BeNil())
	Ω(wantsAlias).To(BeFalse())
}

// TestResolveLambdaConcurrency_ReservedOnly covers the common sizing case:
// an operator caps simultaneous executions without paying the provisioned-
// concurrency ongoing cost. Must NOT create an alias (wantsAlias=false).
func TestResolveLambdaConcurrency_ReservedOnly(t *testing.T) {
	RegisterTestingT(t)

	rc := 10
	reserved, provisioned, wantsAlias, err := resolveLambdaConcurrency(aws.CloudExtras{
		ReservedConcurrency: &rc,
	})
	Ω(err).ToNot(HaveOccurred())
	Ω(reserved).ToNot(BeNil())
	Ω(*reserved).To(Equal(10))
	Ω(provisioned).To(BeNil())
	Ω(wantsAlias).To(BeFalse(), "reservedConcurrency alone must not create an alias")
}

// TestResolveLambdaConcurrency_ReservedZeroIsKillSwitch — reservedConcurrency=0
// is deliberate (AWS refuses every invocation of the function) and must be
// accepted. nil means unreserved; zero means disabled. Collapsing the two
// would turn an operator-intended kill-switch into the account-pool default.
func TestResolveLambdaConcurrency_ReservedZeroIsKillSwitch(t *testing.T) {
	RegisterTestingT(t)

	rc := 0
	reserved, _, wantsAlias, err := resolveLambdaConcurrency(aws.CloudExtras{
		ReservedConcurrency: &rc,
	})
	Ω(err).ToNot(HaveOccurred())
	Ω(reserved).ToNot(BeNil())
	Ω(*reserved).To(Equal(0))
	Ω(wantsAlias).To(BeFalse())
}

// TestResolveLambdaConcurrency_ReservedNegativeRejected — AWS answers a
// negative value with a cryptic ValidationException deep in the Pulumi
// preview. Reject it at parse time with a message that names the field.
func TestResolveLambdaConcurrency_ReservedNegativeRejected(t *testing.T) {
	RegisterTestingT(t)

	rc := -1
	_, _, _, err := resolveLambdaConcurrency(aws.CloudExtras{
		ReservedConcurrency: &rc,
	})
	Ω(err).To(HaveOccurred())
	Ω(err.Error()).To(ContainSubstring("reservedConcurrency"))
	Ω(err.Error()).To(ContainSubstring("-1"))
}

// TestResolveLambdaConcurrency_ProvisionedOnly covers the cold-start-cure
// case. wantsAlias=true gates Publish=true on the function + alias + PCC
// creation + Qualifier on the URL / APIGW integration / Permissions.
// reserved stays nil (AWS unreserved).
func TestResolveLambdaConcurrency_ProvisionedOnly(t *testing.T) {
	RegisterTestingT(t)

	pc := 2
	reserved, provisioned, wantsAlias, err := resolveLambdaConcurrency(aws.CloudExtras{
		ProvisionedConcurrency: &pc,
	})
	Ω(err).ToNot(HaveOccurred())
	Ω(reserved).To(BeNil(), "reserved unset = AWS unreserved")
	Ω(provisioned).ToNot(BeNil())
	Ω(*provisioned).To(Equal(2))
	Ω(wantsAlias).To(BeTrue(), "provisionedConcurrency must gate alias + Publish")
}

// TestResolveLambdaConcurrency_ProvisionedZeroRejected — a zero value for
// provisionedConcurrency is ambiguous: is it nil (disable) or 0 (which AWS
// refuses anyway)? Refuse at parse time; the operator has to delete the
// field to turn it off, which keeps intent legible in git diffs.
func TestResolveLambdaConcurrency_ProvisionedZeroRejected(t *testing.T) {
	RegisterTestingT(t)

	pc := 0
	_, _, _, err := resolveLambdaConcurrency(aws.CloudExtras{
		ProvisionedConcurrency: &pc,
	})
	Ω(err).To(HaveOccurred())
	Ω(err.Error()).To(ContainSubstring("provisionedConcurrency"))
}

// TestResolveLambdaConcurrency_ProvisionedNegativeRejected — same reasoning
// as the negative-reserved case.
func TestResolveLambdaConcurrency_ProvisionedNegativeRejected(t *testing.T) {
	RegisterTestingT(t)

	pc := -3
	_, _, _, err := resolveLambdaConcurrency(aws.CloudExtras{
		ProvisionedConcurrency: &pc,
	})
	Ω(err).To(HaveOccurred())
	Ω(err.Error()).To(ContainSubstring("provisionedConcurrency"))
}

// TestResolveLambdaConcurrency_Both pins the common "warm fleet AND a hard
// cap" shape — e.g. go-embedb's recommended Lambda sizing: provision 2 warm
// to absorb the predictable baseline, cap at 10 so a burst cannot melt the
// downstream S3 writer. Both knobs are independent; neither disables the
// other.
func TestResolveLambdaConcurrency_Both(t *testing.T) {
	RegisterTestingT(t)

	rc, pc := 10, 2
	reserved, provisioned, wantsAlias, err := resolveLambdaConcurrency(aws.CloudExtras{
		ReservedConcurrency:    &rc,
		ProvisionedConcurrency: &pc,
	})
	Ω(err).ToNot(HaveOccurred())
	Ω(reserved).ToNot(BeNil())
	Ω(*reserved).To(Equal(10))
	Ω(provisioned).ToNot(BeNil())
	Ω(*provisioned).To(Equal(2))
	Ω(wantsAlias).To(BeTrue())
}

// TestCloudExtras_ConcurrencyYAMLRoundtrip asserts that the two knobs survive
// the SC descriptor's YAML → JSON → struct roundtrip the same way the other
// CloudExtras fields do. A missing `omitempty` or a wrong tag casing would
// land a nil pointer on the far side of the plugin bus and silently drop
// the operator's intent — the kind of parse-success-yet-value-lost failure
// lambdaInvokeMode has been bitten by before (hence CloudExtras field tags).
func TestCloudExtras_ConcurrencyYAMLRoundtrip(t *testing.T) {
	RegisterTestingT(t)

	// A yaml-shaped value approximating what SC's descriptor pipeline hands
	// to api.ConvertDescriptor. Numeric values arrive as int (from yaml.v3)
	// or float64 (through a json.Unmarshal into map[string]interface{});
	// the json tags on CloudExtras must accept either.
	for name, concurrency := range map[string]map[string]any{
		"int-shape": {
			"reservedConcurrency":    10,
			"provisionedConcurrency": 2,
		},
		"float-shape (map[string]any route)": {
			"reservedConcurrency":    float64(10),
			"provisionedConcurrency": float64(2),
		},
	} {
		t.Run(name, func(t *testing.T) {
			RegisterTestingT(t)
			var ce aws.CloudExtras
			// mirrors the descriptor pipeline: marshal the raw map through
			// JSON, unmarshal into the typed struct. Any tag mismatch drops
			// the value silently.
			err := roundtripCloudExtras(concurrency, &ce)
			Ω(err).ToNot(HaveOccurred())
			Ω(ce.ReservedConcurrency).ToNot(BeNil())
			Ω(*ce.ReservedConcurrency).To(Equal(10))
			Ω(ce.ProvisionedConcurrency).ToNot(BeNil())
			Ω(*ce.ProvisionedConcurrency).To(Equal(2))
		})
	}

	// And the unset case roundtrips to nil pointers (the Pulumi path then
	// omits the fields from FunctionArgs, which is the whole point).
	var ce aws.CloudExtras
	Ω(roundtripCloudExtras(map[string]any{}, &ce)).To(Succeed())
	Ω(ce.ReservedConcurrency).To(BeNil())
	Ω(ce.ProvisionedConcurrency).To(BeNil())
}
