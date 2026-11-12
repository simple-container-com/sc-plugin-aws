// SPDX-License-Identifier: MIT
// Copyright (c) Simple Container

package aws

import (
	"testing"

	. "github.com/onsi/gomega"
	"github.com/simple-container-com/api/pkg/api"
)

func TestApplyComponentRawToSingleImage_NilRaw(t *testing.T) {
	RegisterTestingT(t)
	cfg := &api.StackConfigSingleImage{}
	Ω(applyComponentRawToSingleImage(cfg, nil)).To(Succeed())
	Ω(cfg.Image).To(BeNil())
	Ω(cfg.Env).To(BeNil())
	Ω(cfg.Domain).To(BeEmpty())
	Ω(cfg.Secrets).To(BeNil())
}

func TestApplyComponentRawToSingleImage_NilConfig(t *testing.T) {
	RegisterTestingT(t)
	err := applyComponentRawToSingleImage(nil, map[string]any{"image": "foo"})
	Ω(err).To(HaveOccurred())
	Ω(err.Error()).To(ContainSubstring("nil *StackConfigSingleImage"))
}

func TestApplyComponentRawToSingleImage_ImageStringRef(t *testing.T) {
	RegisterTestingT(t)
	cfg := &api.StackConfigSingleImage{}
	Ω(applyComponentRawToSingleImage(cfg, map[string]any{
		"image": "simplecontainer/sc-component-dummy:v2026.11.11",
	})).To(Succeed())
	Ω(cfg.Image).NotTo(BeNil())
	Ω(cfg.Image.Name).To(Equal("simplecontainer/sc-component-dummy:v2026.11.11"))
	Ω(cfg.Image.Dockerfile).To(BeEmpty())
}

func TestApplyComponentRawToSingleImage_ImageMapWithBuildArgs(t *testing.T) {
	RegisterTestingT(t)
	cfg := &api.StackConfigSingleImage{}
	Ω(applyComponentRawToSingleImage(cfg, map[string]any{
		"image": map[string]any{
			"dockerfile": "/src/Dockerfile",
			"context":    "/src",
			"build": map[string]any{
				"args": map[string]any{
					"VERSION": "v1.2.3",
					"COMMIT":  "abc123",
				},
			},
		},
	})).To(Succeed())
	Ω(cfg.Image).NotTo(BeNil())
	Ω(cfg.Image.Dockerfile).To(Equal("/src/Dockerfile"))
	Ω(cfg.Image.Context).To(Equal("/src"))
	Ω(cfg.Image.Build).NotTo(BeNil())
	Ω(cfg.Image.Build.Args).To(Equal(map[string]string{
		"VERSION": "v1.2.3",
		"COMMIT":  "abc123",
	}))
}

func TestApplyComponentRawToSingleImage_ImageMergeOntoOperatorImage(t *testing.T) {
	RegisterTestingT(t)
	// Operator already set an image on the template (unusual but valid); the
	// component's dockerfile should override it, but operator's Build.Args
	// should merge with the component's.
	cfg := &api.StackConfigSingleImage{
		Image: &api.ContainerImage{
			Dockerfile: "/operator/Dockerfile",
			Build: &api.ContainerImageBuild{
				Args: map[string]string{"OPERATOR_ARG": "yes"},
			},
		},
	}
	Ω(applyComponentRawToSingleImage(cfg, map[string]any{
		"image": map[string]any{
			"dockerfile": "/component/Dockerfile",
			"build":      map[string]any{"args": map[string]any{"COMPONENT_ARG": "yes"}},
		},
	})).To(Succeed())
	Ω(cfg.Image.Dockerfile).To(Equal("/component/Dockerfile"))
	Ω(cfg.Image.Build.Args).To(Equal(map[string]string{
		"OPERATOR_ARG":  "yes",
		"COMPONENT_ARG": "yes",
	}))
}

func TestApplyComponentRawToSingleImage_ImageWrongShape(t *testing.T) {
	RegisterTestingT(t)
	cfg := &api.StackConfigSingleImage{}
	err := applyComponentRawToSingleImage(cfg, map[string]any{"image": 42})
	Ω(err).To(HaveOccurred())
	Ω(err.Error()).To(ContainSubstring("image: want string or map"))
}

func TestApplyComponentRawToSingleImage_EnvOverlay(t *testing.T) {
	RegisterTestingT(t)
	cfg := &api.StackConfigSingleImage{
		Env: map[string]string{"OPERATOR_VAR": "op", "SHARED": "op-val"},
	}
	Ω(applyComponentRawToSingleImage(cfg, map[string]any{
		"env": map[string]any{
			"COMPONENT_VAR": "comp",
			"SHARED":        "comp-val",
		},
	})).To(Succeed())
	Ω(cfg.Env).To(Equal(map[string]string{
		"OPERATOR_VAR":  "op",
		"COMPONENT_VAR": "comp",
		"SHARED":        "comp-val",
	}))
}

func TestApplyComponentRawToSingleImage_EnvWrongShape(t *testing.T) {
	RegisterTestingT(t)
	cfg := &api.StackConfigSingleImage{}
	err := applyComponentRawToSingleImage(cfg, map[string]any{
		"env": map[string]any{"VAR": 123},
	})
	Ω(err).To(HaveOccurred())
	Ω(err.Error()).To(ContainSubstring(`env["VAR"]`))
}

func TestApplyComponentRawToSingleImage_IngressHostname(t *testing.T) {
	RegisterTestingT(t)
	cfg := &api.StackConfigSingleImage{}
	Ω(applyComponentRawToSingleImage(cfg, map[string]any{
		"ingress": map[string]any{
			"hostname":  "my-dummy.simple-forge.com",
			"registrar": "cloudflare",
		},
	})).To(Succeed())
	Ω(cfg.Domain).To(Equal("my-dummy.simple-forge.com"))
}

func TestApplyComponentRawToSingleImage_SigningKey(t *testing.T) {
	RegisterTestingT(t)
	cfg := &api.StackConfigSingleImage{}
	Ω(applyComponentRawToSingleImage(cfg, map[string]any{
		"signingKey": "${secret:SMOKE_SIGNING_KEY}",
	})).To(Succeed())
	Ω(cfg.Secrets).To(HaveKey("SERVICE_JWT_SECRET"))
	Ω(cfg.Secrets["SERVICE_JWT_SECRET"]).To(Equal("${secret:SMOKE_SIGNING_KEY}"))
}

func TestApplyComponentRawToSingleImage_SigningKey_OperatorSecretWins(t *testing.T) {
	RegisterTestingT(t)
	cfg := &api.StackConfigSingleImage{
		Secrets: map[string]string{"SERVICE_JWT_SECRET": "${secret:OPERATOR_PICK}"},
	}
	Ω(applyComponentRawToSingleImage(cfg, map[string]any{
		"signingKey": "${secret:COMPONENT_PICK}",
	})).To(Succeed())
	// Operator's explicit declaration wins; component's signingKey is
	// not force-written over it.
	Ω(cfg.Secrets["SERVICE_JWT_SECRET"]).To(Equal("${secret:OPERATOR_PICK}"))
}

func TestApplyComponentRawToSingleImage_FullHappyPath(t *testing.T) {
	RegisterTestingT(t)
	cfg := &api.StackConfigSingleImage{}
	Ω(applyComponentRawToSingleImage(cfg, map[string]any{
		"image": map[string]any{
			"dockerfile": "/src/Dockerfile",
			"build":      map[string]any{"args": map[string]any{"REVISION": "deadbeef"}},
		},
		"env":        map[string]any{"ENV": "staging"},
		"ingress":    map[string]any{"hostname": "dummy.simple-forge.com"},
		"signingKey": "${secret:SMOKE}",
	})).To(Succeed())
	Ω(cfg.Image.Dockerfile).To(Equal("/src/Dockerfile"))
	Ω(cfg.Image.Build.Args["REVISION"]).To(Equal("deadbeef"))
	Ω(cfg.Env["ENV"]).To(Equal("staging"))
	Ω(cfg.Domain).To(Equal("dummy.simple-forge.com"))
	Ω(cfg.Secrets["SERVICE_JWT_SECRET"]).To(Equal("${secret:SMOKE}"))
}

// cloudExtras overlay — P1.1 of the backup plan 2026-11-12. The three
// cases below cover the merge rules sc-components asked for:
//   1. component writes a scalar into an empty slot.
//   2. operator's scalar wins on collision.
//   3. list fields (lambdaSchedules, awsRoles) append-merge.

func TestApplyComponentRawToSingleImage_CloudExtrasFillsEmptySlot(t *testing.T) {
	RegisterTestingT(t)
	// Operator did not set cfg.CloudExtras at all. Component sets
	// lambdaRoutingType — expect it to land on the final map.
	cfg := &api.StackConfigSingleImage{}
	Ω(applyComponentRawToSingleImage(cfg, map[string]any{
		"cloudExtras": map[string]any{
			"lambdaRoutingType": "function-url",
		},
	})).To(Succeed())
	Ω(cfg.CloudExtras).NotTo(BeNil())
	m, ok := (*cfg.CloudExtras).(map[string]any)
	Ω(ok).To(BeTrue(), "cfg.CloudExtras must be a map post-overlay")
	Ω(m["lambdaRoutingType"]).To(Equal("function-url"))
}

func TestApplyComponentRawToSingleImage_CloudExtrasOperatorWinsOnScalar(t *testing.T) {
	RegisterTestingT(t)
	// Operator set lambdaInvokeMode=BUFFERED. Component also sets it, to
	// RESPONSE_STREAM. Operator's value stays — matches the design doc's
	// "operator wins on compute shape" rule.
	existing := any(map[string]any{
		"lambdaInvokeMode": "BUFFERED",
	})
	cfg := &api.StackConfigSingleImage{CloudExtras: &existing}
	Ω(applyComponentRawToSingleImage(cfg, map[string]any{
		"cloudExtras": map[string]any{
			"lambdaInvokeMode": "RESPONSE_STREAM",
		},
	})).To(Succeed())
	m, _ := (*cfg.CloudExtras).(map[string]any)
	Ω(m["lambdaInvokeMode"]).To(Equal("BUFFERED"),
		"operator's lambdaInvokeMode must win on scalar collision")
}

func TestApplyComponentRawToSingleImage_CloudExtrasListsAppendMerge(t *testing.T) {
	RegisterTestingT(t)
	// Operator declares one lambdaSchedule + two awsRoles. Component declares
	// one schedule + one role. Final result MUST carry both operator entries
	// AND both component entries — the lists append, they don't override.
	// Operator order comes first, preserving author-declared ordering.
	existing := any(map[string]any{
		"lambdaSchedules": []any{
			map[string]any{"name": "op-tick", "expression": "rate(5 minutes)", "request": "{}"},
		},
		"awsRoles": []any{"s3:GetObject", "s3:PutObject"},
	})
	cfg := &api.StackConfigSingleImage{CloudExtras: &existing}
	Ω(applyComponentRawToSingleImage(cfg, map[string]any{
		"cloudExtras": map[string]any{
			"lambdaSchedules": []any{
				map[string]any{"name": "backup-tick", "expression": "rate(1 minute)", "request": "{}"},
			},
			"awsRoles": []any{"ecs:RunTask"},
		},
	})).To(Succeed())
	m, _ := (*cfg.CloudExtras).(map[string]any)
	schedules, _ := m["lambdaSchedules"].([]any)
	Ω(schedules).To(HaveLen(2), "operator + component schedules append, not override")
	Ω(schedules[0].(map[string]any)["name"]).To(Equal("op-tick"),
		"operator's entries come first — preserves author-declared ordering")
	Ω(schedules[1].(map[string]any)["name"]).To(Equal("backup-tick"))
	roles, _ := m["awsRoles"].([]any)
	Ω(roles).To(HaveLen(3))
	Ω(roles).To(ContainElements("s3:GetObject", "s3:PutObject", "ecs:RunTask"))
}

// Defensive cases — malformed wire shapes should return typed errors, not
// silently drop data. Mirrors the contract of parseComponentImage /
// parseComponentStringMap.

func TestApplyComponentRawToSingleImage_CloudExtrasWrongShape(t *testing.T) {
	RegisterTestingT(t)
	cfg := &api.StackConfigSingleImage{}
	err := applyComponentRawToSingleImage(cfg, map[string]any{"cloudExtras": 42})
	Ω(err).To(HaveOccurred())
	Ω(err.Error()).To(ContainSubstring("cloudExtras"))
}

func TestApplyComponentRawToSingleImage_CloudExtrasListFieldWrongShape(t *testing.T) {
	RegisterTestingT(t)
	cfg := &api.StackConfigSingleImage{}
	err := applyComponentRawToSingleImage(cfg, map[string]any{
		"cloudExtras": map[string]any{
			"awsRoles": "ecs:RunTask", // string where []any is expected
		},
	})
	Ω(err).To(HaveOccurred())
	Ω(err.Error()).To(ContainSubstring("awsRoles"))
}
