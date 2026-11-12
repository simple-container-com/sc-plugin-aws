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
