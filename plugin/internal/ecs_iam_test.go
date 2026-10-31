// SPDX-License-Identifier: MIT
// Copyright (c) Simple Container

package aws

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEcsExecutionSecretsAreStackScoped(t *testing.T) {
	for _, arns := range [][]string{nil, {"arn:aws:secretsmanager:eu-west-1:123456789012:secret:stack-a"}} {
		var doc struct {
			Statement []struct {
				Action   []string
				Resource []string
			}
		}
		if err := json.Unmarshal([]byte(ecsExecutionPolicy(arns)), &doc); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, s := range doc.Statement {
			for _, a := range s.Action {
				if a == "secretsmanager:GetSecretValue" {
					found = true
					if len(s.Resource) != len(arns) || len(arns) == 0 || s.Resource[0] != arns[0] {
						t.Fatalf("unscoped secret access: %+v", s)
					}
				}
			}
		}
		if found != (len(arns) > 0) {
			t.Fatalf("secret statement present=%t for %v", found, arns)
		}
	}
}

func TestEcsRuntimePermissionsAreExplicit(t *testing.T) {
	policy := ecsRuntimePolicy(nil, nil)
	for _, forbidden := range []string{"secretsmanager:", "ecr:", "elasticfilesystem:", "ssm:StartSession"} {
		if strings.Contains(policy, forbidden) {
			t.Fatalf("implicit runtime permission %s in %s", forbidden, policy)
		}
	}
	if !strings.Contains(policy, "ssmmessages:OpenDataChannel") {
		t.Fatal("ECS exec compatibility lost")
	}
	explicit := ecsRuntimePolicy([]string{"secretsmanager:GetSecretValue"}, []string{"arn:aws:elasticfilesystem:eu-west-1:123456789012:file-system/fs-stack"})
	if !strings.Contains(explicit, "secretsmanager:GetSecretValue") || !strings.Contains(explicit, "file-system/fs-stack") {
		t.Fatalf("explicit permissions lost: %s", explicit)
	}
}
