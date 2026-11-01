// SPDX-License-Identifier: MIT
// Copyright (c) Simple Container

package aws

import "encoding/json"

type ecsIAMStatement struct {
	Effect   string   `json:"Effect"`
	Action   []string `json:"Action"`
	Resource []string `json:"Resource"`
}

func ecsPolicyJSON(statements []ecsIAMStatement) string {
	// All values are strings and slices; marshaling cannot fail.
	policy, _ := json.Marshal(struct {
		Version   string            `json:"Version"`
		Statement []ecsIAMStatement `json:"Statement"`
	}{"2012-10-17", statements})
	return string(policy)
}

func ecsExecutionPolicy(secretARNs []string) string {
	statements := []ecsIAMStatement{{"Allow", []string{
		"ecr:GetAuthorizationToken", "ecr:BatchGetImage", "ecr:BatchCheckLayerAvailability", "ecr:GetDownloadUrlForLayer",
		"logs:CreateLogStream", "logs:CreateLogGroup", "logs:PutLogEvents",
	}, []string{"*"}}}
	if len(secretARNs) > 0 {
		statements = append(statements, ecsIAMStatement{"Allow", []string{"secretsmanager:GetSecretValue"}, secretARNs})
	}
	return ecsPolicyJSON(statements)
}

func ecsRuntimePolicy(extraActions, fileSystemARNs []string) string {
	statements := []ecsIAMStatement{{"Allow", []string{
		"ssmmessages:CreateControlChannel", "ssmmessages:CreateDataChannel",
		"ssmmessages:OpenControlChannel", "ssmmessages:OpenDataChannel",
	}, []string{"*"}}}
	if len(fileSystemARNs) > 0 {
		statements = append(statements, ecsIAMStatement{"Allow", []string{"elasticfilesystem:ClientMount", "elasticfilesystem:ClientWrite"}, fileSystemARNs})
	}
	// awsRoles remains an explicit, backwards-compatible request for runtime actions.
	if len(extraActions) > 0 {
		statements = append(statements, ecsIAMStatement{"Allow", extraActions, []string{"*"}})
	}
	return ecsPolicyJSON(statements)
}
