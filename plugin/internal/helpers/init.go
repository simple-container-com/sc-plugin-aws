// SPDX-License-Identifier: MIT
// Copyright (c) Simple Container

package helpers

import (
	"github.com/simple-container-com/api/pkg/api"
)

// init registers the two CloudHelper constructors (CloudWatch alert
// Lambda + Health Bridge alert Lambda) with SC core's
// `api.cloudHelpersConfigMapping` registry. The ONLY consumer of that
// registry is the `cloud-helpers` Lambda binary (see
// `cmd/cloud-helpers/main.go`), so this registration lives on the
// plugin side rather than in `sc-plugin-aws/api/init.go` — pulling
// aws-sdk-go-v2/service/{cloudtrail,cloudwatchlogs} into the plugin's
// `/api` module (which SC core imports at parse time) would re-add
// transitive deps the extraction is trying to drop.
//
// The binary blank-imports this package to trigger this init.
func init() {
	api.RegisterCloudHelper(api.CloudHelpersRegisterMap{
		CHCloudwatchAlertLambda:   NewCloudwatchLambdaHelper,
		CHHealthBridgeAlertLambda: NewHealthBridgeLambdaHelper,
	})
}
