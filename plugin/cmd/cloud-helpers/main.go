// SPDX-License-Identifier: MIT
// Copyright (c) Simple Container

// cloud-helpers is the Lambda-side runtime for the two AWS CloudHelpers
// provisioned by sc-plugin-aws:
//
//   - sc-helper-aws-cloudwatch-alert-lambda — receives CloudWatch alarm
//     state-change notifications over SNS, renders them to a Slack-shaped
//     payload including the recent CloudWatch Logs excerpt around the
//     breach, and posts to the configured webhook. See
//     plugin/internal/helpers/ch_cloudwatch_alert.go.
//
//   - sc-helper-aws-health-bridge-lambda — bridges AWS Health events
//     (via EventBridge → SNS) to the same alert webhook. See
//     plugin/internal/helpers/ch_healthevent_trigger.go.
//
// The runtime selects which helper to dispatch to via the
// `SIMPLE_CONTAINER_CLOUD_HELPER_TYPE` env var — set at Lambda
// provisioning time by alerts.go. Each helper registers itself with
// SC core's api.cloudHelpersConfigMapping registry via
// plugin/internal/helpers/init.go, which this binary pulls in via a
// blank import.
//
// Why this binary lives in sc-plugin-aws rather than SC core: the
// helpers package imports aws-sdk-go-v2/service/cloudtrail +
// aws-sdk-go-v2/service/cloudwatchlogs. Keeping the registration path
// out of SC core keeps those transitive deps out of SC core too.
package main

import (
	"context"
	"os"
	"time"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/simple-container-com/api/pkg/api"
	"github.com/simple-container-com/api/pkg/api/logger"
	// Blank-import pulls in the helpers package's init() which
	// registers the two CloudHelper constructors with SC core's
	// api.cloudHelpersConfigMapping. Without this, NewCloudHelper
	// below returns "unknown cloud helper type".
	_ "github.com/simple-container-com/sc-plugin-aws/plugin/internal/helpers"
)

// version is overridden by the release workflow with the CalVer tag.
var version = "latest"

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	chType := os.Getenv(api.ComputeEnv.CloudHelperType)

	handlerCmd := &cobra.Command{
		Use:     "cloud-helpers",
		Version: version,
		Short:   "Simple Container Cloud Helpers — AWS Lambda-side alert handlers.",
		Long:    "Runtime entrypoint for CloudWatch-alarm and AWS Health alert bridges, provisioned by sc-plugin-aws.",
		RunE: func(_ *cobra.Command, _ []string) error {
			ch, err := api.NewCloudHelper(chType, api.WithLogger(logger.New()))
			if err != nil {
				return errors.Wrapf(err, "failed to init cloud helper, did you pass %q env variable?", api.ComputeEnv.CloudHelperType)
			}
			if raw := os.Getenv("SIMPLE_CONTAINER_STARTUP_DELAY"); raw != "" {
				d, err := time.ParseDuration(raw)
				if err != nil {
					return errors.Wrapf(err, "failed to parse SIMPLE_CONTAINER_STARTUP_DELAY")
				}
				time.Sleep(d)
			}
			return ch.Run()
		},
	}

	handlerCmd.SetContext(ctx)
	handlerCmd.SetVersionTemplate("{{printf \"%s\\n\" .Version}}")

	if err := handlerCmd.Execute(); err != nil {
		panic(err)
	}
}
