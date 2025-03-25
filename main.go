package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/compliance-framework/configuration-service/sdk"
	"github.com/compliance-framework/plugin-apt-versions/internal"
	"github.com/google/uuid"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type AptVersion struct {
	logger hclog.Logger
	config map[string]string
}

// Configure, and Eval are called at different times during the plugin execution lifecycle,
// and are responsible for different tasks:
//
// Configure is called on plugin startup. It is primarily used to configure a plugin for its lifetime.
// Here you should store any configurations like usernames and password required by the plugin.
//
// Eval is called once for each scheduled execution with a list of policy paths and it is responsible
// for evaluating each of these policy paths against the data it requires to evaluate those policies.
// The plugin is responsible for collecting the data it needs to evaluate the policies in the Eval
// method and then running the policies against that data.
//
// The simplest way to handle multiple policies is to do an initial lookup of all the data that may
// be required for all policies in the method, and then run the policies against that data. This,
// however, may not be the most efficient way to run policies, and you may want to optimize this
// while writing plugins to reduce the amount of data you need to collect and store in memory. It
// is the plugins responsibility to ensure that it is (reasonably) efficient in its use of
// resources.
//
// A user starts the agent, and passes the plugin and any policy bundles.
//
// The agent will:
//   - Start the plugin
//   - Call Configure() with teh required config
//   - Call Eval() with the first policy bundles (one by one, in turn),
//     so the plugin can report any violations against the configuration
func (l *AptVersion) Configure(req *proto.ConfigureRequest) (*proto.ConfigureResponse, error) {

	// Configure is used to set up any configuration needed by this plugin over its lifetime.
	// This will likely only be called once on plugin startup, which may then run for an extended period of time.

	l.config = req.GetConfig()
	return &proto.ConfigureResponse{}, nil
}

func (l *AptVersion) Eval(request *proto.EvalRequest, apiHelper runner.ApiHelper) (*proto.EvalResponse, error) {
	ctx := context.TODO()

	activities := make([]*proto.Activity, 0)

	data, getInstalledPackagesSteps, err := internal.GetInstalledPackages(l.logger)
	l.logger.Trace(fmt.Sprintf("Packages output: %s", data))
	if err != nil {
		return nil, fmt.Errorf("error getting installed packages: %w", err)
	}

	activities = append(activities, &proto.Activity{
		Title:       "Collect OS packages installed",
		Description: "Collect OS packages installed on the host machine, and prepare collected data for validation in policy engine",
		Steps:       getInstalledPackagesSteps,
	})

	observations, findings, err := l.evaluatePolicies(ctx, activities, data, request)
	if err != nil {
		return &proto.EvalResponse{
			Status: proto.ExecutionStatus_FAILURE,
		}, err
	}

	if err = apiHelper.CreateObservations(ctx, observations); err != nil {
		l.logger.Error("Failed to send observations", "error", err)
		return &proto.EvalResponse{
			Status: proto.ExecutionStatus_FAILURE,
		}, err
	}

	if err = apiHelper.CreateFindings(ctx, findings); err != nil {
		l.logger.Error("Failed to send findings", "error", err)
		return &proto.EvalResponse{
			Status: proto.ExecutionStatus_FAILURE,
		}, err
	}

	return &proto.EvalResponse{
		Status: proto.ExecutionStatus_SUCCESS,
	}, err
}

func (l *AptVersion) evaluatePolicies(ctx context.Context, activities []*proto.Activity, packageData map[string]interface{}, req *proto.EvalRequest) ([]*proto.Observation, []*proto.Finding, error) {
	startTime := time.Now()
	var accumulatedErrors error

	findings := make([]*proto.Finding, 0)
	observations := make([]*proto.Observation, 0)

	l.logger.Debug("config", l.config)

	for _, policyPath := range req.GetPolicyPaths() {
		steps := make([]*proto.Step, 0)
		steps = append(steps, &proto.Step{
			Title:       "Compile policy bundle",
			Description: "Using a locally addressable policy path, compile the policy files to an in memory executable.",
		})
		steps = append(steps, &proto.Step{
			Title:       "Execute policy bundle",
			Description: "Using previously collected JSON-formatted installed OS package data, execute the compiled policies",
		})
		results, err := policyManager.New(ctx, l.logger, policyPath).Execute(ctx, "apt_version", packageData)
		if err != nil {
			l.logger.Error("Failed to evaluate against policy bundle", "error", err)
			accumulatedErrors = errors.Join(accumulatedErrors, err)
			return observations, findings, accumulatedErrors
		}

		hostname := os.Getenv("HOSTNAME")
		subjectAttributeMap := map[string]string{
			"type":     "machine-instance",
			"hostname": hostname,
		}
		subjects := []*proto.SubjectReference{
			{
				Type:       "machine-instance",
				Attributes: subjectAttributeMap,
				Title:      internal.StringAddressed("Machine Instance"),
				Remarks:    internal.StringAddressed("A machine instance where we've retrieved the installed packages."),
				Props: []*proto.Property{
					{
						Name:    "hostname",
						Value:   hostname,
						Remarks: internal.StringAddressed("The local hostname of the machine where the plugin has been executed"),
					},
				},
			},
		}
		actors := []*proto.OriginActor{
			{
				Title: "The Continuous Compliance Framework",
				Type:  "assessment-platform",
				Links: []*proto.Link{
					{
						Href: "https://compliance-framework.github.io/docs/",
						Rel:  internal.StringAddressed("reference"),
						Text: internal.StringAddressed("The Continuous Compliance Framework"),
					},
				},
				Props: nil,
			},
			{
				Title: "Continuous Compliance Framework - Local APT Installed Packages Plugin",
				Type:  "tool",
				Links: []*proto.Link{
					{
						Href: "https://github.com/compliance-framework/plugin-apt-versions",
						Rel:  internal.StringAddressed("reference"),
						Text: internal.StringAddressed("The Continuous Compliance Framework' Local APT Installed Packages Plugin"),
					},
				},
				Props: nil,
			},
		}
		components := []*proto.ComponentReference{
			{
				Identifier: "common-components/package",
			},
		}

		activities = append(activities, &proto.Activity{
			Title:       "Compile Results",
			Description: "Using the output from policy execution, compile the resulting output to Observations and Findings, marking any violations, risks, and other OSCAL-familiar data",
			Steps:       steps,
		})

		for _, result := range results {
			// Observation UUID should differ for each individual subject, but remain consistent when validating the same policy for the same subject.
			// This acts as an identifier to show the history of an observation.
			observationUUIDMap := internal.MergeMaps(subjectAttributeMap, map[string]string{
				"policy":      result.Policy.Package.PurePackage(),
				"policy_file": result.Policy.File,
				"policy_path": policyPath,
			})
			observationUUID, err := sdk.SeededUUID(observationUUIDMap)
			if err != nil {
				accumulatedErrors = errors.Join(accumulatedErrors, err)
				// We've been unable to do much here, but let's try the next one regardless.
				continue
			}

			// Finding UUID should differ for each individual subject, but remain consistent when validating the same policy for the same subject.
			// This acts as an identifier to show the history of a finding.
			findingUUIDMap := internal.MergeMaps(subjectAttributeMap, map[string]string{
				"policy":      result.Policy.Package.PurePackage(),
				"policy_file": result.Policy.File,
				"policy_path": policyPath,
			})
			findingUUID, err := sdk.SeededUUID(findingUUIDMap)
			if err != nil {
				accumulatedErrors = errors.Join(accumulatedErrors, err)
				// We've been unable to do much here, but let's try the next one regardless.
				continue
			}

			observation := proto.Observation{
				ID:         uuid.New().String(),
				UUID:       observationUUID.String(),
				Collected:  timestamppb.New(startTime),
				Expires:    timestamppb.New(startTime.Add(24 * time.Hour)),
				Origins:    []*proto.Origin{{Actors: actors}},
				Subjects:   subjects,
				Activities: activities,
				Components: components,
				RelevantEvidence: []*proto.RelevantEvidence{
					{
						Description: fmt.Sprintf("Policy %v was executed against the local APT installed packages, using the Local APT Packages Compliance Plugin", result.Policy.Package.PurePackage()),
					},
				},
			}

			newFinding := func() *proto.Finding {
				return &proto.Finding{
					ID:        uuid.New().String(),
					UUID:      findingUUID.String(),
					Collected: timestamppb.New(time.Now()),
					Labels: map[string]string{
						"type":         "package",
						"host":         hostname,
						"_policy":      result.Policy.Package.PurePackage(),
						"_policy_path": result.Policy.File,
					},
					Origins:             []*proto.Origin{{Actors: actors}},
					Subjects:            subjects,
					Components:          components,
					RelatedObservations: []*proto.RelatedObservation{{ObservationUUID: observation.ID}},
					Controls:            nil,
				}
			}

			if len(result.Violations) == 0 {
				observation.Title = internal.StringAddressed(fmt.Sprintf("Local APT package validation on %s passed.", result.Policy.Package.PurePackage()))
				observation.Description = fmt.Sprintf("Observed no violations on the %s policy within the Local APT Installed Package Compliance Plugin.", result.Policy.Package.PurePackage())
				observations = append(observations, &observation)

				finding := newFinding()
				finding.Title = fmt.Sprintf("No violations found on %s", result.Policy.Package.PurePackage())
				finding.Description = fmt.Sprintf("No violations found on the %s policy within the Local APT Packages Compliance Plugin.", result.Policy.Package.PurePackage())
				finding.Status = &proto.FindingStatus{
					State: runner.FindingTargetStatusSatisfied,
				}
				findings = append(findings, finding)
			} else {
				observation.Title = internal.StringAddressed(fmt.Sprintf("Validation on %s failed.", result.Policy.Package.PurePackage()))
				observation.Description = fmt.Sprintf("Observed %d violation(s) on the %s policy within the Local APT Packaged Compliance Plugin.", len(result.Violations), result.Policy.Package.PurePackage())
				observations = append(observations, &observation)

				for _, violation := range result.Violations {
					finding := newFinding()
					finding.Title = violation.Title
					finding.Description = violation.Description
					finding.Remarks = internal.StringAddressed(violation.Remarks)
					finding.Status = &proto.FindingStatus{
						State: runner.FindingTargetStatusNotSatisfied,
					}
					findings = append(findings, finding)
				}
			}
		}
	}

	return observations, findings, nil
}

func main() {
	logger := hclog.New(&hclog.LoggerOptions{
		Level:      hclog.Debug,
		JSONFormat: true,
	})

	aptVersionObj := &AptVersion{
		logger: logger,
	}

	goplugin.Serve(&goplugin.ServeConfig{
		HandshakeConfig: runner.HandshakeConfig,
		Plugins: map[string]goplugin.Plugin{
			"runner": &runner.RunnerGRPCPlugin{
				Impl: aptVersionObj,
			},
		},
		GRPCServer: goplugin.DefaultGRPCServer,
	})
}
