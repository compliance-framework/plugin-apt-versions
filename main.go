package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/compliance-framework/configuration-service/sdk"
	protolang "github.com/golang/protobuf/proto"
	"github.com/google/uuid"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"google.golang.org/protobuf/types/known/timestamppb"
	"os"
	"os/exec"
	"time"
)

type AptVersion struct {
	logger hclog.Logger
	config map[string]string
}

// Configure, PrepareForEval, and Eval are called at different times during the plugin execution lifecycle,
// and are responsible for different tasks:
//
// Configure is called on plugin startup. It is primarily used to configure a plugin for its lifetime.
// Here you should store any configurations like usernames and password required by the plugin.
//
// PrepareForEval is called on a scheduled execution of the plugin. Whenever the plugin is going to be run,
// PrepareForEval is called, so it can collect any data necessary for making assertions.
// Here you should run any commands, call any endpoints, or process any reports, which you want to turn into
// compliance findings and observations.
//
// Eval is called multiple times for each scheduled execution. It is responsible for running policies against the
// collected data from PrepareForEval. When a user passed multiple matching policy bundles to the agent, each of them
// will be passed to Eval in sequence. Eval will run against the collected data N times, where N is the amount
// of matching policies passed into the agent.
//
// A user starts the agent, and passes the plugin and any policy bundles.
//
// The agent will:
//   - Start the plugin
//   - Call Configure() with teh required config
//   - Call PrepareForEval() so the plugin can collect the relevant state
//   - Call Eval() with the first policy bundles (one by one, in turn),
//     so the plugin can report any violations against the configuration
func (l *AptVersion) Configure(req *proto.ConfigureRequest) (*proto.ConfigureResponse, error) {

	// Configure is used to set up any configuration needed by this plugin over its lifetime.
	// This will likely only be called once on plugin startup, which may then run for an extended period of time.

	// In this method, you should save any configuration values to your plugin struct, so you can later
	// re-use them in PrepareForEval and Eval.

	l.config = req.Config
	return &proto.ConfigureResponse{}, nil
}

// GetInstalledPackages retrieves the list of installed packages in JSON format
func GetInstalledPackages(l *AptVersion) (map[string]interface{}, string, error) {
	command := `
	               dpkg-query -W -f='${Package} ${Version}\n' |
	               sed -E '
	                          # We want to extract the major, minor, and patch versions from the apt version string, eg: 1:2.38.1-5+deb12u3 => 2.38.1
                              # Remove anything after the '-+~'
                              s/^([^[:space:]]*)[[:space:]](.*)[-+~].*/\1 \2/g;

	                          # If we see x.y.z, then extract those
                              s/^([^[:space:]]*)[[:space:]]([0-9]*:?)?:?([0-9]+)\.([0-9]+)[\.-]([0-9]+).*/\1 \3.\4.\5/g;

	                          # Remove 'ubuntu' et al
                              s/^([^[:space:]]*)[[:space:]]([^a-z]*)([a-z]+)([^a-z].*)/\1 \2.\4/g;

	                          # Then, if we see x.y, then extract that, and add a 0 for the patch version
                              s/^([[^:space:]]*)[[:space:]]([0-9]*:?)?:?([0-9]+)\.([0-9]+)[^.].*/\1 \3.\4.0/g;

	                          # Then, remove leading zeroes
	                          s/\b0*([1-9][0-9]*)/\1/g;

	                          # Truncate those items that have more than three points in the version x.y.z.a rather than x.y.z
	                          s/([^[:space:]]*)[[:space:]]([0-9]+)\.([0-9]+)\.([0-9]+)\..*/\1 \2.\3.\4/;

	                          # Add a zero for those items with only x.y rather than x.y.z
	                          s/([^[:space:]]*)[[:space:]]([0-9]+)\.([0-9]+)$/\1 \2.\3.0/;

	                          # Add two zero for those items with only x rather than x.y.z
	                          s/([^[:space:]]*)[[:space:]]([0-9]+)$/\1 \2.0.0/;

	                          # Now, turn that into a json object:
	                          s/^(.*)[[:space:]](.*)/"\1": "\2"/;
                          ' |
                   awk '
	                       # Turn that into a json document
	                       BEGIN { print "{" } { print (NR>1?",":"") $0 } END { print "}" }
                       ' |
	               tr '\n' ' '
	           `
	l.logger.Debug(fmt.Sprintf("RUNNING COMMAND: %s", command))
	dpkgCmd := exec.Command("bash", "-c", command)

	var dpkgOutput bytes.Buffer
	dpkgCmd.Stdout = &dpkgOutput
	dpkgCmd.Stderr = &dpkgOutput
	if err := dpkgCmd.Run(); err != nil {
		return nil, "", fmt.Errorf("error running dpkg-query: %w", err)
	}

	output := fmt.Sprintf("%s", dpkgOutput.String())
	l.logger.Debug(fmt.Sprintf("Installed Packages JSON:\n%s\n", output))

	// Parse the JSON output into a map
	var packages map[string]interface{}
	if err := json.Unmarshal([]byte(output), &packages); err != nil {
		return nil, output, fmt.Errorf("error parsing JSON output: %w", err)
	}

	return packages, output, nil
}

func (l *AptVersion) Eval(request *proto.EvalRequest, apiHelper runner.ApiHelper) (*proto.EvalResponse, error) {

	// Eval is used to run policies against the data you've collected in PrepareForEval.
	// Eval will be called N times for every scheduled plugin execution where N is the amount of matching policies
	// passed to the agent.

	// When a user passes multiple policy bundles to the agent, each will be passed to Eval in turn to run against the
	// same data collected in PrepareForEval.

	ctx := context.TODO()
	startTime := time.Now()

	data, output, err := GetInstalledPackages(l)
	l.logger.Debug(fmt.Sprintf("JSON OUTPUT 0.1.6: %s", output))
	if err != nil {
		return nil, fmt.Errorf("error getting installed packages: %w", err)
	}

	for _, policyPath := range request.GetPolicyPaths() {
		// The Policy Manager aggregates much of the policy execution and output structuring.
		results, err := policyManager.
			New(ctx, l.logger, policyPath).
			Execute(ctx, "apt_version", data)

		if err != nil {
			l.logger.Error("Failed to evaluate against policy bundle", "error", err)
			return &proto.EvalResponse{
				Status: proto.ExecutionStatus_FAILURE,
			}, err
		}

		hostname := os.Getenv("HOSTNAME")

		response := runner.NewCallableAssessmentResult()
		response.Title = fmt.Sprintf("Package Version compliance for host: %s", hostname)

		for _, policyResult := range results {

			// There are no violations reported from the policies.
			// We'll send the observation back to the agent
			if len(policyResult.Violations) == 0 {
				response.AddObservation(&proto.Observation{
					Uuid:        uuid.New().String(),
					Title:       protolang.String("The plugin succeeded. No compliance issues to report."),
					Description: "The plugin policies did not return any violations. The configuration is in compliance with policies.",
					Collected:   timestamppb.New(time.Now()),
					Expires:     timestamppb.New(time.Now().AddDate(0, 1, 0)), // Add one month for the expiration
					RelevantEvidence: []*proto.RelevantEvidence{
						{
							Description: fmt.Sprintf("Policy %v was evaluated, and no violations were found on machineId: %s", policyResult.Policy.Package.PurePackage(), "ARN:12345"),
						},
					},
				})

				response.AddFinding(&proto.Finding{
					Title:       fmt.Sprintf("No violations found on %s", policyResult.Policy.Package.PurePackage()),
					Description: fmt.Sprintf("No violations found on the %s policy within the Apt Versions Plugin.", policyResult.Policy.Package.PurePackage()),
					Target: &proto.FindingTarget{
						Status: &proto.ObjectiveStatus{
							State: runner.FindingTargetStatusSatisfied,
						},
					},
				})
			}

			// There are violations in the policy checks.
			// We'll send these observations back to the agent
			if len(policyResult.Violations) > 0 {
				observation := &proto.Observation{
					Uuid:        uuid.New().String(),
					Title:       protolang.String(fmt.Sprintf("The plugin found violations for policy %s on machineId: %s", policyResult.Policy.Package.PurePackage(), "ARN:12345")),
					Description: fmt.Sprintf("Observed %d violation(s) for policy %s within the Plugin on machineId: %s.", len(policyResult.Violations), policyResult.Policy.Package.PurePackage(), "ARN:12345"),
					Collected:   timestamppb.New(time.Now()),
					Expires:     timestamppb.New(time.Now().AddDate(0, 1, 0)), // Add one month for the expiration
					RelevantEvidence: []*proto.RelevantEvidence{
						{
							Description: fmt.Sprintf("Policy %v was evaluated, and %d violations were found on machineId: %s", policyResult.Policy.Package.PurePackage(), len(policyResult.Violations), "ARN:12345"),
						},
					},
				}
				response.AddObservation(observation)

				for _, violation := range policyResult.Violations {
					response.AddFinding(&proto.Finding{
						Uuid:        uuid.New().String(),
						Title:       violation.Title,
						Description: violation.Description,
						Remarks:     protolang.String(violation.Remarks),
						RelatedObservations: []*proto.RelatedObservation{
							{
								ObservationUuid: observation.Uuid,
							},
						},
						Target: &proto.FindingTarget{
							Status: &proto.ObjectiveStatus{
								State: runner.FindingTargetStatusNotSatisfied,
							},
						},
					})
				}

			}
		}

		endTime := time.Now()
		response.Start = timestamppb.New(startTime)
		response.End = timestamppb.New(endTime)
		response.AddLogEntry(&proto.AssessmentLog_Entry{
			Title: protolang.String("Plugin checks completed"),
			Start: timestamppb.New(startTime),
			End:   timestamppb.New(endTime),
		})

		streamId, err := sdk.SeededUUID(map[string]string{
			"type":      "apt-versions",
			"_hostname": hostname,
			"_policy":   policyPath,
		})
		if err != nil {
			return nil, err
		}
		if err := apiHelper.CreateResult(streamId.String(), map[string]string{
			"type":      "apt-versions",
			"_hostname": hostname,
			"_policy":   policyPath,
		}, policyPath, response.Result()); err != nil {
			l.logger.Error("Failed to add assessment result", "error", err)
			return &proto.EvalResponse{
				Status: proto.ExecutionStatus_FAILURE,
			}, err
		}
	}

	return &proto.EvalResponse{
		Status: proto.ExecutionStatus_SUCCESS,
	}, nil
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
