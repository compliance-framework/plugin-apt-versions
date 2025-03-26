package internal

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"

	"github.com/compliance-framework/agent/runner/proto"
	"github.com/hashicorp/go-hclog"
)

// GetInstalledPackages retrieves the list of installed packages in JSON format
func GetInstalledPackages(logger hclog.Logger) (map[string]any, []*proto.Step, error) {
	steps := make([]*proto.Step, 0)

	steps = append(steps, &proto.Step{
		Title:       "Get installed packages",
		Description: "Get the list of installed package names and versions on the host using the `dpkg-query` command. This will be used to evaluate the versions of installed packages against the policies supplied.",
		Remarks:     StringAddressed("`dpkg-query -W -f='${Package} ${Version}'` is used to collect the installed packages and their versions."),
	})

	command := `dpkg-query -W -f='${Package} ${Version}\n'`
	logger.Debug(fmt.Sprintf("RUNNING COMMAND: %s", command))
	dpkgCmd := exec.Command("bash", "-c", command)

	var dpkgStdout bytes.Buffer
	var dpkgStderr bytes.Buffer
	dpkgCmd.Stdout = &dpkgStdout
	dpkgCmd.Stderr = &dpkgStderr
	if err := dpkgCmd.Run(); err != nil {
		if dpkgStderr.Len() > 0 {
			logger.Error(fmt.Sprintf("stderr: %s", dpkgStderr.String()))
		}
		return nil, steps, fmt.Errorf("error running dpkg-query: %w", err)
	}

	if dpkgStderr.Len() > 0 {
		logger.Warn(fmt.Sprintf("error found running dpkg-query, continuing as exited successfully: %s", dpkgStderr.String()))
	}

	// Parse the output into a map
	packages, newSteps := getPackages(logger, dpkgStdout.String())
	steps = append(steps, newSteps...)

	return packages, steps, nil
}

func getPackages(logger hclog.Logger, packageData string) (map[string]any, []*proto.Step) {
	packages := make(map[string]any)

	for _, line := range strings.Split(packageData, "\n") {
		if len(line) == 0 {
			continue
		}

		parts := strings.Split(line, " ")
		if len(parts) != 2 {
			logger.Warn(fmt.Sprintf("unexpected number of parts in package line, cannot process: %s", line))
			continue
		}

		packageName := parts[0]
		packageVersion := getVersion(parts[1])

		packages[packageName] = packageVersion
	}

	step := &proto.Step{
		Title:       "Retrieved all installed packages and normalised versions",
		Description: "Retrieved all the installed packages and their versions on the host. The versions are all normalised to a standard format for comparison of the format `x.y.z` where `x`, `y` and `z` are all integers and intended to match the standard SemVer pattern of `major.minor.patch`.",
		Remarks:     StringAddressed(fmt.Sprintf("Normalized %d package versions", len(packages))),
	}

	return packages, []*proto.Step{step}
}

func getVersion(version string) string {
	// If the version contains a colon, we'll split the string and return the version from the second part
	if colonIndex := strings.Index(version, ":"); colonIndex != -1 {
		version = version[colonIndex+1:]
	}

	// If we have any of the characters, '-', '+', '~', we'll split the string and return the version from the first part
	if dashIndex := strings.IndexAny(version, "-+~"); dashIndex != -1 {
		version = version[:dashIndex]
	}

	// Split the version into parts
	parts := strings.Split(version, ".")

	// Check each part is just a number, if it's not we'll split the part and only keep the number
	for i, part := range parts {
		// If the part contains a string after a number we skip from the number onwards
		for j, char := range part {
			if char >= '0' && char <= '9' {
				continue
			}
			parts[i] = part[:j]
			break
		}
	}

	// Check each part for leading zeros and remove them
	for i, part := range parts {
		for j, char := range part {
			if char != '0' {
				parts[i] = part[j:]
				break
			}
		}
	}

	// Make sure we have exactly 3 parts separated by a dot, if we don't we append 0 to the version, if more we skip the rest
	if len(parts) < 3 {
		for i := len(parts); i < 3; i++ {
			parts = append(parts, "0")
		}
	} else if len(parts) > 3 {
		parts = parts[:3]
	}

	version = strings.Join(parts, ".")

	return version
}
