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
	packages := getPackages(dpkgStdout.String())

	return packages, steps, nil
}

func getPackages(output string) map[string]any {
	packages := make(map[string]any)

	for _, line := range strings.Split(output, "\n") {
		if len(line) == 0 {
			continue
		}

		parts := strings.Split(line, " ")
		if len(parts) != 2 {
			continue
		}

		packageName := parts[0]
		packageVersion := getVersion(parts[1])

		packages[packageName] = packageVersion
	}

	return packages
}

func getVersion(version string) string {
	// // If the version contains a colon, we'll split the string and return the version from the second part
	// if colonIndex := strings.Index(version, ":"); colonIndex != -1 {
	// 	return version[colonIndex+1:]
	// }

	// // If we have any of the characters, '-', '+', '~', we'll split the string and return the version from the first part
	// if dashIndex := strings.IndexAny(version, "-+~"); dashIndex != -1 {
	// 	version = version[:dashIndex]
	// }

	// // Split the version into parts
	// parts := strings.Split(version, ".")

	// // Check each part it just a number, if it's not we'll split the part and only keep the number
	// for i, part := range parts {
	// 	// If the part contains a string after a number we skip from the number onwards
	// 	for j, char := range part {
	// 		if char >= '0' && char <= '9' {
	// 			continue
	// 		}
	// 		parts[i] = part[:j]
	// 		break
	// 	}
	// }

	// // Check each part for leading zeros and remove them
	// for i, part := range parts {
	// 	for j, char := range part {
	// 		if char != '0' {
	// 			parts[i] = part[j:]
	// 			break
	// 		}
	// 	}
	// }

	// // Make sure we have exactly 3 parts separated by a dot, if we don't we append 0 to the version, if more we skip the rest
	// if len(parts) < 3 {
	// 	for i := len(parts); i < 3; i++ {
	// 		version += ".0"
	// 	}
	// }
	// if len(parts) > 3 {
	// 	version = strings.Join(parts[:3], ".")
	// }

	return version
}
