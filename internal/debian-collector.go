package internal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/go-hclog"
	"os/exec"
)

type DebianVersionCollector struct {
	logger hclog.Logger
}

func (c *DebianVersionCollector) GetInstalledPackages() (PackageVersions, string, error) {
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
	c.logger.Debug(fmt.Sprintf("RUNNING COMMAND: %s", command))
	dpkgCmd := exec.Command("bash", "-c", command)

	var dpkgOutput bytes.Buffer
	dpkgCmd.Stdout = &dpkgOutput
	dpkgCmd.Stderr = &dpkgOutput
	if err := dpkgCmd.Run(); err != nil {
		return nil, "", fmt.Errorf("error running dpkg-query: %w", err)
	}

	output := fmt.Sprintf("%s", dpkgOutput.String())
	c.logger.Debug(fmt.Sprintf("Installed Packages JSON:\n%s\n", output))

	// Parse the JSON output into a map
	var packages PackageVersions
	if err := json.Unmarshal([]byte(output), &packages); err != nil {
		return nil, output, fmt.Errorf("error parsing JSON output: %w", err)
	}

	return packages, output, nil
}
