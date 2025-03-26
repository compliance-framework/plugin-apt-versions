package internal

import (
	"strings"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
)

func TestGetSimplePackage(t *testing.T) {
	logger := hclog.New(&hclog.LoggerOptions{
		Level:      hclog.Error,
		JSONFormat: true,
	})
	packages, steps := getPackages(logger, "mycoolpackage 1.2.3\n")

	version := packages["mycoolpackage"].(string)
	assert.Equal(t, version, "1.2.3")
	assert.Len(t, steps, 1)
}

func TestGetPackageWithEpochVersion(t *testing.T) {
	logger := hclog.New(&hclog.LoggerOptions{
		Level:      hclog.Error,
		JSONFormat: true,
	})
	packages, steps := getPackages(logger, "mycoolpackage 2:1.2.3\n")

	version := packages["mycoolpackage"].(string)
	assert.Equal(t, version, "1.2.3")
	assert.Len(t, steps, 1)

	packages, steps = getPackages(logger, "mycoolpackage 24:1.2\n")

	version = packages["mycoolpackage"].(string)
	assert.Equal(t, version, "1.2.0")
	assert.Len(t, steps, 1)
}

func TestGetPackageWithSpecialCharactersInVersion(t *testing.T) {
	logger := hclog.New(&hclog.LoggerOptions{
		Level:      hclog.Error,
		JSONFormat: true,
	})
	packages, steps := getPackages(logger, "mycoolpackage 1.2.3-1~ubuntu1\n")

	version := packages["mycoolpackage"].(string)
	assert.Equal(t, version, "1.2.3")
	assert.Len(t, steps, 1)

	packages, steps = getPackages(logger, "mycoolpackage 1.2-1ubuntu1+foo\n")

	version = packages["mycoolpackage"].(string)
	assert.Equal(t, version, "1.2.0")
	assert.Len(t, steps, 1)

	packages, steps = getPackages(logger, "mycoolpackage 25.2.35+ubuntu1\n")

	version = packages["mycoolpackage"].(string)
	assert.Equal(t, version, "25.2.35")
}

func TestGetPackageWithStringCharsInVersion(t *testing.T) {
	logger := hclog.New(&hclog.LoggerOptions{
		Level:      hclog.Error,
		JSONFormat: true,
	})
	packages, steps := getPackages(logger, "mycoolpackage 1.2.3ubuntu1\n")

	version := packages["mycoolpackage"].(string)
	assert.Equal(t, version, "1.2.3")
	assert.Len(t, steps, 1)

	packages, steps = getPackages(logger, "mycoolpackage 25.22ubuntu1\n")

	version = packages["mycoolpackage"].(string)
	assert.Equal(t, version, "25.22.0")
	assert.Len(t, steps, 1)

	packages, steps = getPackages(logger, "mycoolpackage 25.22ubuntu1.44mystring1\n")

	version = packages["mycoolpackage"].(string)
	assert.Equal(t, version, "25.22.44")
	assert.Len(t, steps, 1)
}

func TestGetPackageWithLeadingZeroesInVersion(t *testing.T) {
	logger := hclog.New(&hclog.LoggerOptions{
		Level:      hclog.Error,
		JSONFormat: true,
	})
	packages, steps := getPackages(logger, "mycoolpackage 01.2.3\n")

	version := packages["mycoolpackage"].(string)
	assert.Equal(t, version, "1.2.3")
	assert.Len(t, steps, 1)

	packages, steps = getPackages(logger, "mycoolpackage 25.02\n")

	version = packages["mycoolpackage"].(string)
	assert.Equal(t, version, "25.2.0")
	assert.Len(t, steps, 1)
}

func TestGetPackageWithoutThreeNumsInVersion(t *testing.T) {
	logger := hclog.New(&hclog.LoggerOptions{
		Level:      hclog.Error,
		JSONFormat: true,
	})
	packages, steps := getPackages(logger, "mycoolpackage 1.2\n")

	version := packages["mycoolpackage"].(string)
	assert.Equal(t, version, "1.2.0")
	assert.Len(t, steps, 1)

	packages, steps = getPackages(logger, "mycoolpackage 25.2.5.1.6\n")

	version = packages["mycoolpackage"].(string)
	assert.Equal(t, version, "25.2.5")
	assert.Len(t, steps, 1)
}

func TestGetMultiplePackagesFromRealExamples(t *testing.T) {
	// Setup
	logger := hclog.New(&hclog.LoggerOptions{
		Level:      hclog.Error,
		JSONFormat: true,
	})

	packageStrings := []string{
		"accountsservice 23.13.9-2ubuntu6",
		"acl 2.3.2-1build1.1",
		"adduser 3.137ubuntu1",
		"adwaita-icon-theme 46.0-1",
		"alsa-base 1.0.25+dfsg-0ubuntu7",
		"amd64-microcode 3.20231019.1ubuntu2.1",
		"apg 2.2.3.dfsg.1-5build3",
		"g++ 4:13.2.0-7ubuntu1",
		"g++-13-x86-64-linux-gnu 13.3.0-6ubuntu2~24.04",
		"gir1.2-gmenu-3.0 3.36.0-1.1ubuntu3",
		"gir1.2-upowerglib-1.0 1.90.3-1",
		"heif-gdk-pixbuf 1.17.6-1ubuntu4.1",
		"libatomic1 14.2.0-4ubuntu2~24.04",
		"libatopology2t64 1.2.11-1build2",
		"libatspi2.0-0t64 2.52.0-1build1",
		"libattr1 1:2.5.2-1build1.1",
		"libaudit-common 1:3.1.2-2.1build1.1",
		"libcairo-gobject-perl 1.005-4build3",
		"libdbusmenu-glib4 18.10.20180917~bzr492+repack1-3.1ubuntu5", // TODO: Should we have 20180917 as a patch?
		"libjavascriptcoregtk-4.1-0 2.46.6-0ubuntu0.24.04.1",
		"libplymouth5 24.004.60-1ubuntu7.1", // TODO: Should we definitely remove leading zeros on the 004?
		"libplist-2.0-4 2.3.0-1~exp2build2",
		"make 4.3-4.1build2",
		"mongodb-mongosh 2.4.2",
		"nano 7.2-2ubuntu0.1",
		"nvidia-driver-550 550.144.03-0ubuntu1",
		"openjdk-21-jre 21.0.6+7-1~24.04.1",
		"openssh-server 1:9.6p1-3ubuntu13.8",
		"printer-driver-foo2zjs 20200505dfsg0-2ubuntu6",
	}

	// Get the packages
	packages, steps := getPackages(logger, strings.Join(packageStrings, "\n"))

	// Assertions
	assert.Equal(t, len(packages), len(packageStrings))

	// Check the correct packages are in the map
	for expectedPkg, expectedVersion := range map[string]string{
		"accountsservice":            "23.13.9",
		"acl":                        "2.3.2",
		"adduser":                    "3.137.0",
		"adwaita-icon-theme":         "46.0.0",
		"alsa-base":                  "1.0.25",
		"amd64-microcode":            "3.20231019.1",
		"apg":                        "2.2.3",
		"g++":                        "13.2.0",
		"g++-13-x86-64-linux-gnu":    "13.3.0",
		"gir1.2-gmenu-3.0":           "3.36.0",
		"gir1.2-upowerglib-1.0":      "1.90.3",
		"heif-gdk-pixbuf":            "1.17.6",
		"libatomic1":                 "14.2.0",
		"libatopology2t64":           "1.2.11",
		"libatspi2.0-0t64":           "2.52.0",
		"libattr1":                   "2.5.2",
		"libaudit-common":            "3.1.2",
		"libcairo-gobject-perl":      "1.5.0",
		"libdbusmenu-glib4":          "18.10.20180917",
		"libjavascriptcoregtk-4.1-0": "2.46.6",
		"libplist-2.0-4":             "2.3.0",
		"libplymouth5":               "24.4.60",
		"make":                       "4.3.0",
		"mongodb-mongosh":            "2.4.2",
		"nano":                       "7.2.0",
		"nvidia-driver-550":          "550.144.3",
		"openjdk-21-jre":             "21.0.6",
		"openssh-server":             "9.6.0",
		"printer-driver-foo2zjs":     "20200505.0.0",
	} {
		assert.Contains(t, packages, expectedPkg)
		version := packages[expectedPkg].(string)
		assert.Equal(t, version, expectedVersion)
	}

	assert.Len(t, steps, 1)
	assert.Contains(t, steps[0].GetRemarks(), "29 package")
}
