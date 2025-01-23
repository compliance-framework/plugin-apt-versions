package main

import (
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/compliance-framework/plugin-apt-versions/internal"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"testing"
)

type testVersionCollector struct {
	versions *map[string]interface{}
}

func (t testVersionCollector) GetInstalledPackages() (internal.PackageVersions, string, error) {
	if t.versions == nil {
		return map[string]interface{}{
			"wget": "1.20.3",
		}, "fake output", nil
	}
	return *t.versions, "fake output", nil
}

func TestAptVersion_PrepareForEval(t *testing.T) {
	t.Run("It stores package versions for subsequent evals", func(t *testing.T) {
		plugin := AptVersion{
			logger:           hclog.NewNullLogger(),
			versionCollector: &testVersionCollector{},
		}
		_, err := plugin.PrepareForEval(&proto.PrepareForEvalRequest{})
		assert.NoError(t, err)
		assert.Contains(t, plugin.data, "wget")
	})
}

func TestAptVersion_Eval(t *testing.T) {
	t.Run("On Violation, it returns an observation and an open finding", func(t *testing.T) {
		plugin := AptVersion{
			logger: hclog.NewNullLogger(),
			versionCollector: &testVersionCollector{
				versions: &map[string]interface{}{
					"wget": "1.19.2", // Version is lower than policy. Should fail.
				},
			},
		}
		_, err := plugin.PrepareForEval(&proto.PrepareForEvalRequest{})
		assert.NoError(t, err)

		resp, err := plugin.Eval(&proto.EvalRequest{
			BundlePath: "./testdata/",
		})
		assert.NoError(t, err)

		assert.Len(t, resp.Observations, 1)
		assert.Len(t, resp.Findings, 1)
		assert.Equal(t, proto.FindingStatus_OPEN.String(), resp.Findings[0].Status)
	})

	t.Run("On Violation, it returns an observation and a mitigated finding", func(t *testing.T) {
		plugin := AptVersion{
			logger: hclog.NewNullLogger(),
			versionCollector: &testVersionCollector{
				versions: &map[string]interface{}{
					"wget": "1.21.2", // Version is lower than policy. Should fail.
				},
			},
		}
		_, err := plugin.PrepareForEval(&proto.PrepareForEvalRequest{})
		assert.NoError(t, err)

		resp, err := plugin.Eval(&proto.EvalRequest{
			BundlePath: "./testdata/",
		})
		assert.NoError(t, err)

		assert.Len(t, resp.Observations, 1)
		assert.Len(t, resp.Findings, 1)
		assert.Equal(t, proto.FindingStatus_MITIGATED.String(), resp.Findings[0].Status)
	})
}
