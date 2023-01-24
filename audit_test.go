package audit

import (
	"testing"

	"github.com/luraproject/lura/v2/config"
)

func TestAudit_all(t *testing.T) {
	tc := testCase{
		expectedRecommendations: []string{
			"1.1.1",
			"1.1.2",
			"2.1.3",
			"2.1.7",
			"2.2.1",
			"2.2.2",
			"3.1.1",
			"3.1.2",
			"3.1.3",
			"3.3.1",
			"3.3.2",
			"3.3.3",
			"3.3.4",
			"4.1.1",
			"4.2.1",
			"4.3.1",
			"5.1.1",
			"5.1.2",
			"5.2.2",
		},
		levels: []string{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow},
	}
	testAudit(t, tc)
}

func TestAudit_exclude(t *testing.T) {
	tc := testCase{
		expectedRecommendations: []string{
			"2.1.3",
			"2.1.7",
			"2.2.1",
			"2.2.2",
			"3.1.1",
			"3.1.2",
			"3.1.3",
			"3.3.1",
			"3.3.2",
			"3.3.3",
			"3.3.4",
			"4.1.1",
			"4.2.1",
			"4.3.1",
			"5.1.1",
			"5.1.2",
			"5.2.2",
		},
		exclude: []string{"1.1.1", "1.1.2"},
		levels:  []string{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow},
	}
	testAudit(t, tc)
}

func TestAudit_severity(t *testing.T) {
	tc := testCase{
		expectedRecommendations: []string{
			"2.1.3",
			"3.3.4",
		},
		levels: []string{SeverityCritical},
	}
	testAudit(t, tc)
}

type testCase struct {
	expectedRecommendations []string
	exclude                 []string
	levels                  []string
}

func testAudit(t *testing.T, tc testCase) {
	cfg, err := config.NewParser().Parse("./tests/example1.json")
	if err != nil {
		t.Error(err.Error())
	}
	cfg.Normalize()

	result, err := Audit(&cfg, tc.exclude, tc.levels)
	if err != nil {
		t.Error(err)
		return
	}

	if len(result.Recommendations) != len(tc.expectedRecommendations) {
		t.Errorf("wrong number of recommendations. have %d, expected %d", len(result.Recommendations), len(tc.expectedRecommendations))
	}
	for i, id := range tc.expectedRecommendations {
		if i >= len(result.Recommendations) {
			break
		}
		if result.Recommendations[i].Rule != id {
			t.Errorf("unexpected rule %d: %s", i, result.Recommendations[i].Rule)
		}
	}
}
