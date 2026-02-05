package analyze

import "github.com/jaxxstorm/dnstrace/internal/model"

type OutcomeKind string

const (
	OutcomeSuccess          OutcomeKind = "SUCCESS"
	OutcomeNXDOMAIN         OutcomeKind = "NXDOMAIN"
	OutcomeNODATA           OutcomeKind = "NODATA"
	OutcomeBrokenDelegation OutcomeKind = "BROKEN_DELEGATION"
	OutcomeLameDelegation   OutcomeKind = "LAME_DELEGATION"
	OutcomeServfailTimeout  OutcomeKind = "SERVFAIL_TIMEOUT"
)

type Outcome struct {
	Kind         OutcomeKind
	Summary      string
	EvidenceStep int
	Hints        []string
}

func Diagnose(outcome Outcome) model.Diagnosis {
	steps := []int{}
	if outcome.EvidenceStep >= 0 {
		steps = append(steps, outcome.EvidenceStep)
	}
	return model.Diagnosis{
		Classification: string(outcome.Kind),
		Summary:        outcome.Summary,
		EvidenceSteps:  steps,
		Hints:          outcome.Hints,
	}
}
