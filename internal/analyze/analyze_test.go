package analyze

import "testing"

func TestDiagnoseEvidenceSteps(t *testing.T) {
	d := Diagnose(Outcome{Kind: OutcomeNXDOMAIN, Summary: "nxdomain", EvidenceStep: 2})
	if d.Classification != "NXDOMAIN" {
		t.Fatalf("expected NXDOMAIN, got %s", d.Classification)
	}
	if len(d.EvidenceSteps) != 1 || d.EvidenceSteps[0] != 2 {
		t.Fatalf("expected evidence step 2")
	}
}

func TestDiagnoseNoEvidence(t *testing.T) {
	d := Diagnose(Outcome{Kind: OutcomeServfailTimeout, Summary: "timeout", EvidenceStep: -1})
	if len(d.EvidenceSteps) != 0 {
		t.Fatalf("expected no evidence steps")
	}
}
