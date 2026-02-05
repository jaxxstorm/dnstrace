package output

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/jaxxstorm/dnstrace/internal/model"
)

func RenderPretty(result model.TraceResult) string {
	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("205")).Render("dnstrace")
	stepStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("252"))
	successStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("42"))
	failureStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("196"))

	lines := []string{title, ""}
	for _, step := range result.TraceSteps {
		statusLabel := successStyle.Render("OK")
		if step.Error != "" {
			statusLabel = failureStyle.Render("FAIL")
		}
		serverDisplay := step.Server
		if step.ServerName != "" {
			serverDisplay = fmt.Sprintf("%s (%s)", step.Server, step.ServerName)
		}
		line := fmt.Sprintf("%s %02d %s %s %s -> %s", statusLabel, step.Index+1, serverDisplay, step.QueryName, step.QueryType, step.Rcode)
		if step.Error != "" {
			line = fmt.Sprintf("%s %02d %s %s %s -> error: %s", statusLabel, step.Index+1, serverDisplay, step.QueryName, step.QueryType, step.Error)
		}
		if step.Authoritative {
			line += " aa"
		}
		if step.RTT != "" {
			line += " rtt=" + step.RTT
		}
		if len(step.Answers) > 0 {
			normalized := make([]string, 0, len(step.Answers))
			for _, answer := range step.Answers {
				normalized = append(normalized, normalizeSpace(answer))
			}
			line += " answers=" + strings.Join(normalized, " | ")
		}
		if step.Note != "" {
			line += " note=" + step.Note
		}
		lines = append(lines, stepStyle.Render(line))
	}

	lines = append(lines, "")
	summary := fmt.Sprintf("%s %s", result.Diagnosis.Classification, result.Diagnosis.Summary)
	if result.Diagnosis.Classification == "SUCCESS" {
		lines = append(lines, successStyle.Render(summary))
	} else {
		lines = append(lines, failureStyle.Render(summary))
	}
	if len(result.Diagnosis.Hints) > 0 {
		lines = append(lines, "Hints:")
		for _, hint := range result.Diagnosis.Hints {
			lines = append(lines, "- "+hint)
		}
	}

	return strings.Join(lines, "\n")
}

func normalizeSpace(value string) string {
	return strings.Join(strings.Fields(value), " ")
}
