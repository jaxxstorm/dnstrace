package output

import (
	"encoding/json"

	"github.com/jaxxstorm/dnstrace/internal/model"
)

func RenderJSON(result model.TraceResult) (string, error) {
	b, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}
