package ladder

import (
	"bufio"
	"os"
	"strings"
)

var DefaultPublicResolvers = []string{
	"1.1.1.1",
	"1.0.0.1",
	"8.8.8.8",
	"8.8.4.4",
	"9.9.9.9",
}

func LoadSystemResolvers() ([]string, error) {
	return loadResolvers("/etc/resolv.conf")
}

func DefaultResolverChain() ([]string, error) {
	systemResolvers, err := LoadSystemResolvers()
	if err != nil {
		return nil, err
	}
	return uniqueResolvers(append(systemResolvers, DefaultPublicResolvers...)), nil
}

func loadResolvers(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	resolvers := []string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if strings.ToLower(fields[0]) == "nameserver" {
			resolvers = append(resolvers, fields[1])
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return resolvers, nil
}

func uniqueResolvers(resolvers []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, resolver := range resolvers {
		resolver = strings.TrimSpace(resolver)
		if resolver == "" {
			continue
		}
		key := strings.ToLower(resolver)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, resolver)
	}
	return out
}
