// Command readiness reports whether RTM's optional live integrations have the
// required environment configuration without printing any credential values.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/rarity/rtm/internal/config"
)

func main() {
	requiredFlag := flag.String("require", "", "comma-separated integrations that must be live: graph,sharepoint,threatlocker")
	flag.Parse()

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration is invalid:", err)
		os.Exit(1)
	}

	checks := cfg.IntegrationReadiness()
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(checks); err != nil {
		fmt.Fprintln(os.Stderr, "could not encode readiness output")
		os.Exit(1)
	}

	if missing := unsatisfiedRequirements(checks, *requiredFlag); len(missing) > 0 {
		fmt.Fprintln(os.Stderr, "required integrations are not live:", strings.Join(missing, ", "))
		os.Exit(2)
	}
}

func unsatisfiedRequirements(checks []config.IntegrationCheck, raw string) []string {
	modes := make(map[string]string, len(checks))
	for _, check := range checks {
		modes[check.Name] = check.Mode
	}

	var missing []string
	seen := map[string]struct{}{}
	for _, name := range strings.Split(raw, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		if modes[name] != "live" {
			missing = append(missing, name)
		}
	}
	return missing
}
