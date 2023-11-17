package audit

import (
	"fmt"

	"github.com/luraproject/lura/v2/config"
)

func ExampleAudit() {
	cfg, err := config.NewParser().Parse("./tests/example1.json")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	cfg.Normalize()

	exclude := []string{"1.1.1", "1.1.2"}
	levels := []string{SeverityCritical, SeverityHigh, SeverityMedium}

	result, err := Audit(&cfg, exclude, levels)
	if err != nil {
		fmt.Println(err)
		return
	}

	for i, r := range result.Recommendations {
		fmt.Printf("%02d: %s %s  \t%s\n", i, r.Rule, r.Severity, r.Message)
	}

	// output:
	// 00: 2.1.3 CRITICAL  	TLS is configured but its disable flag prevents from using it.
	// 01: 2.1.7 HIGH  	Enable HTTP security header checks (security/http).
	// 02: 2.1.8 HIGH  	Avoid clear text communication (h2c).
	// 03: 2.1.9 HIGH  	Avoid clear text communication (h2c) and use of deprecated option (prefer service level UseH2C)
	// 04: 2.2.1 MEDIUM  	Hide the version banner in runtime.
	// 05: 2.2.2 HIGH  	Enable CORS.
	// 06: 2.2.3 HIGH  	Avoid passing all input headers to the backend.
	// 07: 2.2.4 HIGH  	Avoid passing all input query strings to the backend.
	// 08: 3.1.2 HIGH  	Implement a rate-limiting strategy and avoid having an All-You-Can-Eat API.
	// 09: 3.1.3 HIGH  	Protect your backends with a circuit breaker.
	// 10: 3.3.2 MEDIUM  	Set timeouts to below 5 seconds for improved performance.
	// 11: 3.3.3 HIGH  	Set timeouts to below 30 seconds for improved performance.
	// 12: 3.3.4 CRITICAL  	Set timeouts to below 1 minute for improved performance.
	// 13: 4.1.1 MEDIUM  	Implement a telemetry system for collecting metrics for monitoring and troubleshooting.
	// 14: 4.2.1 MEDIUM  	Implement a telemetry system for tracing for monitoring and troubleshooting.
	// 15: 4.3.1 MEDIUM  	Use the improved logging component for better log parsing.

}
