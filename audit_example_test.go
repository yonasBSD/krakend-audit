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
	// 00: 2.1.3 CRITICAL  	Ensure your TLS is enabled.
	// 01: 2.1.7 HIGH  	Ensure you enable HTTP security header checks (security/http).
	// 02: 2.2.1 MEDIUM  	Ensure that the version banner is hidden in runtime.
	// 03: 2.2.2 HIGH  	Ensure that CORS is enabled.
	// 04: 3.1.1 MEDIUM  	Ensure that the Bot detector is enabled.
	// 05: 3.1.2 MEDIUM  	Ensure you enable some rate-limiting strategy and avoid having an All-You-Can-Eat API.
	// 06: 3.1.3 MEDIUM  	Ensure you protect your backends with a circuit breaker.
	// 07: 3.3.2 MEDIUM  	Ensure that your timeouts are below 5 seconds.
	// 08: 3.3.3 HIGH  	Ensure that your timeouts are below 30 seconds.
	// 09: 3.3.4 CRITICAL  	Ensure that your timeouts are below 60 seconds.
	// 10: 4.1.1 MEDIUM  	Ensure that you have some telemetry system for metrics.
	// 11: 4.2.1 MEDIUM  	Ensure that you have some telemetry system for tracing.
	// 12: 4.3.1 MEDIUM  	Ensure that you have the improved logging component, which improves log parsing.

}
