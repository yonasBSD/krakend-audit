package audit

import (
	"fmt"

	"github.com/luraproject/lura/v2/config"
)

func ExampleParse() {
	cfg, err := config.NewParser().Parse("./tests/example1.json")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	cfg.Normalize()

	result := Parse(&cfg)
	fmt.Println("details:", result.Details)
	fmt.Println("agents:", result.Agents)
	fmt.Println("endpoints:", result.Endpoints)
	fmt.Println("components:", result.Components)

	// output:
	// details: [7220]
	// agents: []
	// endpoints: [{[2 0 0 140000 0 0] [{[64] map[github.com/devopsfaith/krakend-lua/proxy/backend:[2]]}] map[github.com/devopsfaith/krakend-jose/validator:[] github.com/devopsfaith/krakend-lua/proxy:[3] modifier/response-values:[5 2 0 1 1 1] validation/response-json-schema:[18 1 400 1]]} {[2 1 1 10000 7 0] [{[64] map[backend/http/client:[3]]}] map[github.com/devopsfaith/krakend/transport/http/client/executor:[1]]} {[2 0 0 2000 0 0] [{[64] map[]}] map[websocket:[27 4096 4096 4096 3200000 0 10000 60000 54000 300000 1]]} {[2 0 0 10000 8 2] [{[64] map[]} {[64] map[]} {[64] map[]}] map[github.com/devopsfaith/krakend/proxy:[1]]}]
	// components: map[auth/api-keys:[] github.com/devopsfaith/krakend-lua/router:[1] github_com/devopsfaith/krakend/transport/http/server/handler:[4] github_com/luraproject/lura/router/gin:[262144] grpc:[1] modifier/response-headers:[15] qos/ratelimit/service:[] telemetry/opentelemetry:[50 100 1 2 1]]

}
