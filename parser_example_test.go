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
	// details: [52]
	// agents: []
	// endpoints: [{[2 0 0 140000 0] [{[64] map[]}] map[github.com/devopsfaith/krakend-jose/validator:[]]} {[2 1 1 10000 7] [{[64] map[]}] map[]}]
	// components: map[auth/api-keys:[] github_com/devopsfaith/krakend/transport/http/server/handler:[4]]
}
