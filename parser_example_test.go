package audit

import (
	"encoding/json"
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
	r, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(r))

	// output:
	// {
	//   "d": [
	//     7220
	//   ],
	//   "a": null,
	//   "e": [
	//     {
	//       "d": [
	//         2,
	//         0,
	//         0,
	//         140000,
	//         0,
	//         0
	//       ],
	//       "b": [
	//         {
	//           "d": [
	//             64
	//           ],
	//           "c": {
	//             "github.com/devopsfaith/krakend-httpcache": [
	//               0
	//             ],
	//             "github.com/devopsfaith/krakend-lua/proxy/backend": [
	//               2
	//             ]
	//           }
	//         }
	//       ],
	//       "c": {
	//         "github.com/devopsfaith/krakend-jose/validator": [],
	//         "github.com/devopsfaith/krakend-lua/proxy": [
	//           3
	//         ],
	//         "modifier/response-body": [
	//           5,
	//           2,
	//           0,
	//           1,
	//           1,
	//           1
	//         ],
	//         "validation/response-json-schema": [
	//           18,
	//           1,
	//           400,
	//           1
	//         ]
	//       }
	//     },
	//     {
	//       "d": [
	//         2,
	//         1,
	//         1,
	//         10000,
	//         7,
	//         0
	//       ],
	//       "b": [
	//         {
	//           "d": [
	//             64
	//           ],
	//           "c": {
	//             "backend/http/client": [
	//               3
	//             ]
	//           }
	//         }
	//       ],
	//       "c": {
	//         "github.com/devopsfaith/krakend/transport/http/client/executor": [
	//           1
	//         ]
	//       }
	//     },
	//     {
	//       "d": [
	//         2,
	//         0,
	//         0,
	//         2000,
	//         0,
	//         0
	//       ],
	//       "b": [
	//         {
	//           "d": [
	//             64
	//           ],
	//           "c": {}
	//         }
	//       ],
	//       "c": {
	//         "websocket": [
	//           27,
	//           4096,
	//           4096,
	//           4096,
	//           3200000,
	//           0,
	//           10000,
	//           60000,
	//           54000,
	//           300000,
	//           1
	//         ]
	//       }
	//     },
	//     {
	//       "d": [
	//         2,
	//         0,
	//         0,
	//         2000,
	//         0,
	//         0
	//       ],
	//       "b": [
	//         {
	//           "d": [
	//             64
	//           ],
	//           "c": {
	//             "github.com/devopsfaith/krakend-httpcache": [
	//               7
	//             ]
	//           }
	//         }
	//       ],
	//       "c": {}
	//     },
	//     {
	//       "d": [
	//         2,
	//         0,
	//         0,
	//         2000,
	//         0,
	//         1
	//       ],
	//       "b": [
	//         {
	//           "d": [
	//             64
	//           ],
	//           "c": {
	//             "ai/llm": [
	//               1,
	//               0,
	//               0,
	//               1
	//             ]
	//           }
	//         }
	//       ],
	//       "c": {}
	//     },
	//     {
	//       "d": [
	//         2,
	//         0,
	//         0,
	//         2000,
	//         0,
	//         1
	//       ],
	//       "b": [
	//         {
	//           "d": [
	//             64
	//           ],
	//           "c": {
	//             "ai/llm": [
	//               2,
	//               1,
	//               0,
	//               1
	//             ]
	//           }
	//         }
	//       ],
	//       "c": {}
	//     },
	//     {
	//       "d": [
	//         2,
	//         0,
	//         0,
	//         2000,
	//         0,
	//         1
	//       ],
	//       "b": [
	//         {
	//           "d": [
	//             64
	//           ],
	//           "c": {
	//             "ai/llm": [
	//               4,
	//               0,
	//               1,
	//               1
	//             ]
	//           }
	//         }
	//       ],
	//       "c": {}
	//     },
	//     {
	//       "d": [
	//         2,
	//         0,
	//         0,
	//         2000,
	//         0,
	//         1
	//       ],
	//       "b": [
	//         {
	//           "d": [
	//             64
	//           ],
	//           "c": {
	//             "ai/llm": [
	//               8,
	//               1,
	//               1,
	//               1
	//             ]
	//           }
	//         }
	//       ],
	//       "c": {}
	//     },
	//     {
	//       "d": [
	//         2,
	//         0,
	//         0,
	//         2000,
	//         0,
	//         1
	//       ],
	//       "b": [
	//         {
	//           "d": [
	//             64
	//           ],
	//           "c": {}
	//         }
	//       ],
	//       "c": {
	//         "ai/mcp": []
	//       }
	//     },
	//     {
	//       "d": [
	//         2,
	//         0,
	//         0,
	//         2000,
	//         0,
	//         0
	//       ],
	//       "b": [
	//         {
	//           "d": [
	//             64
	//           ],
	//           "c": {}
	//         }
	//       ],
	//       "c": {
	//         "ai/mcp": []
	//       }
	//     },
	//     {
	//       "d": [
	//         2,
	//         0,
	//         0,
	//         2000,
	//         0,
	//         1
	//       ],
	//       "b": [
	//         {
	//           "d": [
	//             64
	//           ],
	//           "c": {}
	//         }
	//       ],
	//       "c": {
	//         "ai/mcp": []
	//       }
	//     },
	//     {
	//       "d": [
	//         2,
	//         0,
	//         0,
	//         2000,
	//         0,
	//         1
	//       ],
	//       "b": [
	//         {
	//           "d": [
	//             64
	//           ],
	//           "c": {}
	//         }
	//       ],
	//       "c": {
	//         "ai/mcp": []
	//       }
	//     },
	//     {
	//       "d": [
	//         2,
	//         0,
	//         0,
	//         10000,
	//         8,
	//         2
	//       ],
	//       "b": [
	//         {
	//           "d": [
	//             64
	//           ],
	//           "c": {}
	//         },
	//         {
	//           "d": [
	//             64
	//           ],
	//           "c": {}
	//         },
	//         {
	//           "d": [
	//             64
	//           ],
	//           "c": {}
	//         }
	//       ],
	//       "c": {
	//         "github.com/devopsfaith/krakend/proxy": [
	//           1
	//         ]
	//       }
	//     }
	//   ],
	//   "c": {
	//     "ai/mcp": [
	//       2,
	//       3
	//     ],
	//     "auth/api-keys": [],
	//     "github.com/devopsfaith/krakend-lua/router": [
	//       1
	//     ],
	//     "github_com/devopsfaith/krakend/transport/http/server/handler": [
	//       4
	//     ],
	//     "github_com/luraproject/lura/router/gin": [
	//       262144
	//     ],
	//     "grpc": [
	//       1
	//     ],
	//     "modifier/response-headers": [
	//       15
	//     ],
	//     "qos/ratelimit/service": [],
	//     "telemetry/opentelemetry": [
	//       50,
	//       100,
	//       1,
	//       2,
	//       1
	//     ]
	//   }
	// }
}
