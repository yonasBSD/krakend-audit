package audit

import (
	"fmt"
	"math/rand"
	"reflect"
	"testing"

	bf "github.com/krakendio/bloomfilter/v2/krakend"
	botdetector "github.com/krakendio/krakend-botdetector/v2/krakend"
	opencensus "github.com/krakendio/krakend-opencensus/v2"
	juju "github.com/krakendio/krakend-ratelimit/v2/juju/router"
	"github.com/luraproject/lura/v2/config"
	"github.com/luraproject/lura/v2/proxy"
	"github.com/luraproject/lura/v2/proxy/plugin"
	router "github.com/luraproject/lura/v2/router/gin"
	client "github.com/luraproject/lura/v2/transport/http/client/plugin"
	server "github.com/luraproject/lura/v2/transport/http/server/plugin"
)

func TestMarshal(t *testing.T) {
	rand.Seed(1)
	result := Parse(generateCfg())

	b, err := Marshal(&result)
	if err != nil {
		t.Error(err)
	}
	fmt.Println("Compressed (best):", len(b))

	var out Service
	if err := Unmarshal(b, &out); err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(result, out) {
		t.Error("sent and received are different")
	}
}

func generateCfg() *config.ServiceConfig {
	cfg := &config.ServiceConfig{
		SequentialStart: true,
		Endpoints:       []*config.EndpointConfig{},
		ExtraConfig: config.ExtraConfig{
			server.Namespace:      map[string]interface{}{},
			router.Namespace:      map[string]interface{}{},
			bf.Namespace:          map[string]interface{}{},
			botdetector.Namespace: map[string]interface{}{},
			opencensus.Namespace:  map[string]interface{}{},
			juju.Namespace:        map[string]interface{}{},
		},
		AsyncAgents: []*config.AsyncAgent{
			{
				Name:       "first",
				Encoding:   "json",
				Consumer:   config.Consumer{},
				Connection: config.Connection{},
				ExtraConfig: config.ExtraConfig{
					"component3":   true,
					juju.Namespace: map[string]interface{}{},
				},
				Backend: []*config.Backend{
					{
						URLPattern: "/foo",
						Group:      "bar",
						AllowList:  []string{"foo", "bar"},
						Mapping:    map[string]string{"foo": "foobar"},
						Encoding:   "json",
						ExtraConfig: config.ExtraConfig{
							"component4":   true,
							"component5":   true,
							juju.Namespace: map[string]interface{}{},
						},
					},
				},
			},
		},
		Plugin: &config.Plugin{
			Folder: ".",
		},
		TLS: &config.TLS{
			PublicKey:  "./cert.pub",
			PrivateKey: "./cert.key",
		},
	}

	for i := 0; i < 1000; i++ {
		var endpoints []*config.EndpointConfig

		for k := 0; k < 1+rand.Intn(3); k++ {
			e := &config.EndpointConfig{
				Endpoint:       fmt.Sprintf("/foo/%3d", rand.Intn(100)),
				OutputEncoding: "json",
				Backend:        []*config.Backend{},
				ExtraConfig: config.ExtraConfig{
					fmt.Sprintf("component%3d", rand.Intn(100)): true,
					fmt.Sprintf("component%3d", rand.Intn(100)): true,
					plugin.Namespace: map[string]interface{}{},
					proxy.Namespace:  map[string]interface{}{},
				},
			}
			for j := 0; j < 1+rand.Intn(5); j++ {
				e.Backend = append(e.Backend, &config.Backend{
					URLPattern: fmt.Sprintf("/foo/%3d", rand.Intn(100)),
					Group:      fmt.Sprintf("group-%3d", j),
					AllowList:  []string{"foo", "bar"},
					Mapping:    map[string]string{"foo": "foobar"},
					Encoding:   "json",
					ExtraConfig: config.ExtraConfig{
						fmt.Sprintf("component%3d", rand.Intn(100)): true,
						fmt.Sprintf("component%3d", rand.Intn(100)): true,
						client.Namespace: map[string]interface{}{},
					},
				})
			}
			endpoints = append(endpoints, e)
		}
		for k := 0; k < 1+rand.Intn(3); k++ {
			e := &config.EndpointConfig{
				Endpoint:       fmt.Sprintf("/foo/%3d", rand.Intn(100)),
				OutputEncoding: "no-op",
				Backend: []*config.Backend{
					{
						URLPattern: fmt.Sprintf("/foo/%3d", rand.Intn(100)),
						Group:      "first",
						AllowList:  []string{"foo", "bar"},
						Mapping:    map[string]string{"foo": "foobar"},
						Encoding:   "no-op",
						ExtraConfig: config.ExtraConfig{
							fmt.Sprintf("component%3d", rand.Intn(100)): true,
							client.Namespace: map[string]interface{}{},
						},
					},
				},
				ExtraConfig: config.ExtraConfig{
					fmt.Sprintf("component%3d", rand.Intn(100)): true,
					fmt.Sprintf("component%3d", rand.Intn(100)): true,
					plugin.Namespace: map[string]interface{}{},
					proxy.Namespace:  map[string]interface{}{},
				},
			}
			endpoints = append(endpoints, e)
		}

		cfg.Endpoints = append(cfg.Endpoints, endpoints...)
	}

	return cfg
}
