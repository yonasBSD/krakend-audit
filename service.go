package audit

// Service represents a KrakenD configuration as a tree of bitsets representing
// which components and flags are enabled at the KrakenD configuration
type Service struct {
	Details    []int      `json:"d"`
	Agents     []Agent    `json:"a"`
	Endpoints  []Endpoint `json:"e"`
	Components Component  `json:"c"`
}

// Clone returns a deep copy of the service
func (s Service) Clone() Service {
	res := Service{
		Details:    make([]int, len(s.Details)),
		Agents:     make([]Agent, len(s.Agents)),
		Endpoints:  make([]Endpoint, len(s.Endpoints)),
		Components: s.Components.Clone(),
	}
	for i, v := range s.Details {
		res.Details[i] = v
	}
	for i, a := range s.Agents {
		res.Agents[i] = a.Clone()
	}
	for i, e := range s.Endpoints {
		res.Endpoints[i] = e.Clone()
	}
	return res
}

// Agent captures details of the AsyncAgents present at the configuration
type Agent struct {
	Details    []int     `json:"d"`
	Backends   []Backend `json:"b"`
	Components Component `json:"c"`
}

// Clone returns a deep copy of the agent
func (a Agent) Clone() Agent {
	res := Agent{
		Details:    make([]int, len(a.Details)),
		Backends:   make([]Backend, len(a.Backends)),
		Components: a.Components.Clone(),
	}
	for i, v := range a.Details {
		res.Details[i] = v
	}
	for i, b := range a.Backends {
		res.Backends[i] = b.Clone()
	}
	return res
}

// Endpoint captures details of the endpoints present at the configuration
type Endpoint struct {
	Details    []int     `json:"d"`
	Backends   []Backend `json:"b"`
	Components Component `json:"c"`
}

// Clone returns a deep copy of the endpoint
func (e Endpoint) Clone() Endpoint {
	res := Endpoint{
		Details:    make([]int, len(e.Details)),
		Backends:   make([]Backend, len(e.Backends)),
		Components: e.Components.Clone(),
	}
	for i, v := range e.Details {
		res.Details[i] = v
	}
	for i, b := range e.Backends {
		res.Backends[i] = b.Clone()
	}
	return res
}

// Backend captures details of the backends present at the configuration
type Backend struct {
	Details    []int     `json:"d"`
	Components Component `json:"c"`
}

// Clone returns a deep copy of the backend
func (b Backend) Clone() Backend {
	res := Backend{
		Details:    make([]int, len(b.Details)),
		Components: b.Components.Clone(),
	}
	for i, v := range b.Details {
		res.Details[i] = v
	}
	return res
}

// Component captures details of the extra configuration sections
type Component map[string][]int

// Clone returns a deep copy of the set of components
func (c Component) Clone() Component {
	res := Component{}
	for i, vs := range c {
		res[i] = make([]int, len(vs))
		for j, v := range vs {
			res[i][j] = v
		}
	}
	return res
}

const (
	ServicePlugin = iota
	ServiceSequentialStart
	ServiceDebug
	ServiceAllowInsecureConnections
	ServiceDisableStrictREST
	ServiceHasTLS
	ServiceTLSEnabled
	ServiceTLSEnableMTLS
	ServiceTLSDisableSystemCaPool
	ServiceTLSCaCerts
)

const (
	EncodingNOOP = iota
	EncodingJSON
	EncodingSAFEJSON
	EncodingSTRING
	EncodingRSS
	EncodingXML
	EncodingOther
)

const (
	BackendAllow = iota + EncodingOther + 1
	BackendDeny
	BackendMapping
	BackendGroup
	BackendTarget
	BackendIsCollection
)

const (
	RouterErrorBody = iota
	RouterDisableHealth
	RouterDisableAccessLog
	RouterHealthPath
	RouterErrorMsg
	RouterDisableRedirectTrailingSlash
	RouterDisableRedirectFixedPath
	RouterExtraSlash
	RouterHandleMethodNotAllowed
	RouterPathDecoding
	RouterAutoOptions
	RouterForwardedByClientIp
	RouterRemoteIpHeaders
	RouterTrustedProxies
	RouterAppEngine
	RouterMaxMultipartMemory
	RouterLoggerSkipPaths
	RouterHideVersionHeader
)
