package agent

import (
	"log/slog"
	"net/http"

	"github.com/anthropics/anthropic-sdk-go/option"
	flyedge "github.com/compfly-ai/flyedge/flyedge-go"
)

// flyedgeOption wires CompFly (flyedge) governance and observability into an
// agent's Anthropic client. Monitoring is OPT-IN and OFF by default: it activates
// only when an agent identity is configured in the environment (COMPFLY_AGENT_DID
// plus a private key). When unconfigured it returns (nil, noop, nil) and the agent
// runs exactly as before — no request goes anywhere near the CompFly plane.
//
// When active, the returned request option installs an http.Client whose transport
// is wrapped by the flyedge Guard. Every LLM call the agent makes is then signed
// (Ed25519 DID) and checked against the CompFly policy plane (prism /
// policy-enforcer) before it leaves the host: a pre_llm Check runs on each request,
// and a policy denial or operator kill switch surfaces as a request error so the
// model is never called. FailMode governs behavior when the plane is unreachable
// (fail-open by default — availability over strictness).
//
// Environment (see flyedge.LoadEnv):
//
//	COMPFLY_AGENT_DID               did:compfly:<tenant>:<agent> — presence enables monitoring
//	COMPFLY_AGENT_PRIVATE_KEY_PATH  PKCS#8 Ed25519 key file (or COMPFLY_AGENT_PRIVATE_KEY inline)
//	COMPFLY_API_URL                 gateway base URL (defaults to the prism endpoint)
//	FLYEDGE_MODE                    enforce|warn|audit|off — local detectors (default warn)
//	FLYEDGE_FAIL_MODE               fail_open|fail_closed (default fail_open)
//
// The returned cleanup func flushes telemetry and closes the Guard; callers should
// defer it. It is always safe to call, even when monitoring is disabled.
func flyedgeOption() (opt option.RequestOption, cleanup func(), err error) {
	noop := func() {}

	cfg := flyedge.LoadEnv()
	if cfg.DID == "" {
		return nil, noop, nil // not configured — monitoring disabled
	}

	guard, err := flyedge.New(cfg)
	if err != nil {
		return nil, noop, err
	}

	client := &http.Client{Transport: guard.WrapRoundTripper(http.DefaultTransport)}
	slog.Info("compfly monitoring enabled",
		"agent_did", cfg.DID,
		"api_url", cfg.APIURL,
		"mode", string(cfg.Mode),
		"fail_mode", string(cfg.FailMode),
	)
	return option.WithHTTPClient(client), func() { _ = guard.Close() }, nil
}
