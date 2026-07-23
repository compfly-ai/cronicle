package main

// Hook interception surface (M1.5). Coding agents (Claude Code, Cursor, Cline, …) expose a
// client-side lifecycle hook that can allow/deny/ask and, on some events, rewrite tool input/output.
// This is a cooperative, structured interception surface — no CA, no stream rewriting — and it fires
// client-side regardless of where the model call is routed.
//
// The daemon exposes one canonical backend on its existing :8787 mux: POST /hooks/{agent}/{event}.
// Per-agent adapters normalize the request into a canonical hookEvent and denormalize a canonical
// hookDecision back into each agent's response dialect, so the decision core never learns an agent's
// schema. This first slice covers the pre-tool event for Claude Code + Cursor as an OBSERVE + control
// seam: the daemon normalizes and logs the event and returns allow. It makes NO local policy decision
// and does NO local content transformation — that would contradict flyedge's server-authoritative
// model (the SDK's Check* return allow/deny/kill, never a client-side verdict). A later slice routes
// decideHook through Guard.Check for real allow/deny/ask, and brings redaction in as a proper SDK
// control following the Python flyedge patterns — not a regex baked into the daemon. The value hooks
// add over the base-URL proxy is that this fires client-side regardless of where the model call is
// routed, and (once wired) can deny or rewrite structured fields rather than doing SSE token surgery.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	flyedge "github.com/compfly-ai/flyedge/flyedge-go"
)

// hookEvent is the agent-agnostic view of one hook firing.
type hookEvent struct {
	Agent     string
	Event     string // canonical: pre-tool | post-tool | prompt-submit | session-start | stop
	SessionID string
	CWD       string
	Tool      string
	Input     map[string]any // tool arguments (mutable)
	Output    string         // tool output (post-tool)
	Prompt    string         // prompt text (prompt-submit)
}

// hookDecision is the agent-agnostic verdict.
type hookDecision struct {
	Effect  string // allow | deny | ask
	Reason  string
	Message string
}

// serveHooks handles POST /hooks/{agent}/{event}: normalize → decide → denormalize. g is the
// server-authoritative check Guard, or nil (observe-only) when no agent identity is configured.
func serveHooks(w http.ResponseWriter, r *http.Request, g *flyedge.Guard) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/hooks/"), "/"), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		http.Error(w, "path must be /hooks/{agent}/{event}", http.StatusBadRequest)
		return
	}
	agent, event := parts[0], canonicalEvent(parts[1])
	body, _ := readAllLimited(r.Body, 1<<20)

	ev, err := normalizeHook(agent, event, body)
	if err != nil {
		// Fail open: on a shape we don't understand, allow (the proxy/other surfaces still observe).
		writeHookResponse(w, agent, hookDecision{Effect: "allow", Reason: "unparsed_hook_event"})
		return
	}
	dec := decideHook(g, ev)
	color := "\033[32m" // allow
	if dec.Effect == "deny" {
		color = "\033[31m"
	}
	fmt.Fprintf(os.Stderr, "\033[2mhook\033[0m %s/%s tool=%s → %s%s\033[0m \033[2m(%s)\033[0m\n",
		ev.Agent, ev.Event, ev.Tool, color, dec.Effect, dec.Reason)
	writeHookResponse(w, agent, dec)
}

// canonicalEvent maps an agent's event slug to a canonical event name.
func canonicalEvent(s string) string {
	switch strings.ToLower(s) {
	case "pre-tool-use", "pretooluse", "pre-tool", "before-shell-execution", "before-mcp-execution":
		return "pre-tool"
	case "post-tool-use", "posttooluse", "post-tool":
		return "post-tool"
	case "user-prompt-submit", "prompt-submit", "before-submit-prompt":
		return "prompt-submit"
	case "session-start":
		return "session-start"
	case "stop":
		return "stop"
	}
	return strings.ToLower(s)
}

// ---- normalize (agent dialect → canonical) ---------------------------------

func normalizeHook(agent, event string, body []byte) (hookEvent, error) {
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return hookEvent{}, err
	}
	ev := hookEvent{
		Agent:     agent,
		Event:     event,
		SessionID: firstStr(raw, "session_id", "sessionId"),
		CWD:       firstStr(raw, "cwd", "workspace_root", "workspaceRoot"),
		Tool:      firstStr(raw, "tool_name", "toolName", "tool"),
		Prompt:    firstStr(raw, "prompt", "user_prompt", "message"),
	}
	// Tool input lives under a handful of keys across agents; take the first object we find.
	for _, k := range []string{"tool_input", "toolInput", "input", "arguments"} {
		if m, ok := raw[k].(map[string]any); ok {
			ev.Input = m
			break
		}
	}
	ev.Output = firstStr(raw, "tool_output", "toolOutput", "output", "tool_response")
	return ev, nil
}

// ---- decide (the core; stubbed for the first slice) -------------------------

// decideHook is the decision core. It is server-authoritative: for a pre-tool event it runs the tool
// call through Guard.CheckToolCall and maps the platform's verdict to the hook dialect. A server deny
// or kill blocks the tool; allow/advisory-warn/fail-open proceed. With no Guard (no agent identity
// configured) or for non-tool events it stays observe-only (allow). It never does local detection or
// content transformation — that's the SDK's job, following the Python flyedge patterns.
func decideHook(g *flyedge.Guard, ev hookEvent) hookDecision {
	if g == nil || ev.Event != "pre-tool" || ev.Tool == "" {
		return hookDecision{Effect: "allow", Reason: "observed"}
	}
	// Bounded so a slow prism can't exceed the hook shim's 3s and stall the coding agent.
	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()

	// Attribute the call to this coding-agent session (headers only; never folded into the signed body).
	if ev.SessionID != "" {
		ctx = flyedge.ContextWithAgentIdentity(ctx, ev.SessionID, "urn:flyedge:"+ev.Agent)
	}

	dec, err := g.CheckToolCall(ctx, ev.SessionID, ev.Tool, ev.Input, destDomainOf(ev.Input))
	switch {
	case err != nil:
		if k, ok := flyedge.AsKillSwitchError(err); ok {
			return hookDecision{Effect: "deny", Reason: "kill_switch", Message: k.Error()}
		}
		if d, ok := flyedge.AsDenyError(err); ok {
			return hookDecision{Effect: "deny", Reason: orDefault(d.Decision.Reason, "policy_denied"), Message: d.Decision.Message}
		}
		// Unknown error shape — fail open (observe); never block the agent on our own bug.
		return hookDecision{Effect: "allow", Reason: "check_error", Message: err.Error()}
	default:
		// allow, advisory warn (warn/audit modes), or fail_open all proceed.
		return hookDecision{Effect: "allow", Reason: orDefault(dec.Reason, "allowed")}
	}
}

// destDomainOf best-effort extracts an egress target (host) from common tool-arg keys, so
// destination-scoped policies (e.g. "no external egress") can evaluate. Empty when none is present.
func destDomainOf(input map[string]any) string {
	for _, k := range []string{"url", "uri", "endpoint", "host"} {
		if s, ok := input[k].(string); ok && s != "" {
			if u, err := url.Parse(s); err == nil && u.Host != "" {
				return u.Host
			}
			return s
		}
	}
	return ""
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// ---- denormalize (canonical → agent dialect) --------------------------------

func writeHookResponse(w http.ResponseWriter, agent string, dec hookDecision) {
	w.Header().Set("Content-Type", "application/json")
	var out map[string]any
	switch agent {
	case "cursor":
		out = map[string]any{"permission": dec.Effect}
		if dec.Message != "" {
			out["user_message"] = dec.Message
		}
	default: // claude-code (and unknown agents get Claude Code's shape)
		hs := map[string]any{"hookEventName": "PreToolUse", "permissionDecision": dec.Effect}
		if dec.Reason != "" {
			hs["permissionDecisionReason"] = dec.Reason
		}
		out = map[string]any{"hookSpecificOutput": hs}
	}
	_ = json.NewEncoder(w).Encode(out)
}

// ---- helpers ----------------------------------------------------------------

func firstStr(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

func readAllLimited(r interface{ Read([]byte) (int, error) }, n int64) ([]byte, error) {
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	var total int64
	for {
		k, err := r.Read(tmp)
		if k > 0 {
			total += int64(k)
			if total > n {
				buf = append(buf, tmp[:k-int(total-n)]...)
				break
			}
			buf = append(buf, tmp[:k]...)
		}
		if err != nil {
			break
		}
	}
	return buf, nil
}
