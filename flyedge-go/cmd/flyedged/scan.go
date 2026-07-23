package main

// Passive endpoint discovery (Mode 1, agent-unaware): identify AI agents running on the host by
// inspecting established network connections and the owning process — no integration, no logs, no
// proxy. The signal is "a process holding a TCP connection to a known LLM provider (or the local
// gateway)". This catches Claude Code, Cursor, and hand-rolled/LangChain agents alike, since they
// all talk to a provider endpoint. macOS/Linux via `lsof`; robust provider identification (SNI)
// would need eBPF later, but provider IP ranges + live DNS resolution + the gateway endpoint cover
// the common cases without kernel hooks.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// scanLoop runs the endpoint scan continuously (Mode 1 as a live sensor, not a one-shot): every
// interval it discovers AI agents by their live connections and emits any newly-seen ones into the
// recorder. Dedup is via the activity MsgID (scan:<pid>:<provider>), so a long-lived agent is
// reported once, and a new process/connection is reported when it appears.
func scanLoop(rec *recorder, gatewayHostPorts []string, interval time.Duration) {
	for {
		for _, a := range scanEndpoints(gatewayHostPorts) {
			rec.emit(&activity{
				Time:   time.Now().Format("15:04:05"),
				MsgID:  fmt.Sprintf("scan:%d:%s", a.PID, a.Provider),
				Source: "endpoint",
				Model:  a.Tool,
				Method: "scan",
				Path:   a.Provider,
				PID:    a.PID,
				Remote: a.Remote,
				Status: 200,
			})
		}
		time.Sleep(interval)
	}
}

// providerHosts are resolved live at scan time so we match current provider IPs (handles rotation).
var providerHosts = map[string][]string{
	"anthropic": {"api.anthropic.com"},
	"openai":    {"api.openai.com"},
	"google":    {"generativelanguage.googleapis.com"},
	"xai":       {"api.x.ai"},
}

// staticProviderCIDRs backstop DNS with known announced ranges (Anthropic has its own /23).
var staticProviderCIDRs = map[string]string{
	"anthropic": "160.79.104.0/23",
}

// endpointAgent is one discovered agent process talking to a provider/gateway.
type endpointAgent struct {
	Tool     string `json:"tool"`
	PID      int    `json:"pid"`
	Command  string `json:"command"`
	Provider string `json:"provider"` // anthropic | openai | google | xai | gateway
	Remote   string `json:"remote"`
}

// toolFor maps a process command name to a coarse tool label.
func toolFor(cmd string) string {
	c := strings.ToLower(cmd)
	switch {
	case strings.Contains(c, "claude"):
		return "claude-code"
	case strings.Contains(c, "cursor") || strings.Contains(c, "code helper"):
		return "cursor"
	case strings.Contains(c, "ollama"):
		return "ollama"
	case strings.HasPrefix(c, "python"):
		return "python-agent"
	case c == "node":
		return "node-agent"
	case strings.Contains(c, "flyedged"):
		return "" // the daemon itself — don't self-report
	default:
		return cmd // hand-rolled binary name (e.g., reference-agent)
	}
}

// scanEndpoints returns the AI agents currently discoverable on the host by their live connections.
// gatewayHostPorts (e.g. "127.0.0.1:8080") are matched as the local flyedge/prism gateway.
func scanEndpoints(gatewayHostPorts []string) []endpointAgent {
	// Build the provider IP set from live DNS + static CIDRs.
	ipProvider := map[string]string{}
	for prov, hosts := range providerHosts {
		for _, h := range hosts {
			ips, err := net.LookupIP(h)
			if err != nil {
				continue
			}
			for _, ip := range ips {
				ipProvider[ip.String()] = prov
			}
		}
	}
	type cidrEntry struct {
		net  *net.IPNet
		prov string
	}
	var cidrs []cidrEntry
	for prov, c := range staticProviderCIDRs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			cidrs = append(cidrs, cidrEntry{n, prov})
		}
	}
	gw := map[string]bool{}
	for _, hp := range gatewayHostPorts {
		gw[hp] = true
	}

	out := exec.Command("lsof", "-nP", "-iTCP", "-sTCP:ESTABLISHED", "-Fcpn")
	stdout, err := out.Output()
	if err != nil {
		return nil
	}

	seen := map[string]bool{} // dedup by pid+provider
	var agents []endpointAgent
	var pid int
	var cmd string
	sc := bufio.NewScanner(strings.NewReader(string(stdout)))
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		switch line[0] {
		case 'p':
			pid, _ = strconv.Atoi(line[1:])
		case 'c':
			cmd = line[1:]
		case 'n':
			// name field: "local->remote" for established conns
			name := line[1:]
			arrow := strings.Index(name, "->")
			if arrow < 0 {
				continue
			}
			remote := name[arrow+2:]
			host, port := splitHostPort(remote)
			if host == "" {
				continue
			}
			prov := ipProvider[host]
			if prov == "" {
				if ip := net.ParseIP(host); ip != nil {
					for _, ce := range cidrs {
						if ce.net.Contains(ip) {
							prov = ce.prov
							break
						}
					}
				}
			}
			if prov == "" && gw[host+":"+port] {
				prov = "gateway"
			}
			if prov == "" {
				continue
			}
			key := strconv.Itoa(pid) + "|" + prov
			if seen[key] {
				continue
			}
			// lsof's command field is truncated/unreliable (e.g. a version string); ps gives the
			// real executable name, which drives the tool label.
			realCmd := commandForPID(pid)
			if realCmd == "" {
				realCmd = cmd
			}
			tool := toolFor(realCmd)
			if tool == "" {
				continue
			}
			seen[key] = true
			agents = append(agents, endpointAgent{Tool: tool, PID: pid, Command: realCmd, Provider: prov, Remote: remote})
		}
	}
	return agents
}

// providerCanonicalHost maps a matched provider to the hostname Hubble/Lens classifies on.
var providerCanonicalHost = map[string]string{
	"anthropic": "api.anthropic.com",
	"openai":    "api.openai.com",
	"google":    "generativelanguage.googleapis.com",
	"xai":       "api.x.ai",
	"gateway":   "gateway.local",
}

// runReport scans the host for AI agents and reports each to Hubble Telescope's /v1/events
// (endpoint-key auth). This is the daemon acting as an endpoint sensor: what it finds passively
// lands in the discovery plane (Lens), where it can be promoted to a governable agent.
func runReport(hubbleURL, apiKey string) error {
	if apiKey == "" {
		return fmt.Errorf("report: FLYEDGED_HUBBLE_KEY (endpoint key) required")
	}
	agents := scanEndpoints([]string{"127.0.0.1:8080"})
	if len(agents) == 0 {
		fmt.Println("no AI agents discovered on host — nothing to report")
		return nil
	}
	hostname, _ := os.Hostname()
	sent, failed := 0, 0
	for _, a := range agents {
		dest := providerCanonicalHost[a.Provider]
		if dest == "" {
			dest = a.Provider
		}
		body, _ := json.Marshal(map[string]any{
			"provider":    "flyedge-daemon",
			"source_ip":   "127.0.0.1",
			"destination": dest,
			"method":      "POST",
			"user_agent":  a.Tool,
			"host_name":   hostname,
			"payload":     map[string]any{"pid": a.PID, "command": a.Command, "remote": a.Remote, "tool": a.Tool},
		})
		req, _ := http.NewRequest(http.MethodPost, hubbleURL+"/v1/events", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", apiKey)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			failed++
			continue
		}
		ok := resp.StatusCode < 300
		resp.Body.Close()
		if !ok {
			failed++
			continue
		}
		sent++
		fmt.Printf("  \033[36m%-14s\033[0m → \033[33m%s\033[0m \033[2m(%s, pid %d)\033[0m\n", a.Tool, dest, a.Provider, a.PID)
	}
	fmt.Printf("\033[1mreported\033[0m %d/%d discoveries to Hubble (%s)\n", sent, sent+failed, hubbleURL)
	return nil
}

// commandForPID returns the real executable basename for a pid via ps (lsof's is unreliable).
func commandForPID(pid int) string {
	out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "comm=").Output()
	if err != nil {
		return ""
	}
	cmd := strings.TrimSpace(string(out))
	if i := strings.LastIndexByte(cmd, '/'); i >= 0 {
		cmd = cmd[i+1:] // basename
	}
	return cmd
}

// splitHostPort splits "host:port" where host may be IPv4/IPv6 (last colon is the port separator).
func splitHostPort(s string) (string, string) {
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return s, ""
	}
	return s[:i], s[i+1:]
}
