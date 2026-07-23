// Command flyedged is the M0 flyedge daemon: an observe-only local proxy that Claude Code (or any
// Anthropic-API client) points at via ANTHROPIC_BASE_URL. It forwards every request to Anthropic
// verbatim — auth headers passed through untouched, nothing signed, nothing blocked — while parsing
// each request/response into a live "flight recorder": model, message/tool counts, token usage,
// tool calls the model made, latency, and an estimated cost.
//
// This is the zero-integration observability wedge from the daemon plan: no code change to the tool,
// no CA/TLS-MITM (the client speaks plain HTTP to localhost; the daemon re-originates HTTPS), and no
// platform dependency — it's a local-first flight recorder. Guardrails, identity, and the control
// plane come in later milestones.
//
// Usage:
//
//	flyedged                       # listen on 127.0.0.1:8787, forward to api.anthropic.com
//	ANTHROPIC_BASE_URL=http://127.0.0.1:8787 claude   # point Claude Code at it
//
// Env:
//
//	FLYEDGED_LISTEN    listen address (default 127.0.0.1:8787)
//	FLYEDGED_UPSTREAM  upstream base (default https://api.anthropic.com)
//	FLYEDGED_LOG       JSONL activity log path (default ~/.flyedge/activity.jsonl)
//	FLYEDGED_VERBOSE   =1 to include truncated prompt/response previews in the live view + log
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	flyedge "github.com/compfly-ai/flyedge/flyedge-go"
)

func main() {
	// Subcommands run before flag parsing (they take positional args, not flags):
	//   flyedged hook <agent> <event>   — hook shim: stdin event → daemon → stdout decision
	//   flyedged install-hooks          — wire coding agents' hooks to this daemon
	//   flyedged uninstall-hooks        — remove them
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "hook":
			runHookShim(os.Args[2:])
			return
		case "install-hooks":
			installHooks()
			return
		case "uninstall-hooks":
			uninstallHooks()
			return
		}
	}

	replay := flag.String("replay", "", "one-shot: parse an existing transcript file/dir into the flight recorder, print, and exit")
	claudeDir := flag.String("claude-dir", filepath.Join(home(), ".claude", "projects"), "Claude Code projects dir to tail/replay")
	enrollFlag := flag.Bool("enroll", false, "enroll this daemon as a sensor with the platform, then exit")
	whoamiFlag := flag.Bool("whoami", false, "make a signed call to verify sensor auth, then exit")
	connectFlag := flag.Bool("connect", false, "push observed inventory to the platform (auto-provisions discovered agents), then exit")
	scanFlag := flag.Bool("scan", false, "passively discover AI agents on the host by their live connections, then exit")
	reportFlag := flag.Bool("report", false, "scan the host and report discovered AI agents to Hubble, then exit")
	hubbleURL := flag.String("hubble", envOr("FLYEDGED_HUBBLE_URL", "http://127.0.0.1:8091"), "Hubble Telescope base URL")
	platform := flag.String("platform", envOr("FLYEDGED_PLATFORM", "http://127.0.0.1:8887"), "platform-backend base URL")
	orgFlag := flag.String("org", os.Getenv("FLYEDGED_ORG"), "org id for enrollment")
	userFlag := flag.String("user", os.Getenv("FLYEDGED_USER"), "user id (principal) for enrollment")
	flag.Parse()

	// Sensor auth one-shots (build/verify the platform identity), then exit.
	if *enrollFlag {
		if err := runEnroll(*platform, *orgFlag, *userFlag, os.Getenv("FLYEDGED_API_KEY")); err != nil {
			fmt.Fprintln(os.Stderr, "flyedged:", err)
			os.Exit(1)
		}
		return
	}
	if *whoamiFlag {
		if err := runWhoami(*platform); err != nil {
			fmt.Fprintln(os.Stderr, "flyedged:", err)
			os.Exit(1)
		}
		return
	}
	if *connectFlag {
		if err := runConnect(*platform, *claudeDir); err != nil {
			fmt.Fprintln(os.Stderr, "flyedged:", err)
			os.Exit(1)
		}
		return
	}
	if *scanFlag {
		agents := scanEndpoints([]string{"127.0.0.1:8080"})
		fmt.Printf("\033[1mpassive endpoint scan\033[0m — %d AI agent(s) discovered by live connections:\n", len(agents))
		for _, a := range agents {
			fmt.Printf("  \033[36m%-14s\033[0m pid=%-7d \033[2m%s\033[0m → \033[33m%s\033[0m \033[2m(%s)\033[0m\n",
				a.Tool, a.PID, a.Command, a.Provider, a.Remote)
		}
		return
	}
	if *reportFlag {
		if err := runReport(*hubbleURL, os.Getenv("FLYEDGED_HUBBLE_KEY")); err != nil {
			fmt.Fprintln(os.Stderr, "flyedged:", err)
			os.Exit(1)
		}
		return
	}

	listen := envOr("FLYEDGED_LISTEN", "127.0.0.1:8787")
	upstreamRaw := envOr("FLYEDGED_UPSTREAM", "https://api.anthropic.com")
	verbose := os.Getenv("FLYEDGED_VERBOSE") == "1"
	logPath := envOr("FLYEDGED_LOG", filepath.Join(home(), ".flyedge", "activity.jsonl"))

	rec := &recorder{verbose: verbose, logPath: logPath}
	rec.openLog()

	// --replay: passive parse of existing transcripts (demo / backfill), then exit.
	if *replay != "" {
		rec.quiet = true
		n := replayPath(*replay, rec)
		fmt.Printf("\033[1mflyedged --replay\033[0m — passive parse of %s → %d assistant events\n\n", *replay, n)
		rec.printTail(15)
		rec.printSummary()
		return
	}

	upstream, err := url.Parse(upstreamRaw)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bad FLYEDGED_UPSTREAM:", err)
		os.Exit(1)
	}

	proxy := &httputil.ReverseProxy{
		Director: func(r *http.Request) {
			r.URL.Scheme = upstream.Scheme
			r.URL.Host = upstream.Host
			r.Host = upstream.Host // send the right Host upstream, not localhost
		},
		ModifyResponse: rec.observeResponse,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, e error) {
			// Never break the client on an observation/transport hiccup — fail open.
			http.Error(w, "flyedged upstream error: "+e.Error(), http.StatusBadGateway)
		},
	}

	// Hook enforcement Guard: if an agent identity is configured (COMPFLY_AGENT_DID + key +
	// COMPFLY_API_URL prism), build a server-authoritative check Guard so pre-tool hooks are decided
	// by real platform policy. Absent that, hooks stay observe-only (nil Guard → allow + record).
	hookGuard := buildHookGuard()

	mux := http.NewServeMux()
	// Local flight-recorder surface — carved out so it isn't proxied upstream.
	mux.HandleFunc("/_flyedge/events", rec.serveEvents)
	mux.HandleFunc("/_flyedge", rec.serveDashboard)
	// Hook interception surface (M1.5): coding agents POST lifecycle events here for allow/deny.
	// Carved out of the "/" proxy like the other _flyedge routes.
	mux.HandleFunc("/hooks/", func(w http.ResponseWriter, r *http.Request) { serveHooks(w, r, hookGuard) })
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		r = rec.observeRequest(r) // parse request facts onto the context, restore body for forwarding
		proxy.ServeHTTP(w, r)
	})

	banner(listen, upstream.String(), logPath, *claudeDir, verbose)
	if h, _, e := net.SplitHostPort(listen); e == nil && !isLoopback(h) {
		fmt.Printf("\033[33mwarning:\033[0m listening on non-loopback %q — the dashboard exposes captured\n"+
			"         activity (and prompt previews in verbose) and the proxy is reachable off-host.\n"+
			"         Bind 127.0.0.1 unless you intend this.\n\n", h)
	}
	go tailProjects(*claudeDir, rec) // passive sensor (Claude Code transcripts) — always on
	scanEvery := 500 * time.Millisecond
	if v := os.Getenv("FLYEDGED_SCAN_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			scanEvery = d
		}
	}
	go scanLoop(rec, []string{"127.0.0.1:8080"}, scanEvery) // endpoint discovery — always on, continuous
	if err := http.ListenAndServe(listen, mux); err != nil {
		fmt.Fprintln(os.Stderr, "flyedged:", err)
		os.Exit(1)
	}
}

// buildHookGuard returns a server-authoritative check Guard for the hook path, or nil (observe-only)
// when no agent identity is configured. It reads the standard COMPFLY_*/FLYEDGE_* env (same as any
// flyedge agent) and enables enforcement only when a signing identity (DID + key) is present, since
// prism resolves the governed agent from the signed request. Timeout is tightened to stay under the
// hook shim's 3s so a slow gateway can't stall the coding agent.
func buildHookGuard() *flyedge.Guard {
	cfg := flyedge.LoadEnv()
	if cfg.DID == "" || (len(cfg.KeyPEM) == 0 && cfg.KeyPEMPath == "") {
		fmt.Printf("  \033[2mhooks:    observe-only (set COMPFLY_AGENT_DID + COMPFLY_AGENT_PRIVATE_KEY[_PATH] + COMPFLY_API_URL to enforce)\033[0m\n")
		return nil
	}
	cfg.Timeout = 2 * time.Second
	g, err := flyedge.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  \033[33mhooks:    enforcement disabled (guard: %v)\033[0m\n", err)
		return nil
	}
	mode := cfg.Mode
	if mode == "" {
		mode = flyedge.ModeWarn
	}
	api := cfg.APIURL
	if api == "" {
		api = flyedge.DefaultAPIURL
	}
	fmt.Printf("  \033[32mhooks:    server-authoritative pre-tool checks \033[1mON\033[0m\033[32m → %s (mode=%s)\033[0m\n", api, mode)
	return g
}

// ---- passive sensor: tail Claude Code transcripts --------------------------

// parseTranscriptLine turns one Claude Code transcript JSONL line into an activity, or nil if the
// line isn't an assistant turn. Rich content (model, token usage incl. cache, tool calls, stop
// reason) comes straight from what Claude Code already writes to disk — no proxy, no switch.
func parseTranscriptLine(raw []byte) *activity {
	var e struct {
		Type      string `json:"type"`
		Timestamp string `json:"timestamp"`
		Cwd       string `json:"cwd"`
		GitBranch string `json:"gitBranch"`
		Message   struct {
			ID         string `json:"id"`
			Model      string `json:"model"`
			StopReason string `json:"stop_reason"`
			Usage      struct {
				InputTokens              int `json:"input_tokens"`
				OutputTokens             int `json:"output_tokens"`
				CacheReadInputTokens     int `json:"cache_read_input_tokens"`
				CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
			} `json:"usage"`
			Content []struct {
				Type string `json:"type"`
				Name string `json:"name"`
			} `json:"content"`
		} `json:"message"`
	}
	if json.Unmarshal(raw, &e) != nil || e.Type != "assistant" || e.Message.Model == "" {
		return nil
	}
	act := &activity{
		Time:       hhmmss(e.Timestamp),
		MsgID:      e.Message.ID,
		Source:     "passive",
		Project:    projName(e.Cwd, e.GitBranch),
		Method:     "transcript",
		Model:      e.Message.Model,
		StopReason: e.Message.StopReason,
		Status:     200,
		InTokens:   e.Message.Usage.InputTokens,
		OutTokens:  e.Message.Usage.OutputTokens,
		CacheRead:  e.Message.Usage.CacheReadInputTokens,
		CacheWrite: e.Message.Usage.CacheCreationInputTokens,
	}
	for _, c := range e.Message.Content {
		if c.Type == "tool_use" {
			act.ToolCalls = append(act.ToolCalls, c.Name)
		}
	}
	act.CostUSD = estimateCost(act.Model, act.InTokens, act.OutTokens)
	return act
}

// replayPath parses a transcript file (or every *.jsonl under a dir) into the recorder. Returns the
// number of assistant events found. Used by --replay for demo/backfill.
func replayPath(path string, rec *recorder) int {
	var files []string
	if fi, err := os.Stat(path); err == nil && fi.IsDir() {
		filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() && strings.HasSuffix(p, ".jsonl") {
				files = append(files, p)
			}
			return nil
		})
	} else {
		files = []string{path}
	}
	n := 0
	for _, fp := range files {
		f, err := os.Open(fp)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 64<<20) // transcript lines can be large
		for sc.Scan() {
			if act := parseTranscriptLine(sc.Bytes()); act != nil {
				if isNew, _, _, _, _ := rec.record(act); isNew {
					n++ // count unique messages, not repeated transcript lines
				}
			}
		}
		f.Close()
	}
	return n
}

// tailProjects polls the Claude Code projects dir and streams new assistant turns as they're
// written — the live passive sensor. stdlib-only (poll + byte-offset), no fsnotify dep. Starts at
// each file's current EOF so it observes new activity, not history (use --replay for history).
func tailProjects(dir string, rec *recorder) {
	offsets := map[string]int64{}
	// Baseline: files already on disk at startup are history — skip to their EOF (use --replay to
	// backfill). Files that appear AFTER startup are new sessions → read from the beginning so we
	// don't miss their first turn.
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".jsonl") {
			if fi, e := os.Stat(p); e == nil {
				offsets[p] = fi.Size()
			}
		}
		return nil
	})
	for {
		filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".jsonl") {
				return nil
			}
			fi, err := os.Stat(p)
			if err != nil {
				return nil
			}
			size := fi.Size()
			off, seen := offsets[p]
			if !seen {
				off = 0 // appeared after startup → new session, capture from the beginning
				offsets[p] = 0
			}
			if size <= off {
				if size < off {
					offsets[p] = size // truncated/rotated
				}
				return nil
			}
			f, err := os.Open(p)
			if err != nil {
				return nil
			}
			data := make([]byte, size-off)
			nRead, _ := f.ReadAt(data, off)
			f.Close()
			data = data[:nRead]
			// only advance past complete (newline-terminated) lines; leave a partial write for next tick
			last := bytes.LastIndexByte(data, '\n')
			if last < 0 {
				return nil
			}
			for _, line := range bytes.Split(data[:last], []byte{'\n'}) {
				if act := parseTranscriptLine(line); act != nil {
					rec.emit(act)
				}
			}
			offsets[p] = off + int64(last+1)
			return nil
		})
		time.Sleep(time.Second)
	}
}

func projName(cwd, branch string) string {
	p := filepath.Base(cwd)
	if branch != "" {
		return p + "@" + branch
	}
	return p
}

func hhmmss(ts string) string {
	if t, err := time.Parse(time.RFC3339, ts); err == nil {
		return t.Local().Format("15:04:05")
	}
	return time.Now().Format("15:04:05")
}

// ---- activity record --------------------------------------------------------

type activity struct {
	Time         string   `json:"time"`
	MsgID        string   `json:"msgId,omitempty"` // Anthropic message id — dedup key (transcripts repeat a message across lines)
	Source       string   `json:"source"`          // "inline" (proxy) | "passive" (transcript tail)
	Project      string   `json:"project,omitempty"`
	Method       string   `json:"method"`
	Path         string   `json:"path"`
	Model        string   `json:"model,omitempty"`
	CacheRead    int      `json:"cacheReadTokens,omitempty"`
	CacheWrite   int      `json:"cacheWriteTokens,omitempty"`
	Messages     int      `json:"messages,omitempty"`
	SystemChars  int      `json:"systemChars,omitempty"`
	ToolsOffered []string `json:"toolsOffered,omitempty"`
	Stream       bool     `json:"stream"`
	Status       int      `json:"status"`
	StopReason   string   `json:"stopReason,omitempty"`
	InTokens     int      `json:"inTokens,omitempty"`
	OutTokens    int      `json:"outTokens,omitempty"`
	ToolCalls    []string `json:"toolCalls,omitempty"`
	LatencyMS    int64    `json:"latencyMs"`
	CostUSD      float64  `json:"costUsdEst,omitempty"`
	PromptPrev   string   `json:"promptPreview,omitempty"`
	OutputPrev   string   `json:"outputPreview,omitempty"`
	PID          int      `json:"pid,omitempty"`    // endpoint-scan: owning process
	Remote       string   `json:"remote,omitempty"` // endpoint-scan: remote addr

	start time.Time // not serialized
}

// ---- recorder ---------------------------------------------------------------

type recorder struct {
	verbose bool
	quiet   bool // record-only (no per-event stdout) — used by --replay
	logPath string

	mu      sync.Mutex
	ring    []activity     // recent, capped — the display buffer
	ringIdx map[string]int // message.id -> ring index (display refresh only; bounded to the ring)
	// counted/countedPrev are the totals dedup set. It must be GLOBAL, not windowed: Claude Code
	// re-appends earlier transcript lines on session resume/compaction, so the same message.id can
	// recur ~1000+ lines later (observed) — a small window would over-count it. Two generations bound
	// memory at ~2*countedGen ids while keeping the effective dedup window ≥ countedGen distinct
	// messages, far beyond any real recurrence gap.
	counted     map[string]struct{}
	countedPrev map[string]struct{}
	logf        *os.File
	totIn       int
	totOut      int
	totReq      int
	totCost     float64
}

const ringCap = 200

// countedGen bounds each generation of the totals dedup set; memory tops out at ~2*countedGen ids
// (~25 MB at 100k) while the effective dedup window stays ≥ countedGen distinct messages.
const countedGen = 100_000

// isCounted reports whether this message.id has already been folded into the totals.
func (rec *recorder) isCounted(id string) bool {
	if id == "" {
		return false
	}
	if _, ok := rec.counted[id]; ok {
		return true
	}
	_, ok := rec.countedPrev[id]
	return ok
}

// markCounted records that a message.id has been counted, rotating generations to bound memory.
func (rec *recorder) markCounted(id string) {
	if id == "" {
		return
	}
	if rec.counted == nil {
		rec.counted = map[string]struct{}{}
	}
	rec.counted[id] = struct{}{}
	if len(rec.counted) >= countedGen {
		rec.countedPrev = rec.counted
		rec.counted = map[string]struct{}{}
	}
}

func (rec *recorder) openLog() {
	_ = os.MkdirAll(filepath.Dir(rec.logPath), 0o755)
	f, err := os.OpenFile(rec.logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err == nil {
		rec.logf = f
	}
}

// observeRequest parses the outbound request for facts, carries them on the request context (which
// ReverseProxy propagates to the cloned outbound request → resp.Request), and restores the body so
// forwarding is byte-identical. Returns the request with the activity attached.
func (rec *recorder) observeRequest(r *http.Request) *http.Request {
	act := &activity{
		Time:   time.Now().Format("15:04:05"),
		Source: "inline",
		Method: r.Method,
		Path:   r.URL.Path,
		start:  time.Now(),
	}
	if r.Body != nil && strings.Contains(r.URL.Path, "/v1/messages") {
		body, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
		parseAnthropicRequest(body, act, rec.verbose)
	}
	return r.WithContext(context.WithValue(r.Context(), actKey, act))
}

func (rec *recorder) observeResponse(resp *http.Response) error {
	act, _ := resp.Request.Context().Value(actKey).(*activity)
	if act == nil {
		return nil
	}
	act.Status = resp.StatusCode
	ct := resp.Header.Get("Content-Type")

	finalize := func() {
		act.LatencyMS = time.Since(act.start).Milliseconds()
		act.CostUSD = estimateCost(act.Model, act.InTokens, act.OutTokens)
		rec.emit(act)
	}

	switch {
	case strings.Contains(ct, "text/event-stream"):
		act.Stream = true
		resp.Body = &streamObserver{under: resp.Body, act: act, verbose: rec.verbose, done: finalize}
	case strings.Contains(ct, "application/json"):
		resp.Body = &jsonObserver{under: resp.Body, act: act, verbose: rec.verbose, done: finalize}
	default:
		// non-message endpoint (or an error body) — record the bare fact.
		finalize()
	}
	return nil
}

// record folds an activity into the ring buffer, totals, and JSONL log — deduping by message.id,
// since Claude Code writes one assistant message across several transcript lines (same id + usage);
// counting per-line over-counts tokens/cost ~3x. Returns (isNew, running totals). A repeated line
// only refreshes the display entry (later lines may carry more content blocks); totals count once.
//
// Totals are deduped globally via the counted set (see recorder); the ring/ringIdx are just the
// bounded display buffer, so a duplicate that's still on-screen only refreshes its row.
func (rec *recorder) record(act *activity) (bool, int, int, int, float64) {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.ringIdx == nil {
		rec.ringIdx = map[string]int{}
	}
	if id := act.MsgID; rec.isCounted(id) {
		if idx, ok := rec.ringIdx[id]; ok && idx < len(rec.ring) {
			rec.ring[idx] = *act // already counted — later line may carry more blocks; refresh display only
		}
		return false, rec.totReq, rec.totIn, rec.totOut, rec.totCost
	}
	rec.totReq++
	rec.totIn += act.InTokens
	rec.totOut += act.OutTokens
	rec.totCost += act.CostUSD
	rec.ring = append(rec.ring, *act)
	if act.MsgID != "" {
		rec.markCounted(act.MsgID)
		rec.ringIdx[act.MsgID] = len(rec.ring) - 1
	}
	if len(rec.ring) > ringCap {
		rec.ring = rec.ring[len(rec.ring)-ringCap:]
		rec.ringIdx = map[string]int{}
		for i := range rec.ring {
			if rec.ring[i].MsgID != "" {
				rec.ringIdx[rec.ring[i].MsgID] = i
			}
		}
	}
	if rec.logf != nil {
		if b, err := json.Marshal(act); err == nil {
			rec.logf.Write(append(b, '\n'))
		}
	}
	return true, rec.totReq, rec.totIn, rec.totOut, rec.totCost
}

func (rec *recorder) emit(act *activity) {
	isNew, tReq, tIn, tOut, tCost := rec.record(act)
	if rec.quiet || !isNew {
		return
	}
	printLive(act)
	footer := fmt.Sprintf("       └─ session: %d msgs · %d in / %d out tokens", tReq, tIn, tOut)
	if tCost > 0 {
		footer += fmt.Sprintf(" · ~$%.4f", tCost)
	}
	fmt.Println(footer)
}

func (rec *recorder) printTail(n int) {
	rec.mu.Lock()
	r := make([]activity, len(rec.ring))
	copy(r, rec.ring)
	rec.mu.Unlock()
	if len(r) > n {
		r = r[len(r)-n:]
	}
	for i := range r {
		printLive(&r[i])
	}
}

func (rec *recorder) printSummary() {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	cost := "  \033[2m(subscription/API — not priced; tokens are the metric)\033[0m"
	if rec.totCost > 0 {
		cost = fmt.Sprintf("  ~$%.4f \033[2m(list-price est., API-billed only)\033[0m", rec.totCost)
	}
	fmt.Printf("\n\033[1msession totals:\033[0m %d messages · %d in / %d out tokens%s\n",
		rec.totReq, rec.totIn, rec.totOut, cost)
}

func (rec *recorder) serveEvents(w http.ResponseWriter, r *http.Request) {
	rec.mu.Lock()
	out := make([]activity, len(rec.ring))
	copy(out, rec.ring)
	rec.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"events": out})
}

func (rec *recorder) serveDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, dashboardHTML)
}

// ---- request/response parsing ----------------------------------------------

func parseAnthropicRequest(body []byte, act *activity, verbose bool) {
	var req struct {
		Model    string          `json:"model"`
		System   json.RawMessage `json:"system"`
		Stream   bool            `json:"stream"`
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if json.Unmarshal(body, &req) != nil {
		return
	}
	act.Model = req.Model
	act.Messages = len(req.Messages)
	act.SystemChars = len(contentText(req.System))
	for _, t := range req.Tools {
		act.ToolsOffered = append(act.ToolsOffered, t.Name)
	}
	if verbose && len(req.Messages) > 0 {
		last := req.Messages[len(req.Messages)-1]
		act.PromptPrev = preview(last.Role + ": " + contentText(last.Content))
	}
}

// contentText pulls text from a string-or-array Anthropic content field.
func contentText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &parts) == nil {
		var b strings.Builder
		for _, p := range parts {
			if p.Text != "" {
				b.WriteString(p.Text + " ")
			}
		}
		return strings.TrimSpace(b.String())
	}
	return ""
}

// jsonObserver buffers a non-streaming response, passes bytes through untouched, and parses the full
// message on EOF.
type jsonObserver struct {
	under   io.ReadCloser
	act     *activity
	verbose bool
	done    func()
	buf     bytes.Buffer
	fired   bool
}

func (o *jsonObserver) Read(p []byte) (int, error) {
	n, err := o.under.Read(p)
	if n > 0 {
		o.buf.Write(p[:n])
	}
	if err == io.EOF && !o.fired {
		o.fired = true
		parseAnthropicResponse(o.buf.Bytes(), o.act, o.verbose)
		o.done()
	}
	return n, err
}
func (o *jsonObserver) Close() error {
	if !o.fired {
		o.fired = true
		parseAnthropicResponse(o.buf.Bytes(), o.act, o.verbose)
		o.done()
	}
	return o.under.Close()
}

func parseAnthropicResponse(body []byte, act *activity, verbose bool) {
	var resp struct {
		StopReason string `json:"stop_reason"`
		Model      string `json:"model"`
		Usage      struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
			Name string `json:"name"`
		} `json:"content"`
	}
	if json.Unmarshal(body, &resp) != nil {
		return
	}
	if resp.Model != "" {
		act.Model = resp.Model
	}
	act.StopReason = resp.StopReason
	act.InTokens = resp.Usage.InputTokens
	act.OutTokens = resp.Usage.OutputTokens
	var text strings.Builder
	for _, c := range resp.Content {
		switch c.Type {
		case "text":
			text.WriteString(c.Text)
		case "tool_use":
			act.ToolCalls = append(act.ToolCalls, c.Name)
		}
	}
	if verbose {
		act.OutputPrev = preview(text.String())
	}
}

// streamObserver passes SSE bytes through to the client untouched (preserving streaming) while
// parsing the event stream to accumulate model/usage/tool-calls/stop_reason.
type streamObserver struct {
	under   io.ReadCloser
	act     *activity
	verbose bool
	done    func()
	line    bytes.Buffer
	text    strings.Builder
	fired   bool
}

func (o *streamObserver) Read(p []byte) (int, error) {
	n, err := o.under.Read(p)
	if n > 0 {
		o.feed(p[:n])
	}
	if err == io.EOF && !o.fired {
		o.finish()
	}
	return n, err
}
func (o *streamObserver) Close() error {
	if !o.fired {
		o.finish()
	}
	return o.under.Close()
}
func (o *streamObserver) finish() {
	o.fired = true
	if o.verbose {
		o.act.OutputPrev = preview(o.text.String())
	}
	o.done()
}

func (o *streamObserver) feed(b []byte) {
	for _, c := range b {
		if c == '\n' {
			o.handleLine(strings.TrimSpace(o.line.String()))
			o.line.Reset()
			continue
		}
		o.line.WriteByte(c)
	}
}

func (o *streamObserver) handleLine(line string) {
	if !strings.HasPrefix(line, "data:") {
		return
	}
	data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
	if data == "" || data == "[DONE]" {
		return
	}
	var ev struct {
		Type    string `json:"type"`
		Message struct {
			Model string `json:"model"`
			Usage struct {
				InputTokens  int `json:"input_tokens"`
				OutputTokens int `json:"output_tokens"`
			} `json:"usage"`
		} `json:"message"`
		ContentBlock struct {
			Type string `json:"type"`
			Name string `json:"name"`
		} `json:"content_block"`
		Delta struct {
			Type       string `json:"type"`
			Text       string `json:"text"`
			StopReason string `json:"stop_reason"`
		} `json:"delta"`
		Usage struct {
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}
	if json.Unmarshal([]byte(data), &ev) != nil {
		return
	}
	switch ev.Type {
	case "message_start":
		if ev.Message.Model != "" {
			o.act.Model = ev.Message.Model
		}
		o.act.InTokens = ev.Message.Usage.InputTokens
	case "content_block_start":
		if ev.ContentBlock.Type == "tool_use" {
			o.act.ToolCalls = append(o.act.ToolCalls, ev.ContentBlock.Name)
		}
	case "content_block_delta":
		if ev.Delta.Type == "text_delta" {
			o.text.WriteString(ev.Delta.Text)
		}
	case "message_delta":
		if ev.Delta.StopReason != "" {
			o.act.StopReason = ev.Delta.StopReason
		}
		if ev.Usage.OutputTokens > 0 {
			o.act.OutTokens = ev.Usage.OutputTokens
		}
	}
}

// ---- cost estimate (approximate, editable) ----------------------------------

// price is USD per 1M tokens {input, output}. EMPTY by default on purpose: we don't hardcode/guess
// per-model prices, and — critically — Claude Code on a subscription (Max/Pro) is NOT metered per
// token, so a per-token dollar figure would misrepresent actual spend. Tokens are the ground-truth
// signal we report; supply real prices here (or via config) to opt into a clearly-labeled
// list-price estimate for API-key-billed usage only.
var pricing = map[string][2]float64{}

func estimateCost(model string, in, out int) float64 {
	p, ok := pricing[model]
	if !ok {
		// prefix match (model ids often carry a date suffix)
		for k, v := range pricing {
			if strings.HasPrefix(model, k) {
				p, ok = v, true
				break
			}
		}
	}
	if !ok {
		return 0
	}
	return float64(in)/1e6*p[0] + float64(out)/1e6*p[1]
}

// ---- live view --------------------------------------------------------------

func printLive(a *activity) {
	if a.Source == "endpoint" {
		// endpoint-scan discovery — process → provider (metadata, no tokens)
		fmt.Printf("\033[2m%s\033[0m \033[35m[endpoint]\033[0m \033[36m%-14s\033[0m → \033[33m%s\033[0m \033[2m(%s, pid %d)\033[0m\n",
			a.Time, a.Model, a.Path, a.Remote, a.PID)
		return
	}
	badge := "\033[34m[inline] \033[0m"
	if a.Source == "passive" {
		badge = "\033[33m[passive]\033[0m"
	}
	model := a.Model
	if model == "" {
		model = a.Method + " " + a.Path
	}
	ctx := ""
	switch {
	case a.Project != "":
		ctx = " \033[2m" + a.Project + "\033[0m"
	case a.Messages > 0:
		ctx = fmt.Sprintf(" msgs=%d", a.Messages)
	}
	tools := ""
	if len(a.ToolsOffered) > 0 {
		tools = fmt.Sprintf(" tools=%d", len(a.ToolsOffered))
	}
	stream := ""
	if a.Stream {
		stream = " \033[2m(stream)\033[0m"
	}
	cache := ""
	if a.CacheRead > 0 || a.CacheWrite > 0 {
		cache = fmt.Sprintf(" \033[2mcache=%dr/%dw\033[0m", a.CacheRead, a.CacheWrite)
	}
	cost := ""
	if a.CostUSD > 0 {
		cost = fmt.Sprintf(" ~$%.4f", a.CostUSD)
	}
	stop := ""
	if a.StopReason != "" {
		stop = "  stop=" + a.StopReason
	}
	used := ""
	if len(a.ToolCalls) > 0 {
		used = "  \033[35mtool_use=[" + strings.Join(a.ToolCalls, ",") + "]\033[0m"
	}
	lat := ""
	if a.LatencyMS > 0 {
		lat = fmt.Sprintf(" %dms", a.LatencyMS)
	}
	fmt.Printf("\033[2m%s\033[0m %s \033[36m%-26s\033[0m%s%s%s → \033[32m%din/%dout\033[0m%s%s%s%s%s\n",
		a.Time, badge, model, ctx, tools, stream, a.InTokens, a.OutTokens, cache, cost, stop, used, lat)
	if a.PromptPrev != "" {
		fmt.Printf("       \033[2m» %s\033[0m\n", a.PromptPrev)
	}
	if a.OutputPrev != "" {
		fmt.Printf("       \033[2m« %s\033[0m\n", a.OutputPrev)
	}
}

func banner(listen, upstream, logPath, claudeDir string, verbose bool) {
	fmt.Printf("\033[1mflyedged\033[0m — AI activity flight recorder\n")
	fmt.Printf("  \033[33mpassive\033[0m (always on): tailing %s\n", claudeDir)
	fmt.Printf("  \033[35mendpoint\033[0m (always on): scanning host connections for AI agents every 0.5s (lsof + ps)\n")
	fmt.Printf("  \033[34minline\033[0m  (always on): proxy at http://%s — route a tool through it to also capture/guardrail its traffic:\n", listen)
	fmt.Printf("               \033[1mANTHROPIC_BASE_URL=http://%s claude\033[0m\n", listen)
	fmt.Printf("  upstream:  %s\n", upstream)
	fmt.Printf("  log:       %s   verbose=%v\n", logPath, verbose)
	fmt.Printf("  dashboard: http://%s/_flyedge\n\n", listen)
}

// ---- helpers ----------------------------------------------------------------

type ctxKey int

const actKey ctxKey = 0

func preview(s string) string {
	s = strings.ReplaceAll(strings.TrimSpace(s), "\n", " ")
	const max = 140
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func home() string {
	h, _ := os.UserHomeDir()
	return h
}

// isLoopback reports whether a listen host is loopback-only (safe to expose the dashboard/proxy on).
// Empty host means the wildcard address (all interfaces) — not loopback.
func isLoopback(host string) bool {
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

const dashboardHTML = `<!doctype html><meta charset=utf-8><title>flyedged</title>
<style>body{font:13px ui-monospace,monospace;margin:2rem;background:#0b0e14;color:#cbd5e1}
h1{font-size:15px}table{border-collapse:collapse;width:100%}td,th{padding:4px 8px;border-bottom:1px solid #1e293b;text-align:left}
.deny{color:#f87171}.tool{color:#c084fc}</style>
<h1>flyedged — AI flight recorder</h1><div id=s></div>
<table id=t><thead><tr><th>time<th>model<th>msgs<th>in<th>out<th>~$<th>stop<th>tools_used<th>ms</thead><tbody></tbody></table>
<script>
async function tick(){let r=await fetch('/_flyedge/events');let d=await r.json();let e=d.events.reverse();
document.querySelector('#t tbody').innerHTML=e.map(a=>` + "`" + `<tr><td>${a.time}<td>${a.model||a.path}<td>${a.messages||''}<td>${a.inTokens||''}<td>${a.outTokens||''}<td>${a.costUsdEst?('$'+a.costUsdEst.toFixed(4)):''}<td>${a.stopReason||''}<td class=tool>${(a.toolCalls||[]).join(',')}<td>${a.latencyMs}` + "`" + `).join('');}
tick();setInterval(tick,1500);
</script>`
