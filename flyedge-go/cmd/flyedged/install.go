package main

// Tooling to actually *use* the hook surface: a hook shim (so any agent — even ones that exec a
// process rather than POST HTTP — reaches the daemon) and an installer that wires a coding agent's
// hook config to this daemon.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// runHookShim is the `flyedged hook <agent> <event>` shim. A coding agent execs it, writes the hook
// event JSON on stdin, and reads the decision JSON on stdout. The shim just forwards to the daemon's
// /hooks/{agent}/{event} endpoint (which owns normalize/decide/denormalize) and pipes the response.
// It ALWAYS exits 0 and fails open (empty stdout = "no decision" = allow) so a down/slow daemon can
// never block the agent.
func runHookShim(args []string) {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: flyedged hook <agent> <event>")
		return
	}
	agent, event := args[0], args[1]
	body, _ := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))

	listen := envOr("FLYEDGED_LISTEN", "127.0.0.1:8787")
	url := "http://" + listen + "/hooks/" + agent + "/" + event
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return // fail open — daemon down/slow → no decision → agent proceeds
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	os.Stdout.Write(out)
}

// installHooks wires coding-agent hook configs to this daemon. Claude Code is auto-configured (a
// PreToolUse command hook that runs this binary's shim); Cursor's config is printed for the user to
// paste (its hooks.json schema is verified manually before we auto-write it). Idempotent.
func installHooks() {
	exe, err := os.Executable()
	if err != nil || exe == "" {
		exe = "flyedged"
	}
	cmd := exe + " hook claude-code pre-tool-use"

	if err := installClaudeHook(cmd); err != nil {
		fmt.Fprintf(os.Stderr, "claude code: %v\n", err)
	} else {
		fmt.Printf("\033[32m✓\033[0m Claude Code: PreToolUse hook → this daemon (%s)\n", claudeSettingsPath())
	}

	listen := envOr("FLYEDGED_LISTEN", "127.0.0.1:8787")
	fmt.Printf("\nNext:\n")
	fmt.Printf("  1. run the daemon:   \033[1mFLYEDGED_LISTEN=%s %s\033[0m\n", listen, exe)
	fmt.Printf("  2. use Claude Code as usual — tool calls are observed by this daemon (allow-only for\n     now; server-authoritative allow/deny/ask + SDK redaction land in a later slice).\n")
	fmt.Printf("  (undo with: \033[1m%s uninstall-hooks\033[0m)\n", exe)

	fmt.Printf("\n\033[2mCursor (manual — paste into ~/.cursor/hooks.json, verify against your Cursor version):\033[0m\n")
	cursorCmd := exe + " hook cursor pre-tool-use"
	snippet, _ := json.MarshalIndent(map[string]any{
		"version": 1,
		"hooks":   map[string]any{"preToolUse": []any{map[string]any{"command": cursorCmd}}},
	}, "  ", "  ")
	fmt.Printf("  %s\n", string(snippet))
}

// uninstallHooks removes the daemon's hook entries from the agent configs.
func uninstallHooks() {
	if err := removeClaudeHook(); err != nil {
		fmt.Fprintf(os.Stderr, "claude code: %v\n", err)
	} else {
		fmt.Printf("\033[32m✓\033[0m removed the flyedged PreToolUse hook from Claude Code\n")
	}
	fmt.Printf("Cursor: remove the flyedged entry from ~/.cursor/hooks.json manually.\n")
}

// ---- Claude Code settings.json wiring --------------------------------------

func claudeSettingsPath() string { return filepath.Join(home(), ".claude", "settings.json") }

// hookMarker identifies our command hook so install is idempotent and uninstall is targeted.
const hookMarker = "hook claude-code pre-tool-use"

func installClaudeHook(command string) error {
	path := claudeSettingsPath()
	settings, err := readJSONObject(path)
	if err != nil {
		return err
	}

	hooks, _ := settings["hooks"].(map[string]any)
	if hooks == nil {
		hooks = map[string]any{}
	}
	pre, _ := hooks["PreToolUse"].([]any)

	// Idempotent: bail if our command is already present.
	for _, entry := range pre {
		if em, ok := entry.(map[string]any); ok {
			if hs, ok := em["hooks"].([]any); ok {
				for _, h := range hs {
					if hm, ok := h.(map[string]any); ok {
						if c, _ := hm["command"].(string); strings.Contains(c, hookMarker) {
							return nil // already installed
						}
					}
				}
			}
		}
	}

	pre = append(pre, map[string]any{
		"matcher": "", // empty = all tools
		"hooks":   []any{map[string]any{"type": "command", "command": command}},
	})
	hooks["PreToolUse"] = pre
	settings["hooks"] = hooks
	return writeJSONObject(path, settings)
}

func removeClaudeHook() error {
	path := claudeSettingsPath()
	settings, err := readJSONObject(path)
	if err != nil {
		return err
	}
	hooks, _ := settings["hooks"].(map[string]any)
	if hooks == nil {
		return nil
	}
	pre, _ := hooks["PreToolUse"].([]any)
	kept := make([]any, 0, len(pre))
	for _, entry := range pre {
		drop := false
		if em, ok := entry.(map[string]any); ok {
			if hs, ok := em["hooks"].([]any); ok {
				for _, h := range hs {
					if hm, ok := h.(map[string]any); ok {
						if c, _ := hm["command"].(string); strings.Contains(c, hookMarker) {
							drop = true
						}
					}
				}
			}
		}
		if !drop {
			kept = append(kept, entry)
		}
	}
	if len(kept) == 0 {
		delete(hooks, "PreToolUse")
	} else {
		hooks["PreToolUse"] = kept
	}
	if len(hooks) == 0 {
		delete(settings, "hooks")
	} else {
		settings["hooks"] = hooks
	}
	return writeJSONObject(path, settings)
}

// ---- small JSON-file helpers (preserve unrelated keys) ----------------------

func readJSONObject(path string) (map[string]any, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]any{}, nil
		}
		return nil, err
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return map[string]any{}, nil
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("existing %s is not a JSON object: %w", path, err)
	}
	return m, nil
}

func writeJSONObject(path string, m map[string]any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}
