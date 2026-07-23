package main

// Sensor enrollment + signed data-plane auth. The daemon generates its own Ed25519 keypair, sends
// only the public key to the platform's /api/v1/sensors/enroll (which binds a tenant-scoped DID),
// and thereafter authenticates its own calls by signing them with the frozen flyedge contract
// (github.com/compfly-ai/flyedge/flyedge-go/identity). The private key never leaves the host.

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/compfly-ai/flyedge/flyedge-go/identity"
)

const daemonVersion = "0.1.0"

// sensorState is persisted next to the private key so the daemon remembers who it enrolled as.
type sensorState struct {
	InstallID   string `json:"installId"`
	DID         string `json:"did"`
	SensorID    string `json:"sensorId"`
	OrgID       string `json:"orgId"`
	KeyID       string `json:"keyId"`
	PlatformURL string `json:"platformUrl"`
}

func flyedgeDir() string { return filepath.Join(home(), ".flyedge") }
func keyPath() string    { return filepath.Join(flyedgeDir(), "sensor.key") }
func statePath() string  { return filepath.Join(flyedgeDir(), "sensor.json") }

func loadState() (*sensorState, error) {
	b, err := os.ReadFile(statePath())
	if err != nil {
		return nil, err
	}
	var s sensorState
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func saveState(s *sensorState) error {
	if err := os.MkdirAll(flyedgeDir(), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(s, "", "  ")
	return os.WriteFile(statePath(), b, 0o600)
}

// loadOrCreateKey returns the daemon's private key PEM + public key, generating and persisting a new
// keypair (0600) on first use.
func loadOrCreateKey() (privPEM []byte, pub ed25519.PublicKey, err error) {
	if b, rerr := os.ReadFile(keyPath()); rerr == nil {
		block, _ := pem.Decode(b)
		if block == nil {
			return nil, nil, fmt.Errorf("sensor key: no PEM block in %s", keyPath())
		}
		key, perr := x509.ParsePKCS8PrivateKey(block.Bytes)
		if perr != nil {
			return nil, nil, fmt.Errorf("sensor key: %w", perr)
		}
		priv, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, nil, fmt.Errorf("sensor key: not Ed25519")
		}
		return b, priv.Public().(ed25519.PublicKey), nil
	}
	pubKey, priv, gerr := ed25519.GenerateKey(rand.Reader)
	if gerr != nil {
		return nil, nil, gerr
	}
	der, merr := x509.MarshalPKCS8PrivateKey(priv)
	if merr != nil {
		return nil, nil, merr
	}
	privPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.MkdirAll(flyedgeDir(), 0o700); err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(keyPath(), privPEM, 0o600); err != nil {
		return nil, nil, err
	}
	return privPEM, pubKey, nil
}

func publicKeyPEM(pub ed25519.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

func osUsername() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return os.Getenv("USER")
}

// runEnroll generates/loads the daemon's key and registers it as a sensor. Idempotent: re-running
// re-enrolls the same install. apiKey + orgID authenticate the enrolling principal (service/bootstrap
// path); in production the platform BFF supplies a human JWT + resolved org instead.
func runEnroll(platformURL, orgID, userID, apiKey string) error {
	if orgID == "" {
		return fmt.Errorf("enroll: --org (or FLYEDGED_ORG) is required")
	}
	if apiKey == "" {
		return fmt.Errorf("enroll: FLYEDGED_API_KEY is required to authenticate enrollment")
	}
	privPEM, pub, err := loadOrCreateKey()
	if err != nil {
		return err
	}
	pubPEM, err := publicKeyPEM(pub)
	if err != nil {
		return err
	}

	// Stable install id — reuse the existing one if we've enrolled before.
	installID := ""
	if st, err := loadState(); err == nil {
		installID = st.InstallID
	}
	if installID == "" {
		buf := make([]byte, 8)
		_, _ = rand.Read(buf)
		installID = "inst_" + hex.EncodeToString(buf)
	}

	hostname, _ := os.Hostname()
	reqBody, _ := json.Marshal(map[string]any{
		"installId":    installID,
		"publicKeyPem": pubPEM,
		"name":         hostname,
		"authMode":     "did",
		"version":      daemonVersion,
		"host": map[string]string{
			"hostname": hostname,
			"os":       runtime.GOOS,
			"osArch":   runtime.GOARCH,
			"osUser":   osUsername(),
		},
	})
	req, _ := http.NewRequest(http.MethodPost, platformURL+"/api/v1/sensors/enroll", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("X-Organization-Id", orgID)
	if userID != "" {
		req.Header.Set("X-User-Id", userID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("enroll: platform returned %d: %s", resp.StatusCode, string(body))
	}
	var env struct {
		Data struct {
			SensorID string `json:"sensorId"`
			OrgID    string `json:"orgId"`
			DID      string `json:"did"`
			KeyID    string `json:"keyId"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return fmt.Errorf("enroll: bad response: %w", err)
	}
	st := &sensorState{
		InstallID:   installID,
		DID:         env.Data.DID,
		SensorID:    env.Data.SensorID,
		OrgID:       env.Data.OrgID,
		KeyID:       env.Data.KeyID,
		PlatformURL: platformURL,
	}
	if err := saveState(st); err != nil {
		return fmt.Errorf("enroll: persist state: %w", err)
	}
	_ = privPEM // already persisted by loadOrCreateKey
	fmt.Printf("\033[1menrolled\033[0m as sensor %s\n  did:      %s\n  org:      %s\n  install:  %s\n  key:      %s\n  platform: %s\n",
		st.SensorID, st.DID, st.OrgID, st.InstallID, keyPath(), platformURL)
	return nil
}

// invItem is one observed (tool, workspace) fingerprint with light usage stats — the unit the
// platform auto-provisions as a discovered agent.
type invItem struct {
	Tool      string `json:"tool"`
	Workspace string `json:"workspace"`
	Model     string `json:"model"`
	Events    int    `json:"events"`
	InTokens  int    `json:"inTokens"`
	OutTokens int    `json:"outTokens"`
}

// collectInventory scans the Claude Code transcripts and aggregates distinct workspaces (repo) the
// daemon has observed — the (tool, workspace) grain we report as discovered agents. Deduped by
// message.id (transcripts repeat a message across lines).
func collectInventory(claudeDir string) []invItem {
	agg := map[string]*invItem{}
	seen := map[string]bool{}
	filepath.WalkDir(claudeDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".jsonl") {
			return nil
		}
		f, e := os.Open(p)
		if e != nil {
			return nil
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 64<<20)
		for sc.Scan() {
			act := parseTranscriptLine(sc.Bytes())
			if act == nil || act.MsgID == "" || seen[act.MsgID] {
				continue
			}
			seen[act.MsgID] = true
			ws := act.Project // "repo@branch" — take the repo as the workspace grain
			if i := strings.IndexByte(ws, '@'); i >= 0 {
				ws = ws[:i]
			}
			if ws == "" {
				continue
			}
			it := agg[ws]
			if it == nil {
				it = &invItem{Tool: "claude-code", Workspace: ws}
				agg[ws] = it
			}
			it.Events++
			it.InTokens += act.InTokens
			it.OutTokens += act.OutTokens
			if act.Model != "" {
				it.Model = act.Model
			}
		}
		return nil
	})
	out := make([]invItem, 0, len(agg))
	for _, it := range agg {
		out = append(out, *it)
	}
	return out
}

// runConnect pushes the daemon's observed inventory to the platform (signed), which marks the sensor
// online and auto-provisions each (tool, workspace) as a discovered agent attributed to this sensor.
func runConnect(platformURL, claudeDir string) error {
	st, err := loadState()
	if err != nil {
		return fmt.Errorf("connect: not enrolled (%v) — run --enroll first", err)
	}
	if platformURL == "" {
		platformURL = st.PlatformURL
	}
	privPEM, _, err := loadOrCreateKey()
	if err != nil {
		return err
	}
	signer, err := identity.NewFileSigner(privPEM, st.DID)
	if err != nil {
		return fmt.Errorf("connect: signer: %w", err)
	}
	inv := collectInventory(claudeDir)
	body, _ := json.Marshal(map[string]any{"inventory": inv})
	hdrs, err := signer.Sign(body, time.Now())
	if err != nil {
		return fmt.Errorf("connect: sign: %w", err)
	}
	req, _ := http.NewRequest(http.MethodPost, platformURL+"/api/v1/edge/connect", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("connect: platform returned %d: %s", resp.StatusCode, string(out))
	}
	var env struct {
		Data struct {
			SensorID string `json:"sensorId"`
			Agents   []struct {
				Tool      string `json:"tool"`
				Workspace string `json:"workspace"`
				Slug      string `json:"slug"`
				AgentID   string `json:"agentId"`
				Created   bool   `json:"created"`
			} `json:"agents"`
		} `json:"data"`
	}
	_ = json.Unmarshal(out, &env)
	created := 0
	for _, a := range env.Data.Agents {
		if a.Created {
			created++
		}
	}
	fmt.Printf("\033[1mconnected\033[0m — reported %d workspace(s); %d discovered agents (%d newly created):\n",
		len(inv), len(env.Data.Agents), created)
	for _, a := range env.Data.Agents {
		tag := "\033[2mexists\033[0m"
		if a.Created {
			tag = "\033[32mNEW\033[0m"
		}
		fmt.Printf("  [%s] %-28s \033[2m%s\033[0m\n", tag, a.Workspace, a.AgentID)
	}
	return nil
}

// runWhoami proves the enrolled daemon can authenticate AS ITSELF using only its key: it signs a
// request with the frozen contract and calls the platform's signed /edge/whoami.
func runWhoami(platformURL string) error {
	st, err := loadState()
	if err != nil {
		return fmt.Errorf("whoami: not enrolled (%v) — run --enroll first", err)
	}
	if platformURL == "" {
		platformURL = st.PlatformURL
	}
	privPEM, _, err := loadOrCreateKey()
	if err != nil {
		return err
	}
	signer, err := identity.NewFileSigner(privPEM, st.DID)
	if err != nil {
		return fmt.Errorf("whoami: signer: %w", err)
	}
	body := []byte(`{"ping":"whoami"}`)
	hdrs, err := signer.Sign(body, time.Now())
	if err != nil {
		return fmt.Errorf("whoami: sign: %w", err)
	}
	req, _ := http.NewRequest(http.MethodPost, platformURL+"/api/v1/edge/whoami", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("whoami: %w", err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("whoami: platform returned %d: %s", resp.StatusCode, string(out))
	}
	fmt.Printf("\033[1msigned auth OK\033[0m — platform recognizes this daemon:\n%s\n", string(out))
	return nil
}
