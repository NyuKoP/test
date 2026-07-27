package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var (
	torTargetPattern = regexp.MustCompile(`^[a-z2-7]{56}\.onion$`)
)

type onionRoutePayload struct {
	To           string `json:"to"`
	From         string `json:"from"`
	Envelope     string `json:"envelope"`
	ToDeviceID   string `json:"toDeviceId"`
	ToOnion      string `json:"toOnion"`
	FromDeviceID string `json:"fromDeviceId"`
	Route        struct {
		Mode            string `json:"mode"`
		TorOnion        string `json:"torOnion"`
		InboxWriteToken string `json:"inboxWriteToken"`
	} `json:"route"`
}

type transportForwardParams struct {
	Payload        onionRoutePayload `json:"payload"`
	TorProxyURL    string            `json:"torProxyUrl"`
	QueueOnFailure bool              `json:"queueOnFailure"`
}

type transportForwardResult struct {
	Status int              `json:"status"`
	Body   map[string]any   `json:"body"`
	Traces []map[string]any `json:"traces"`
}

type routeCandidate struct {
	kind   string
	target string
	proxy  string
}

func normalizeRouteTarget(kind, value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if !strings.HasPrefix(value, "http://") {
		value = "http://" + value
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return ""
	}
	hostname := strings.ToLower(parsed.Hostname())
	if kind == "tor" && !torTargetPattern.MatchString(hostname) {
		return ""
	}
	return "http://" + parsed.Host
}

func buildRouteCandidates(mode, torTarget, torProxy string) []routeCandidate {
	tor := routeCandidate{kind: "tor", target: torTarget, proxy: strings.TrimSpace(torProxy)}
	hasTor := tor.target != "" && tor.proxy != ""
	switch mode {
	case "preferTor":
		if hasTor {
			return []routeCandidate{tor}
		}
	case "manual":
		if hasTor {
			return []routeCandidate{tor}
		}
	case "auto":
		if hasTor {
			return []routeCandidate{tor}
		}
	}
	return nil
}

func normalizeForwardError(err error) string {
	text := strings.ToLower(err.Error())
	if strings.Contains(text, "ingest_failed:429") {
		return "upstream_rate_limited"
	}
	if strings.Contains(text, "ingest_failed:4") {
		return "permanent_upstream_rejection"
	}
	if strings.Contains(text, "ingest_failed:5") {
		return "upstream_http_error"
	}
	for _, code := range []string{"proxy_connect_timeout", "socks_handshake_timeout", "upstream_response_timeout"} {
		if strings.Contains(text, code) {
			return code
		}
	}
	if strings.Contains(text, "socks_reply_host_unreachable") {
		return "onion_descriptor_unavailable"
	}
	if strings.Contains(text, "socks_reply_network_unreachable") {
		return "tor_network_unreachable"
	}
	if strings.Contains(text, "socks_reply_connection_refused") {
		return "onion_service_refused"
	}
	if strings.Contains(text, "timeout") || strings.Contains(text, "deadline exceeded") {
		return "upstream_response_timeout"
	}
	if strings.Contains(text, "socks_auth") || strings.Contains(text, "socks_connect") || strings.Contains(text, "unsupported_socks") || strings.Contains(text, "invalid_socks") {
		return "handshake_failed"
	}
	if strings.Contains(text, "connection refused") || strings.Contains(text, "actively refused") || strings.Contains(text, "connectex") || strings.Contains(text, "no such host") || strings.Contains(text, "network is unreachable") || strings.Contains(text, "host is unreachable") || strings.Contains(text, "connection reset") || strings.Contains(text, "forcibly closed") || strings.Contains(text, "connect_fail") {
		return "proxy_unreachable"
	}
	return "upstream_error"
}

func forwardFailure(status int, msgID, code string, traces []map[string]any) transportForwardResult {
	return transportForwardResult{
		Status: status,
		Body:   map[string]any{"ok": false, "error": code},
		Traces: traces,
	}
}

func (w *worker) forwardOnion(params transportForwardParams) (transportForwardResult, error) {
	payload := params.Payload
	if payload.Envelope == "" {
		return forwardFailure(http.StatusBadRequest, "", "missing-fields", nil), nil
	}
	msgID := newID()
	now := time.Now().UnixMilli()
	toDeviceID := payload.ToDeviceID
	if toDeviceID == "" {
		toDeviceID = payload.To
	}
	fromDeviceID := payload.FromDeviceID
	if fromDeviceID == "" {
		fromDeviceID = payload.From
	}
	if toDeviceID == "" {
		return forwardFailure(http.StatusBadRequest, msgID, "missing-to-device", nil), nil
	}
	if len(toDeviceID) > 256 || len(fromDeviceID) > 256 {
		return forwardFailure(http.StatusBadRequest, msgID, "invalid-device-id", nil), nil
	}
	mode := payload.Route.Mode
	if mode == "" {
		mode = "manual"
	}
	if mode != "auto" && mode != "preferTor" && mode != "manual" {
		return forwardFailure(http.StatusBadRequest, msgID, "invalid-route-mode", nil), nil
	}
	torValue := payload.ToOnion
	if torValue == "" {
		torValue = payload.Route.TorOnion
	}
	if torValue == "" && strings.Contains(payload.To, ".onion") {
		torValue = payload.To
	}
	torTarget := normalizeRouteTarget("tor", torValue)
	if torValue != "" && torTarget == "" {
		return forwardFailure(http.StatusBadRequest, msgID, "invalid-route-target", nil), nil
	}

	candidates := buildRouteCandidates(mode, torTarget, params.TorProxyURL)
	traces := make([]map[string]any, 0, len(candidates)*2)
	terminalCode := "forward_failed:no_route"
	terminalStatus := http.StatusBadRequest
	for index, candidate := range candidates {
		targetURL := candidate.target + "/onion/ingest"
		traces = append(traces, map[string]any{
			"event": "onionController:forward:start", "opId": msgID,
			"routeKind": candidate.kind, "routeMode": mode,
			"attempt": index + 1, "maxRouteAttempts": len(candidates), "timeoutMs": 45_000,
		})
		body, err := json.Marshal(map[string]any{
			"toDeviceId": toDeviceID, "from": fromDeviceID, "envelope": payload.Envelope,
			"ts": now, "id": msgID, "inboxWriteToken": payload.Route.InboxWriteToken,
		})
		if err != nil {
			return transportForwardResult{}, err
		}
		response, err := w.transport.fetch(transportFetchParams{
			URL: targetURL, Method: http.MethodPost,
			Headers:    map[string]string{"Content-Type": "application/json"},
			BodyBase64: base64.StdEncoding.EncodeToString(body), TimeoutMS: 45_000,
			SocksProxyURL: candidate.proxy, Retry: transportRetryParams{Attempts: 1, DelayMS: 350},
		})
		if err == nil && response.Status >= 200 && response.Status < 300 {
			traces = append(traces, map[string]any{
				"event": "onionController:forward:ok", "opId": msgID,
				"routeKind": candidate.kind, "routeMode": mode, "status": response.Status,
				"attempt": index + 1, "maxRouteAttempts": len(candidates),
			})
			return transportForwardResult{
				Status: http.StatusOK,
				Body:   map[string]any{"ok": true, "msgId": msgID, "forwarded": true, "via": candidate.kind},
				Traces: traces,
			}, nil
		}
		code := "upstream_error"
		if err != nil {
			code = normalizeForwardError(err)
		}
		traces = append(traces, map[string]any{
			"event": "onionController:forward:fail", "level": "warn", "opId": msgID,
			"routeKind": candidate.kind, "routeMode": mode, "normalizedCode": code,
			"attempt": index + 1, "maxRouteAttempts": len(candidates),
		})
		terminalCode = "forward_failed:" + code
		terminalStatus = http.StatusBadGateway
		if mode != "auto" {
			break
		}
	}

	shouldQueue := params.QueueOnFailure && torTarget != ""
	if shouldQueue {
		queue := w.getQueue()
		if queue != nil {
			_, err := queue.enqueue(enqueueParams{
				ID: msgID, FriendID: toDeviceID, OnionAddress: torTarget,
				Payload: payload.Envelope, InboxWriteToken: payload.Route.InboxWriteToken,
				CreatedAt: now,
			})
			if err != nil {
				return transportForwardResult{}, fmt.Errorf("queue_forward_failure:%w", err)
			}
			traces = append(traces, map[string]any{
				"event": "onionController:offlineQueue:pending", "level": "warn",
				"opId":   msgID,
				"reason": terminalCode,
			})
			return transportForwardResult{
				Status: http.StatusAccepted,
				Body: map[string]any{
					"ok": true, "msgId": msgID, "forwarded": false, "queued": true,
					"status": "PENDING", "error": terminalCode,
				},
				Traces: traces,
			}, nil
		}
	}
	return forwardFailure(terminalStatus, msgID, terminalCode, traces), nil
}
