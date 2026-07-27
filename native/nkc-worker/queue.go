package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const queueFrameLimit = 2 * 1024 * 1024

type friendRoute struct {
	FriendID     string `json:"friendId"`
	OnionAddress string `json:"onionAddress"`
}

type queuedMessage struct {
	ID              string `json:"id"`
	FriendID        string `json:"friendId"`
	OnionAddress    string `json:"onionAddress"`
	Payload         string `json:"payload"`
	InboxWriteToken string `json:"inboxWriteToken,omitempty"`
	Status          string `json:"status"`
	CreatedAt       int64  `json:"createdAt"`
	UpdatedAt       int64  `json:"updatedAt"`
	DeliveredAt     int64  `json:"deliveredAt,omitempty"`
	LastError       string `json:"lastError,omitempty"`
	Attempts        int    `json:"attempts,omitempty"`
	NextAttemptAt   int64  `json:"nextAttemptAt,omitempty"`
	FailedAt        int64  `json:"failedAt,omitempty"`
}

type queueFile struct {
	Friends  []friendRoute   `json:"friends"`
	Messages []queuedMessage `json:"messages"`
}

type queueStore struct {
	mu       sync.Mutex
	path     string
	proxyURL string
	state    queueFile
}

type queueInitParams struct {
	Path           string `json:"path"`
	LegacySnapshot string `json:"legacySnapshot"`
	LegacyJournal  string `json:"legacyJournal"`
}
type setFriendsParams struct {
	Friends []friendRoute `json:"friends"`
}
type enqueueParams struct {
	ID              string `json:"id"`
	FriendID        string `json:"friendId"`
	OnionAddress    string `json:"onionAddress"`
	Payload         string `json:"payload"`
	InboxWriteToken string `json:"inboxWriteToken"`
	CreatedAt       int64  `json:"createdAt"`
}
type setProxyParams struct {
	ProxyURL string `json:"proxyUrl"`
}
type flushParams struct {
	ConnectTimeoutMs int `json:"connectTimeoutMs"`
	AckTimeoutMs     int `json:"ackTimeoutMs"`
}

func newID() string {
	bytes := make([]byte, 16)
	_, _ = rand.Read(bytes)
	bytes[6] = (bytes[6] & 0x0f) | 0x40
	bytes[8] = (bytes[8] & 0x3f) | 0x80
	hexID := hex.EncodeToString(bytes)
	return fmt.Sprintf("%s-%s-%s-%s-%s", hexID[:8], hexID[8:12], hexID[12:16], hexID[16:20], hexID[20:])
}

func normalizeOnion(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	value = strings.TrimPrefix(value, "http://")
	value = strings.TrimPrefix(value, "https://")
	if index := strings.IndexByte(value, '/'); index >= 0 {
		value = value[:index]
	}
	return value
}

func openQueueStore(path string, legacyPaths ...string) (*queueStore, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("invalid_queue_path")
	}
	store := &queueStore{path: path, state: queueFile{Friends: []friendRoute{}, Messages: []queuedMessage{}}}
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		raw, err = os.ReadFile(path + ".bak")
	}
	if err == nil {
		if err = json.Unmarshal(raw, &store.state); err != nil {
			return nil, fmt.Errorf("invalid_queue_file")
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	} else if len(legacyPaths) >= 2 {
		if err = store.migrateLegacy(legacyPaths[0], legacyPaths[1]); err != nil {
			return nil, err
		}
	}
	return store, nil
}

type legacyJournalEntry struct {
	Op        string                     `json:"op"`
	Queue     *queueFile                 `json:"queue"`
	Friends   []friendRoute              `json:"friends"`
	Message   *queuedMessage             `json:"message"`
	Friend    *friendRoute               `json:"friend"`
	IDs       []string                   `json:"ids"`
	Patch     map[string]json.RawMessage `json:"patch"`
	FriendID  string                     `json:"friendId"`
	UpdatedAt int64                      `json:"updatedAt"`
	LastError string                     `json:"lastError"`
}

func (q *queueStore) migrateLegacy(snapshotPath, journalPath string) error {
	if raw, err := os.ReadFile(snapshotPath); err == nil {
		_ = json.Unmarshal(raw, &q.state)
	}
	if raw, err := os.ReadFile(journalPath); err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(raw)))
		scanner.Buffer(make([]byte, 64*1024), 32*1024*1024)
		for scanner.Scan() {
			var entry legacyJournalEntry
			if json.Unmarshal(scanner.Bytes(), &entry) != nil {
				continue
			}
			q.applyLegacyEntry(entry)
		}
	}
	if len(q.state.Friends) > 0 || len(q.state.Messages) > 0 {
		return q.persist()
	}
	return nil
}

func (q *queueStore) applyLegacyEntry(entry legacyJournalEntry) {
	switch entry.Op {
	case "base":
		if entry.Queue != nil {
			q.state = *entry.Queue
		}
	case "replaceFriends":
		q.state.Friends = entry.Friends
	case "upsertMessage":
		if entry.Friend != nil {
			found := false
			for index := range q.state.Friends {
				if q.state.Friends[index].FriendID == entry.Friend.FriendID {
					q.state.Friends[index] = *entry.Friend
					found = true
				}
			}
			if !found {
				q.state.Friends = append(q.state.Friends, *entry.Friend)
			}
		}
		if entry.Message != nil {
			found := false
			for index := range q.state.Messages {
				if q.state.Messages[index].ID == entry.Message.ID {
					q.state.Messages[index] = *entry.Message
					found = true
				}
			}
			if !found {
				q.state.Messages = append(q.state.Messages, *entry.Message)
			}
		}
	case "patchMessages":
		ids := map[string]bool{}
		for _, id := range entry.IDs {
			ids[id] = true
		}
		for index := range q.state.Messages {
			if !ids[q.state.Messages[index].ID] {
				continue
			}
			if raw := entry.Patch["status"]; raw != nil {
				_ = json.Unmarshal(raw, &q.state.Messages[index].Status)
			}
			if raw := entry.Patch["updatedAt"]; raw != nil {
				_ = json.Unmarshal(raw, &q.state.Messages[index].UpdatedAt)
			}
			if raw := entry.Patch["deliveredAt"]; raw != nil {
				_ = json.Unmarshal(raw, &q.state.Messages[index].DeliveredAt)
			}
			if raw := entry.Patch["lastError"]; raw != nil {
				_ = json.Unmarshal(raw, &q.state.Messages[index].LastError)
			} else {
				q.state.Messages[index].LastError = ""
			}
		}
	case "resetFriend":
		for index := range q.state.Messages {
			if q.state.Messages[index].FriendID == entry.FriendID && q.state.Messages[index].Status == "IN_FLIGHT" {
				q.state.Messages[index].Status = "PENDING"
				q.state.Messages[index].UpdatedAt = entry.UpdatedAt
				q.state.Messages[index].LastError = entry.LastError
			}
		}
	}
}

func (q *queueStore) persist() error {
	if err := os.MkdirAll(filepath.Dir(q.path), 0o700); err != nil {
		return err
	}
	raw, err := json.Marshal(q.state)
	if err != nil {
		return err
	}
	temp := q.path + ".tmp"
	if err = os.WriteFile(temp, raw, 0o600); err != nil {
		return err
	}
	backup := q.path + ".bak"
	_ = os.Remove(backup)
	hadCurrent := false
	if _, statErr := os.Stat(q.path); statErr == nil {
		if err = os.Rename(q.path, backup); err != nil {
			return err
		}
		hadCurrent = true
	}
	if err = os.Rename(temp, q.path); err != nil {
		if hadCurrent {
			_ = os.Rename(backup, q.path)
		}
		return err
	}
	_ = os.Remove(backup)
	return nil
}

func (q *queueStore) setFriends(friends []friendRoute) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	byID := make(map[string]friendRoute, len(q.state.Friends)+len(friends))
	for _, friend := range q.state.Friends {
		byID[friend.FriendID] = friend
	}
	for _, friend := range friends {
		friend.OnionAddress = normalizeOnion(friend.OnionAddress)
		if friend.FriendID == "" || !strings.HasSuffix(friend.OnionAddress, ".onion") {
			continue
		}
		byID[friend.FriendID] = friend
	}
	q.state.Friends = q.state.Friends[:0]
	for _, friend := range byID {
		q.state.Friends = append(q.state.Friends, friend)
	}
	sort.Slice(q.state.Friends, func(i, j int) bool { return q.state.Friends[i].FriendID < q.state.Friends[j].FriendID })
	return q.persist()
}

func (q *queueStore) enqueue(input enqueueParams) (queuedMessage, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	onion := normalizeOnion(input.OnionAddress)
	if input.FriendID == "" || !strings.HasSuffix(onion, ".onion") || len(input.Payload) == 0 {
		return queuedMessage{}, fmt.Errorf("invalid_friend_onion_route")
	}
	now := time.Now().UnixMilli()
	if input.CreatedAt <= 0 {
		input.CreatedAt = now
	}
	if input.ID == "" {
		input.ID = newID()
	}
	for index, existing := range q.state.Messages {
		if existing.ID != input.ID {
			continue
		}
		if existing.Status != "DELIVERED" {
			existing.Status, existing.UpdatedAt, existing.LastError = "PENDING", now, ""
			existing.Attempts, existing.NextAttemptAt, existing.FailedAt = 0, now, 0
			q.state.Messages[index] = existing
			return existing, q.persist()
		}
		return existing, nil
	}
	message := queuedMessage{
		ID: input.ID, FriendID: input.FriendID, OnionAddress: onion, Payload: input.Payload,
		InboxWriteToken: input.InboxWriteToken,
		Status:          "PENDING", CreatedAt: input.CreatedAt, UpdatedAt: now, NextAttemptAt: now,
	}
	q.state.Messages = append(q.state.Messages, message)
	found := false
	for index, friend := range q.state.Friends {
		if friend.FriendID == input.FriendID {
			q.state.Friends[index].OnionAddress = onion
			found = true
		}
	}
	if !found {
		q.state.Friends = append(q.state.Friends, friendRoute{input.FriendID, onion})
	}
	return message, q.persist()
}

func (q *queueStore) list() []queuedMessage {
	q.mu.Lock()
	defer q.mu.Unlock()
	result := append([]queuedMessage(nil), q.state.Messages...)
	sort.SliceStable(result, func(i, j int) bool { return result[i].CreatedAt < result[j].CreatedAt })
	return result
}

func (q *queueStore) setProxy(value string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.proxyURL = strings.TrimSpace(value)
}

type socksProxyConfig struct {
	address  string
	username string
	password string
	hasAuth  bool
}

func parseProxy(proxyURL string) (socksProxyConfig, error) {
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		return socksProxyConfig{}, err
	}
	if parsed.Scheme != "socks5" && parsed.Scheme != "socks5h" {
		return socksProxyConfig{}, fmt.Errorf("unsupported_socks_protocol")
	}
	if parsed.Hostname() == "" || parsed.Port() == "" {
		return socksProxyConfig{}, fmt.Errorf("invalid_socks_proxy")
	}
	config := socksProxyConfig{address: net.JoinHostPort(parsed.Hostname(), parsed.Port())}
	if parsed.User != nil {
		config.username = parsed.User.Username()
		config.password, config.hasAuth = parsed.User.Password()
		if config.username == "" || !config.hasAuth || config.password == "" || len(config.username) > 255 || len(config.password) > 255 {
			return socksProxyConfig{}, fmt.Errorf("invalid_socks_auth")
		}
	}
	return config, nil
}

func dialSOCKS(proxyURL, target string, targetPort int, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return dialSOCKSContext(ctx, proxyURL, target, targetPort, timeout)
}

func dialSOCKSContext(ctx context.Context, proxyURL, target string, targetPort int, timeout time.Duration) (net.Conn, error) {
	proxy, err := parseProxy(proxyURL)
	if err != nil {
		return nil, err
	}
	conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", proxy.address)
	if err != nil {
		return nil, fmt.Errorf("proxy_connect:%w", err)
	}
	fail := func(err error) (net.Conn, error) { _ = conn.Close(); return nil, err }
	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	_ = conn.SetDeadline(deadline)
	method := byte(0)
	if proxy.hasAuth {
		method = 2
	}
	if _, err = conn.Write([]byte{5, 1, method}); err != nil {
		return fail(fmt.Errorf("socks_handshake:%w", err))
	}
	reply := make([]byte, 2)
	if _, err = io.ReadFull(conn, reply); err != nil {
		return fail(fmt.Errorf("socks_handshake:%w", err))
	}
	if reply[0] != 5 || reply[1] != method {
		return fail(fmt.Errorf("socks_auth_failed"))
	}
	if proxy.hasAuth {
		authRequest := []byte{1, byte(len(proxy.username))}
		authRequest = append(authRequest, []byte(proxy.username)...)
		authRequest = append(authRequest, byte(len(proxy.password)))
		authRequest = append(authRequest, []byte(proxy.password)...)
		if _, err = conn.Write(authRequest); err != nil {
			return fail(fmt.Errorf("socks_auth:%w", err))
		}
		authReply := make([]byte, 2)
		if _, err = io.ReadFull(conn, authReply); err != nil {
			return fail(fmt.Errorf("socks_auth:%w", err))
		}
		if authReply[0] != 1 || authReply[1] != 0 {
			return fail(fmt.Errorf("socks_auth_failed"))
		}
	}
	host := []byte(normalizeOnion(target))
	if len(host) == 0 || len(host) > 255 {
		return fail(fmt.Errorf("target_host_too_long"))
	}
	request := append([]byte{5, 1, 0, 3, byte(len(host))}, host...)
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(targetPort))
	request = append(request, port...)
	if _, err = conn.Write(request); err != nil {
		return fail(fmt.Errorf("socks_connect:%w", err))
	}
	head := make([]byte, 4)
	if _, err = io.ReadFull(conn, head); err != nil {
		return fail(fmt.Errorf("socks_connect:%w", err))
	}
	if head[0] != 5 || head[1] != 0 {
		return fail(fmt.Errorf("socks_reply_%s", socksReplyName(head[1])))
	}
	addressBytes := 0
	switch head[3] {
	case 1:
		addressBytes = 4
	case 4:
		addressBytes = 16
	case 3:
		length := make([]byte, 1)
		if _, err = io.ReadFull(conn, length); err != nil {
			return fail(err)
		}
		addressBytes = int(length[0])
	default:
		return fail(fmt.Errorf("socks_connect_failed"))
	}
	if _, err = io.ReadFull(conn, make([]byte, addressBytes+2)); err != nil {
		return fail(err)
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func socksReplyName(code byte) string {
	switch code {
	case 1:
		return "general_failure"
	case 2:
		return "ruleset_denied"
	case 3:
		return "network_unreachable"
	case 4:
		return "host_unreachable"
	case 5:
		return "connection_refused"
	case 6:
		return "ttl_expired"
	case 7:
		return "command_unsupported"
	case 8:
		return "address_unsupported"
	default:
		return "unknown"
	}
}

func (q *queueStore) pendingForFriend(friendID string, now int64) []queuedMessage {
	result := []queuedMessage{}
	for _, message := range q.state.Messages {
		if message.FriendID == friendID && message.Status == "PENDING" && message.NextAttemptAt <= now {
			result = append(result, message)
		}
	}
	sort.SliceStable(result, func(i, j int) bool { return result[i].CreatedAt < result[j].CreatedAt })
	return result
}

func queueFailurePolicy(err error, attempts int, now int64) (string, string, int64) {
	code := normalizeForwardError(err)
	text := strings.ToLower(err.Error())
	permanent := strings.Contains(text, "invalid_") ||
		strings.Contains(text, "unsupported_") ||
		strings.Contains(text, "socks_auth_failed") ||
		strings.Contains(text, "response_too_large") ||
		(strings.HasPrefix(text, "ingest_failed:4") && !strings.HasPrefix(text, "ingest_failed:429"))
	if permanent || attempts >= 15 {
		return "FAILED", code, 0
	}
	base, capDelay := int64(3_000), int64(120_000)
	switch code {
	case "onion_service_refused":
		base, capDelay = 1_000, 30_000
	case "proxy_unreachable", "proxy_connect_timeout":
		base, capDelay = 2_000, 60_000
	case "onion_descriptor_unavailable":
		base, capDelay = 5_000, 120_000
	}
	exponent := min(max(attempts-1, 0), 6)
	delay := base * int64(1<<exponent)
	if delay > capDelay {
		delay = capDelay
	}
	return "PENDING", code, now + delay
}

func (q *queueStore) patchFailure(id string, failure error) error {
	now := time.Now().UnixMilli()
	for index := range q.state.Messages {
		message := &q.state.Messages[index]
		if message.ID != id {
			continue
		}
		message.Attempts++
		message.Status, message.LastError, message.NextAttemptAt = queueFailurePolicy(failure, message.Attempts, now)
		message.UpdatedAt = now
		if message.Status == "FAILED" {
			message.FailedAt = now
		}
		break
	}
	return q.persist()
}

func (q *queueStore) patchStatus(ids map[string]bool, status, lastError string) error {
	now := time.Now().UnixMilli()
	for index := range q.state.Messages {
		if !ids[q.state.Messages[index].ID] {
			continue
		}
		q.state.Messages[index].Status = status
		q.state.Messages[index].UpdatedAt = now
		q.state.Messages[index].LastError = lastError
		if status == "DELIVERED" {
			q.state.Messages[index].NextAttemptAt = 0
			q.state.Messages[index].LastError = ""
			q.state.Messages[index].DeliveredAt = now
			// Delivery receipts retain metadata; the encrypted payload is no longer
			// needed for retry and should not be rewritten on every later update.
			q.state.Messages[index].Payload = ""
		}
	}
	return q.persist()
}

func createOnionHTTPClient(proxyURL string, connectTimeout time.Duration) *http.Client {
	transport := &http.Transport{
		MaxIdleConns:        8,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     65 * time.Second,
		DisableCompression:  true,
	}
	transport.DialContext = func(ctx context.Context, _, address string) (net.Conn, error) {
		host, portText, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		port, err := strconv.Atoi(portText)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid_target_port")
		}
		return dialSOCKSContext(ctx, proxyURL, host, port, connectTimeout)
	}
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func postIngest(client *http.Client, message queuedMessage, timeout time.Duration) error {
	body, err := json.Marshal(map[string]any{
		"id":              message.ID,
		"toDeviceId":      message.FriendID,
		"envelope":        message.Payload,
		"inboxWriteToken": message.InboxWriteToken,
	})
	if err != nil {
		return err
	}
	if len(body) > queueFrameLimit {
		return fmt.Errorf("frame_too_large")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	endpoint := "http://" + message.OnionAddress + "/onion/ingest"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, queueFrameLimit+1))
	if err != nil {
		return err
	}
	if len(raw) > queueFrameLimit {
		return fmt.Errorf("response_too_large")
	}
	var ack struct {
		OK        bool   `json:"ok"`
		MessageID string `json:"msgId"`
	}
	if json.Unmarshal(raw, &ack) != nil || response.StatusCode != http.StatusOK || !ack.OK {
		return fmt.Errorf("ingest_failed:%d", response.StatusCode)
	}
	return nil
}

func (q *queueStore) flush(params flushParams) (any, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.proxyURL == "" {
		return map[string]int{"delivered": 0}, nil
	}
	connectTimeout := time.Duration(params.ConnectTimeoutMs) * time.Millisecond
	ackTimeout := time.Duration(params.AckTimeoutMs) * time.Millisecond
	if connectTimeout <= 0 {
		connectTimeout = 8 * time.Second
	}
	if ackTimeout <= 0 {
		ackTimeout = 10 * time.Second
	}
	delivered := 0
	now := time.Now().UnixMilli()
	client := createOnionHTTPClient(q.proxyURL, connectTimeout)
	defer client.CloseIdleConnections()
	for _, friend := range q.state.Friends {
		pending := q.pendingForFriend(friend.FriendID, now)
		if len(pending) == 0 {
			continue
		}
		for _, message := range pending {
			ids := map[string]bool{message.ID: true}
			if err := q.patchStatus(ids, "IN_FLIGHT", ""); err != nil {
				break
			}
			if err := postIngest(client, message, ackTimeout); err != nil {
				_ = q.patchFailure(message.ID, err)
				break
			}
			if err := q.patchStatus(ids, "DELIVERED", ""); err != nil {
				break
			}
			delivered++
		}
	}
	return map[string]int{"delivered": delivered}, nil
}
