package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func TestQueuePersistsAndDeduplicates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "queue.json")
	store, err := openQueueStore(path)
	if err != nil {
		t.Fatal(err)
	}
	onion := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion"
	first, err := store.enqueue(enqueueParams{ID: "m1", FriendID: "f1", OnionAddress: onion, Payload: "ciphertext", CreatedAt: 1})
	if err != nil {
		t.Fatal(err)
	}
	if first.Status != "PENDING" {
		t.Fatalf("unexpected status: %s", first.Status)
	}
	if _, err = store.enqueue(enqueueParams{ID: "m1", FriendID: "f1", OnionAddress: onion, Payload: "ciphertext", CreatedAt: 1}); err != nil {
		t.Fatal(err)
	}
	reloaded, err := openQueueStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.list()) != 1 {
		t.Fatalf("queue was not deduplicated: %#v", reloaded.list())
	}
}

func TestQueueFailurePolicySeparatesTransientAndPermanentErrors(t *testing.T) {
	now := int64(1_000)
	status, code, retryAt := queueFailurePolicy(fmt.Errorf("socks_reply_host_unreachable"), 1, now)
	if status != "PENDING" || code != "onion_descriptor_unavailable" || retryAt != now+5_000 {
		t.Fatalf("unexpected descriptor policy: %s %s %d", status, code, retryAt)
	}
	status, code, retryAt = queueFailurePolicy(fmt.Errorf("ingest_failed:400"), 1, now)
	if status != "FAILED" || code != "permanent_upstream_rejection" || retryAt != 0 {
		t.Fatalf("unexpected permanent policy: %s %s %d", status, code, retryAt)
	}
	status, _, retryAt = queueFailurePolicy(fmt.Errorf("connection refused"), 15, now)
	if status != "FAILED" || retryAt != 0 {
		t.Fatalf("expected retry cap, got %s %d", status, retryAt)
	}
}

func TestQueueMigratesLegacyJournal(t *testing.T) {
	dir := t.TempDir()
	legacy := filepath.Join(dir, "legacy.json")
	journal := legacy + ".journal"
	native := filepath.Join(dir, "native.json")
	onion := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion"
	line := `{"v":1,"op":"upsertMessage","friend":{"friendId":"f1","onionAddress":"` + onion + `"},"message":{"id":"legacy-message","friendId":"f1","onionAddress":"` + onion + `","payload":"ciphertext","status":"PENDING","createdAt":1,"updatedAt":1}}` + "\n"
	if err := os.WriteFile(journal, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := openQueueStore(native, legacy, journal)
	if err != nil {
		t.Fatal(err)
	}
	if len(store.list()) != 1 || store.list()[0].ID != "legacy-message" {
		t.Fatalf("legacy queue was not migrated: %#v", store.list())
	}
	if _, err = os.Stat(native); err != nil {
		t.Fatalf("native queue snapshot missing: %v", err)
	}
}

func TestPostIngestUsesLiveOnionHTTPContract(t *testing.T) {
	var received map[string]any
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path != "/onion/ingest" {
			t.Fatalf("unexpected path: %s", request.URL.Path)
		}
		raw, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(raw, &received); err != nil {
			t.Fatal(err)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"ok":true,"msgId":"m1"}`)),
			Header:     make(http.Header),
		}, nil
	})}
	message := queuedMessage{
		ID: "m1", FriendID: "device-1",
		OnionAddress: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion",
		Payload:      "encrypted-envelope",
		InboxWriteToken: "mailbox-capability",
	}
	if err := postIngest(client, message, time.Second); err != nil {
		t.Fatal(err)
	}
	if received["toDeviceId"] != "device-1" ||
		received["envelope"] != "encrypted-envelope" ||
		received["id"] != "m1" ||
		received["inboxWriteToken"] != "mailbox-capability" {
		t.Fatalf("unexpected ingest payload: %#v", received)
	}
}

func TestQueueFlushDeliversThroughSOCKS5HTTP(t *testing.T) {
	received := make(chan map[string]any, 1)
	target := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var payload map[string]any
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Error(err)
			response.WriteHeader(400)
			return
		}
		received <- payload
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"ok":true,"msgId":"queued-message"}`))
	}))
	defer target.Close()
	targetAddress := strings.TrimPrefix(target.URL, "http://")

	proxy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	go func() {
		for {
			client, acceptErr := proxy.Accept()
			if acceptErr != nil {
				return
			}
			go func(client net.Conn) {
				defer client.Close()
				greeting := make([]byte, 3)
				if _, err := io.ReadFull(client, greeting); err != nil {
					return
				}
				_, _ = client.Write([]byte{5, 0})
				head := make([]byte, 5)
				if _, err := io.ReadFull(client, head); err != nil {
					return
				}
				if head[3] != 3 {
					return
				}
				if _, err := io.ReadFull(client, make([]byte, int(head[4])+2)); err != nil {
					return
				}
				upstream, err := net.Dial("tcp", targetAddress)
				if err != nil {
					return
				}
				defer upstream.Close()
				_, _ = client.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 80})
				done := make(chan struct{}, 1)
				go func() { _, _ = io.Copy(upstream, client); done <- struct{}{} }()
				_, _ = io.Copy(client, upstream)
				<-done
			}(client)
		}
	}()

	store, err := openQueueStore(filepath.Join(t.TempDir(), "queue.json"))
	if err != nil {
		t.Fatal(err)
	}
	store.setProxy("socks5h://" + proxy.Addr().String())
	onion := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion"
	if _, err = store.enqueue(enqueueParams{ID: "queued-message", FriendID: "device-1", OnionAddress: onion, Payload: "encrypted-envelope", CreatedAt: 1}); err != nil {
		t.Fatal(err)
	}
	result, err := store.flush(flushParams{ConnectTimeoutMs: 2_000, AckTimeoutMs: 2_000})
	if err != nil {
		t.Fatal(err)
	}
	if result.(map[string]int)["delivered"] != 1 {
		t.Fatalf("message was not delivered: %#v", result)
	}
	if store.list()[0].Status != "DELIVERED" {
		t.Fatalf("unexpected queue status: %#v", store.list())
	}
	select {
	case payload := <-received:
		if payload["id"] != "queued-message" || payload["toDeviceId"] != "device-1" {
			t.Fatalf("unexpected payload: %#v", payload)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("target did not receive queued message")
	}
}
