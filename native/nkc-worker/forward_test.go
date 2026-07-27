package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"testing"
)

const testTorOnion = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion"

func testForwardWorker(t *testing.T, fetch func(transportFetchParams) (transportFetchResult, error), withQueue bool) *worker {
	t.Helper()
	w := &worker{transport: newTransportEngine()}
	w.transport.fetchOverride = fetch
	if withQueue {
		queue, err := openQueueStore(filepath.Join(t.TempDir(), "queue.json"))
		if err != nil {
			t.Fatal(err)
		}
		w.queue = queue
	}
	return w
}

func forwardParams(mode string) transportForwardParams {
	params := transportForwardParams{
		TorProxyURL:    "socks5h://127.0.0.1:9050",
		QueueOnFailure: true,
	}
	params.Payload.ToDeviceID = "peer-1"
	params.Payload.FromDeviceID = "sender-1"
	params.Payload.Envelope = "ciphertext"
	params.Payload.Route.Mode = mode
	params.Payload.Route.TorOnion = testTorOnion
	params.Payload.Route.InboxWriteToken = "mailbox-capability"
	return params
}

func TestForwardAutoUsesTor(t *testing.T) {
	var targets []string
	w := testForwardWorker(t, func(params transportFetchParams) (transportFetchResult, error) {
		targets = append(targets, params.URL)
		return transportFetchResult{Status: http.StatusOK}, nil
	}, false)
	result, err := w.forwardOnion(forwardParams("auto"))
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != http.StatusOK || result.Body["via"] != "tor" || len(targets) != 1 {
		t.Fatalf("unexpected result: %#v targets=%v", result, targets)
	}
}

func TestForwardQueuesTorFailure(t *testing.T) {
	w := testForwardWorker(t, func(transportFetchParams) (transportFetchResult, error) {
		return transportFetchResult{}, fmt.Errorf("connection refused")
	}, true)
	params := forwardParams("preferTor")
	result, err := w.forwardOnion(params)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != http.StatusAccepted || result.Body["queued"] != true {
		t.Fatalf("unexpected result: %#v", result)
	}
	queued := w.getQueue().list()
	if len(queued) != 1 || queued[0].Payload != "ciphertext" ||
		queued[0].OnionAddress != testTorOnion ||
		queued[0].InboxWriteToken != "mailbox-capability" {
		t.Fatalf("unexpected queue: %#v", queued)
	}
}

func TestForwardRejectsInjectedTarget(t *testing.T) {
	w := testForwardWorker(t, func(transportFetchParams) (transportFetchResult, error) {
		t.Fatal("fetch must not be called")
		return transportFetchResult{}, nil
	}, false)
	params := forwardParams("manual")
	params.Payload.Route.TorOnion = "http://127.0.0.1:8080"
	result, err := w.forwardOnion(params)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != http.StatusBadRequest || result.Body["error"] != "invalid-route-target" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestNormalizeForwardErrorRecognizesWindowsProxyFailure(t *testing.T) {
	err := fmt.Errorf("connectex: No connection could be made because the target machine actively refused it")
	if code := normalizeForwardError(err); code != "proxy_unreachable" {
		t.Fatalf("unexpected code: %s", code)
	}
}

func TestForwardSendsExpectedIngestEnvelope(t *testing.T) {
	w := testForwardWorker(t, func(params transportFetchParams) (transportFetchResult, error) {
		raw, err := base64.StdEncoding.DecodeString(params.BodyBase64)
		if err != nil {
			t.Fatal(err)
		}
		var payload map[string]any
		if err = json.Unmarshal(raw, &payload); err != nil {
			t.Fatal(err)
		}
		if payload["toDeviceId"] != "peer-1" || payload["from"] != "sender-1" ||
			payload["envelope"] != "ciphertext" ||
			payload["inboxWriteToken"] != "mailbox-capability" {
			t.Fatalf("unexpected payload: %#v", payload)
		}
		return transportFetchResult{Status: http.StatusOK}, nil
	}, false)
	params := forwardParams("preferTor")
	result, err := w.forwardOnion(params)
	if err != nil || result.Status != http.StatusOK {
		t.Fatalf("unexpected result: %#v err=%v", result, err)
	}
	for _, trace := range result.Traces {
		for _, forbidden := range []string{"destination", "destinationUrl", "toDeviceId"} {
			if _, exists := trace[forbidden]; exists {
				t.Fatalf("trace leaked %s: %#v", forbidden, trace)
			}
		}
	}
}
