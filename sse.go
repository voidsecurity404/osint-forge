package main

import (
	"encoding/json"
	"sync"
)

// sseMsg is one pre-encoded Server-Sent Event.
type sseMsg struct {
	event string
	data  []byte
}

// Hub fans scan events out to every connected browser tab.
//
// Each client gets a large buffered channel. If a client falls so far behind that
// its buffer fills (e.g. a backgrounded tab during a huge scan), it is dropped
// instead of blocking the scan; the browser's EventSource reconnects on its own
// and the UI re-syncs from /api/snapshot, so no graph data is lost.
type Hub struct {
	mu      sync.Mutex
	clients map[chan sseMsg]struct{}
}

const clientBuffer = 8192

func NewHub() *Hub { return &Hub{clients: map[chan sseMsg]struct{}{}} }

func (h *Hub) Subscribe() chan sseMsg {
	ch := make(chan sseMsg, clientBuffer)
	h.mu.Lock()
	h.clients[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *Hub) Unsubscribe(ch chan sseMsg) {
	h.mu.Lock()
	if _, ok := h.clients[ch]; ok {
		delete(h.clients, ch)
		close(ch)
	}
	h.mu.Unlock()
}

func (h *Hub) Publish(event string, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		return
	}
	msg := sseMsg{event: event, data: data}
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.clients {
		select {
		case ch <- msg:
		default:
			// Too slow: disconnect; it will reconnect and resync.
			delete(h.clients, ch)
			close(ch)
		}
	}
}
