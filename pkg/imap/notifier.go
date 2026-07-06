package imap

import "sync"

// MailboxNotifier manages a pub/sub mechanism for mailbox changes.
// Subscribers register interest in a specific mailbox and receive
// notification (via channel close) when the mailbox changes.
type MailboxNotifier struct {
	mu   sync.RWMutex
	subs map[int64][]chan struct{}
}

// NewMailboxNotifier creates a new MailboxNotifier.
func NewMailboxNotifier() *MailboxNotifier {
	return &MailboxNotifier{
		subs: make(map[int64][]chan struct{}),
	}
}

// Subscribe registers interest in notifications for the given mailbox.
// The returned channel will be closed when the mailbox changes.
// The caller MUST call Unsubscribe to avoid leaking channels.
func (n *MailboxNotifier) Subscribe(mailboxID int64) <-chan struct{} {
	n.mu.Lock()
	defer n.mu.Unlock()
	ch := make(chan struct{})
	n.subs[mailboxID] = append(n.subs[mailboxID], ch)
	return ch
}

// Unsubscribe removes a previously registered subscription.
func (n *MailboxNotifier) Unsubscribe(mailboxID int64, ch <-chan struct{}) {
	n.mu.Lock()
	defer n.mu.Unlock()
	subs := n.subs[mailboxID]
	for i, sub := range subs {
		if sub == ch {
			n.subs[mailboxID] = append(subs[:i], subs[i+1:]...)
			return
		}
	}
}

// Notify signals all subscribers of the given mailbox that it has changed.
// All existing subscription channels for this mailbox are closed, and fresh
// channels are created for future subscribers.
func (n *MailboxNotifier) Notify(mailboxID int64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, ch := range n.subs[mailboxID] {
		close(ch)
	}
	n.subs[mailboxID] = nil
}
