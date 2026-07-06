package imap

import (
	"context"
	"io"
	"strings"
	"time"

	"github.com/emersion/go-imap"
	"github.com/i-got-this-faa/marco/pkg/storage"
)

// Mailbox implements backend.Mailbox.

// blobLiteral wraps an io.Reader with a known size, satisfying imap.Literal.
type blobLiteral struct {
	io.Reader
	size int64
}

func (l *blobLiteral) Len() int {
	return int(l.size)
}
type Mailbox struct {
	user      User
	mailboxID int64
	name      string
	notifier  *MailboxNotifier
	poller    func(mailboxID int64, stop <-chan struct{}, changes chan<- struct{})
}

// Name returns the mailbox name.
func (m *Mailbox) Name() string {
	return m.name
}

// Info returns mailbox metadata.
func (m *Mailbox) Info() (*imap.MailboxInfo, error) {
	return &imap.MailboxInfo{
		Name:       m.name,
		Attributes: []string{},
		Delimiter:  ".",
	}, nil
}

// Status returns mailbox status.
func (m *Mailbox) Status(items []imap.StatusItem) (*imap.MailboxStatus, error) {
	ctx := context.TODO()
	status := imap.NewMailboxStatus(m.name, items)

	count, err := storage.CountMessages(ctx, m.user.db, m.mailboxID)
	if err != nil {
		return nil, err
	}
	status.Messages = uint32(count)
	status.UidValidity = uint32(m.mailboxID)
	status.Flags = []string{imap.SeenFlag, imap.AnsweredFlag, imap.FlaggedFlag, imap.DeletedFlag, imap.DraftFlag}

	msgs, err := storage.ListMessages(ctx, m.user.db, m.mailboxID, 1, 0)
	if err != nil {
		return nil, err
	}
	if len(msgs) > 0 {
		status.UidNext = msgs[0].UID + 1
	} else {
		status.UidNext = 1
	}

	return status, nil
}

// SetSubscribed subscribes or unsubscribes.
func (m *Mailbox) SetSubscribed(subscribed bool) error {
	return nil
}

// Check performs a checkpoint.
func (m *Mailbox) Check() error {
	return nil
}

// ListMessages fetches messages and sends them to the provided channel.
// When uid is true, seqset contains UIDs; otherwise it contains sequence numbers
// (1-based index in the mailbox sorted by UID ascending).
func (m *Mailbox) ListMessages(uid bool, seqset *imap.SeqSet, items []imap.FetchItem, ch chan<- *imap.Message) error {
	go func() {
		defer close(ch)
		ctx := context.TODO()

		allMsgs, err := storage.ListMessages(ctx, m.user.db, m.mailboxID, 0, 0)
		if err != nil {
			return
		}

		// Reverse to ascending UID order so sequence numbers are 1-indexed.
		for i, j := 0, len(allMsgs)-1; i < j; i, j = i+1, j-1 {
			allMsgs[i], allMsgs[j] = allMsgs[j], allMsgs[i]
		}

		for seqNum, msg := range allMsgs {
			seq := uint32(seqNum + 1) // 1-based sequence number

			// Filter by seqset.
			if uid {
				if !seqset.Contains(msg.UID) {
					continue
				}
			} else if !seqset.Contains(seq) {
				continue
			}

			imapMsg := imap.NewMessage(seq, items)
			imapMsg.Uid = msg.UID
			for _, item := range items {
				switch item {
				case imap.FetchFlags:
					imapMsg.Flags = flagsToIMAP(msg.Flags)
				case imap.FetchEnvelope:
					imapMsg.Envelope = &imap.Envelope{
						Subject: msg.Subject,
						From:    []*imap.Address{{MailboxName: msg.FromAddr}},
						To:      []*imap.Address{{MailboxName: msg.ToAddr}},
						Date:    time.Unix(msg.InternalDate, 0),
					}
				case imap.FetchBody, imap.FetchBodyStructure, imap.FetchRFC822:
					rc, err := m.user.blob.Get(ctx, msg.BlobKey)
					if err != nil {
						continue
					}
					section := &imap.BodySectionName{}
					imapMsg.Body[section] = &blobLiteral{Reader: rc, size: msg.Size}
					imapMsg.Size = uint32(msg.Size)
				case imap.FetchInternalDate:
					imapMsg.InternalDate = time.Unix(msg.InternalDate, 0)
				case imap.FetchRFC822Size:
					imapMsg.Size = uint32(msg.Size)
				}
			}
			ch <- imapMsg
		}
	}()
	return nil
}

// SearchMessages searches messages. Returns UIDs when uid is true,
// or sequence numbers when uid is false.
func (m *Mailbox) SearchMessages(uid bool, criteria *imap.SearchCriteria) ([]uint32, error) {
	// If text search criteria is specified, use FTS5 full-text search.
	if len(criteria.Text) > 0 {
		// Build FTS5 query: each text term is a word or phrase that must appear.
		// Phrases (containing spaces) are wrapped in double quotes.
		var terms []string
		for _, t := range criteria.Text {
			if strings.Contains(t, " ") {
				terms = append(terms, `"`+t+`"`)
			} else {
				terms = append(terms, t)
			}
		}
		query := strings.Join(terms, " ")

		msgs, err := storage.SearchMessages(context.TODO(), m.user.db, m.mailboxID, query, 0)
		if err != nil {
			return nil, err
		}

		// Collect UIDs from matching messages.
		uids := make([]uint32, len(msgs))
		for i, msg := range msgs {
			uids[i] = msg.UID
		}

		if uid {
			return uids, nil
		}

		// Convert UIDs to 1-based sequence numbers.
		allUIDs, err := storage.ListMessageUIDs(context.TODO(), m.user.db, m.mailboxID)
		if err != nil {
			return nil, err
		}
		uidToSeq := make(map[uint32]uint32, len(allUIDs))
		for i, u := range allUIDs {
			uidToSeq[u] = uint32(i + 1)
		}
		result := make([]uint32, len(uids))
		for i, u := range uids {
			result[i] = uidToSeq[u]
		}
		return result, nil
	}

	// No text criteria — use lightweight UID listing (existing behavior).
	uids, err := storage.ListMessageUIDs(context.TODO(), m.user.db, m.mailboxID)
	if err != nil {
		return nil, err
	}

	if uid {
		return uids, nil
	}

	// Return 1-based sequence numbers matching the UID order.
	result := make([]uint32, len(uids))
	for i := range uids {
		result[i] = uint32(i + 1)
	}
	return result, nil
}

// CreateMessage appends a new message to this mailbox.
func (m *Mailbox) CreateMessage(flags []string, date time.Time, body imap.Literal) error {
	ctx := context.TODO()

	blobKey, _, err := m.user.blob.Put(ctx, body, nil)
	if err != nil {
		return err
	}

	flagBits := flagsToBits(flags)
	_, _, err = storage.InsertMessage(ctx, m.user.db, m.mailboxID, blobKey,
		int64(body.Len()), "", "", "", flagBits)
	if err != nil {
		return err
	}

	m.notifier.Notify(m.mailboxID)
	return nil
}

// UpdateMessagesFlags updates message flags.
// When uid is true, seqset contains UIDs; otherwise it contains sequence numbers.
func (m *Mailbox) UpdateMessagesFlags(uid bool, seqset *imap.SeqSet, operation imap.FlagsOp, flags []string) error {
	ctx := context.TODO()
	msgs, err := storage.ListMessages(ctx, m.user.db, m.mailboxID, 0, 0)
	if err != nil {
		return err
	}

	// Reverse to ascending UID order so sequence numbers are 1-indexed.
	for i, j := 0, len(msgs)-1; i < j; i, j = i+1, j-1 {
		msgs[i], msgs[j] = msgs[j], msgs[i]
	}

	flagBits := flagsToBits(flags)
	for seqNum, msg := range msgs {
		seq := uint32(seqNum + 1)

		if uid {
			if !seqset.Contains(msg.UID) {
				continue
			}
		} else if !seqset.Contains(seq) {
			continue
		}

		var newFlags int
		switch operation {
		case imap.SetFlags:
			newFlags = flagBits
		case imap.AddFlags:
			newFlags = msg.Flags | flagBits
		case imap.RemoveFlags:
			newFlags = msg.Flags & ^flagBits
		}

		if err := storage.UpdateFlags(ctx, m.user.db, msg.ID, newFlags, ^0); err != nil {
			return err
		}
	}
	m.notifier.Notify(m.mailboxID)
	return nil
}

// CopyMessages copies messages to another mailbox.
// When uid is true, seqset contains UIDs; otherwise it contains sequence numbers.
func (m *Mailbox) CopyMessages(uid bool, seqset *imap.SeqSet, dest string) error {
	destBox, err := storage.GetMailbox(context.TODO(), m.user.db, m.user.userID, dest)
	if err != nil {
		return err
	}

	ctx := context.TODO()
	msgs, err := storage.ListMessages(ctx, m.user.db, m.mailboxID, 0, 0)
	if err != nil {
		return err
	}

	// Reverse to ascending UID order so sequence numbers are 1-indexed.
	for i, j := 0, len(msgs)-1; i < j; i, j = i+1, j-1 {
		msgs[i], msgs[j] = msgs[j], msgs[i]
	}

	for seqNum, msg := range msgs {
		seq := uint32(seqNum + 1)

		if uid {
			if !seqset.Contains(msg.UID) {
				continue
			}
		} else if !seqset.Contains(seq) {
			continue
		}

		_, _, err := storage.InsertMessage(ctx, m.user.db, destBox.ID, msg.BlobKey,
			msg.Size, msg.FromAddr, msg.ToAddr, msg.Subject, msg.Flags)
		if err != nil {
			return err
		}
	}
	m.notifier.Notify(m.mailboxID)
	if destBox.ID != m.mailboxID {
		m.notifier.Notify(destBox.ID)
	}
	return nil
}

// Expunge removes messages flagged with \Deleted.
func (m *Mailbox) Expunge() error {
	ctx := context.TODO()
	msgs, err := storage.ListMessages(ctx, m.user.db, m.mailboxID, 0, 0)
	if err != nil {
		return err
	}
	for _, msg := range msgs {
		if msg.Flags&flagDeleted != 0 {
			if err := storage.DeleteMessage(ctx, m.user.db, msg.ID); err != nil {
				return err
			}
		}
	}
	m.notifier.Notify(m.mailboxID)
	return nil
}

// Idle subscribes to mailbox notifications and waits for changes or a stop signal.
// When a change occurs, it sends on the changes channel to wake the IMAP server.
func (m *Mailbox) Idle(stop <-chan struct{}, changes chan<- struct{}) error {
	ch := m.notifier.Subscribe(m.mailboxID)
	defer m.notifier.Unsubscribe(m.mailboxID, ch)

	select {
	case <-ch:
		// Notify the IMAP server that there are new changes.
		changes <- struct{}{}
	case <-stop:
		// Client sent DONE.
	}
	return nil
}

// IdleDone is called after the IDLE command finishes.
func (m *Mailbox) IdleDone() error {
	return nil
}

// Internal flag bitmask constants matching IMAP flags.
const (
	flagSeen     = 1 << iota
	flagAnswered
	flagFlagged
	flagDeleted
	flagDraft
)

func flagsToBits(flags []string) int {
	var bits int
	for _, f := range flags {
		switch f {
		case imap.SeenFlag:
			bits |= flagSeen
		case imap.AnsweredFlag:
			bits |= flagAnswered
		case imap.FlaggedFlag:
			bits |= flagFlagged
		case imap.DeletedFlag:
			bits |= flagDeleted
		case imap.DraftFlag:
			bits |= flagDraft
		}
	}
	return bits
}

func flagsToIMAP(bits int) []string {
	var flags []string
	if bits&flagSeen != 0 {
		flags = append(flags, imap.SeenFlag)
	}
	if bits&flagAnswered != 0 {
		flags = append(flags, imap.AnsweredFlag)
	}
	if bits&flagFlagged != 0 {
		flags = append(flags, imap.FlaggedFlag)
	}
	if bits&flagDeleted != 0 {
		flags = append(flags, imap.DeletedFlag)
	}
	if bits&flagDraft != 0 {
		flags = append(flags, imap.DraftFlag)
	}
	return flags
}
