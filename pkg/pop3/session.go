package pop3

import (
	"bufio"
	"context"
	"crypto/md5"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/i-got-this-faa/marco/pkg/storage"
)

// POP3 protocol states.
const (
	stateAuthorization = iota
	stateTransaction
	stateUpdate
)

// Session represents a single POP3 client connection.
type Session struct {
	srv    *Server
	conn   net.Conn
	br     *bufio.Reader
	bw     *bufio.Writer
	log    *slog.Logger
	state  int
	userID int64
	email  string
	// set of message IDs marked for deletion in this session
	markedDeleted map[int64]bool
	// APOP challenge timestamp
	apopTimestamp string
	// whether the connection is TLS-secured
	secured bool
	// tracks whether the next byte is the start of a line (for dot-stuffing)
	startOfLine bool
}

func (s *Session) handle() {
	// Generate timestamp for APOP challenge.
	s.apopTimestamp = fmt.Sprintf("<%d.%s@marco>", time.Now().UnixNano(), s.srv.cfg.ListenAddr)

	// Send greeting.
	s.writeLine("+OK Marco POP3 server ready [%s]", s.apopTimestamp)
	s.state = stateAuthorization
	s.markedDeleted = make(map[int64]bool)

	for {
		line, err := s.br.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")

		if line == "" {
			continue
		}

		parts := strings.SplitN(line, " ", 2)
		cmd := strings.ToUpper(parts[0])
		var arg string
		if len(parts) > 1 {
			arg = parts[1]
		}

		if !s.handleCommand(cmd, arg) {
			return
		}
	}
}

// handleCommand processes a single POP3 command. Returns false if the
// connection should be closed.
func (s *Session) handleCommand(cmd, arg string) bool {
	switch cmd {
	case "QUIT":
		return s.handleQUIT()
	case "CAPA":
		return s.handleCAPA()
	}

	// Authorization state: only a few commands allowed.
	if s.state == stateAuthorization {
		switch cmd {
		case "USER":
			return s.handleUSER(arg)
		case "PASS":
			return s.handlePASS(arg)
		case "APOP":
			return s.handleAPOP(arg)
		case "STLS":
			return s.handleSTLS()
		default:
			s.writeLine("-ERR Authorization required")
			return true
		}
	}

	// Transaction state commands.
	switch cmd {
	case "STAT":
		return s.handleSTAT()
	case "LIST":
		return s.handleLIST(arg)
	case "RETR":
		return s.handleRETR(arg)
	case "DELE":
		return s.handleDELE(arg)
	case "NOOP":
		s.writeLine("+OK")
		return true
	case "RSET":
		return s.handleRSET()
	case "TOP":
		return s.handleTOP(arg)
	case "UIDL":
		return s.handleUIDL(arg)
	default:
		s.writeLine("-ERR Unknown command")
		return true
	}
}

// handleUSER processes the USER command.
func (s *Session) handleUSER(email string) bool {
	if email == "" {
		s.writeLine("-ERR Missing username")
		return true
	}
	s.email = email
	s.writeLine("+OK Welcome, %s", email)
	return true
}

// handlePASS processes the PASS command.
func (s *Session) handlePASS(password string) bool {
	if s.email == "" {
		s.writeLine("-ERR No USER provided first")
		return true
	}
	if password == "" {
		s.writeLine("-ERR Missing password")
		return true
	}

	userID, err := s.srv.am.Authenticate(context.Background(), s.email, password)
	if err != nil {
		s.writeLine("-ERR Authentication failed")
		s.email = ""
		return true
	}

	s.userID = userID
	s.state = stateTransaction
	s.writeLine("+OK Authentication successful")
	return true
}

// handleAPOP processes the APOP command.
func (s *Session) handleAPOP(arg string) bool {
	if s.srv.cfg.APOPSecret == "" {
		s.writeLine("-ERR APOP not configured")
		return true
	}

	parts := strings.SplitN(arg, " ", 2)
	if len(parts) != 2 {
		s.writeLine("-ERR Usage: APOP <user> <digest>")
		return true
	}
	email := parts[0]
	digest := parts[1]

	expected := fmt.Sprintf("%x", md5.Sum([]byte(s.apopTimestamp+s.srv.cfg.APOPSecret)))
	if !strings.EqualFold(digest, expected) {
		s.writeLine("-ERR APOP authentication failed")
		return true
	}

	user, err := storage.GetUserByEmail(context.Background(), s.srv.db, email)
	if err != nil {
		s.writeLine("-ERR APOP authentication failed")
		return true
	}

	s.userID = user.ID
	s.email = email
	s.state = stateTransaction
	s.writeLine("+OK APOP authentication successful")
	return true
}

// handleSTLS upgrades the connection to TLS.
func (s *Session) handleSTLS() bool {
	if s.secured {
		s.writeLine("-ERR Already using TLS")
		return true
	}
	if s.srv.tlsCfg == nil {
		s.writeLine("-ERR TLS not configured")
		return true
	}
	s.writeLine("+OK Begin TLS negotiation")

	tlsConn := tls.Server(s.conn, s.srv.tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		s.writeLine("-ERR TLS handshake failed")
		return true
	}
	s.conn = tlsConn
	s.br = bufio.NewReader(tlsConn)
	s.bw = bufio.NewWriter(tlsConn)
	s.secured = true
	return true
}

// handleCAPA lists capabilities.
func (s *Session) handleCAPA() bool {
	s.writeLine("+OK Capability list follows")
	s.writeLine("TOP")
	s.writeLine("USER")
	s.writeLine("UIDL")
	if s.srv.cfg.APOPSecret != "" {
		s.writeLine("APOP")
	}
	if s.srv.tlsCfg != nil && !s.secured {
		s.writeLine("STLS")
	}
	s.writeLine("IMPLEMENTATION Marco POP3")
	s.writeLine(".")
	return true
}

// handleSTAT returns mailbox status.
func (s *Session) handleSTAT() bool {
	mbox, err := s.getINBOX()
	if err != nil {
		s.writeLine("-ERR %s", err)
		return true
	}

	count, err := storage.CountMessages(context.Background(), s.srv.db, mbox.ID)
	if err != nil {
		s.writeLine("-ERR Cannot get mailbox status")
		return true
	}

	msgs, err := storage.ListMessages(context.Background(), s.srv.db, mbox.ID, 0, 0)
	if err != nil {
		s.writeLine("-ERR Cannot get mailbox status")
		return true
	}

	var totalSize int64
	for _, msg := range msgs {
		totalSize += msg.Size
	}

	s.writeLine("+OK %d %d", count, totalSize)
	return true
}

// handleLIST returns message listings.
func (s *Session) handleLIST(arg string) bool {
	mbox, err := s.getINBOX()
	if err != nil {
		s.writeLine("-ERR %s", err)
		return true
	}

	msgs, err := storage.ListMessages(context.Background(), s.srv.db, mbox.ID, 0, 0)
	if err != nil {
		s.writeLine("-ERR Cannot list messages")
		return true
	}

	if arg != "" {
		uid, err := strconv.ParseUint(arg, 10, 32)
		if err != nil {
			s.writeLine("-ERR Invalid message number")
			return true
		}
		for _, msg := range msgs {
			if uint32(uid) == msg.UID {
				s.writeLine("+OK %d %d", msg.UID, msg.Size)
				return true
			}
		}
		s.writeLine("-ERR No such message")
		return true
	}

	s.writeLine("+OK %d messages", len(msgs))
	for _, msg := range msgs {
		s.writeLine("%d %d", msg.UID, msg.Size)
	}
	s.writeLine(".")
	return true
}

// handleRETR retrieves a message.
func (s *Session) handleRETR(arg string) bool {
	if arg == "" {
		s.writeLine("-ERR Missing message number")
		return true
	}

	uid, err := strconv.ParseUint(arg, 10, 32)
	if err != nil {
		s.writeLine("-ERR Invalid message number")
		return true
	}

	msg, err := s.getMessageByUID(uint32(uid))
	if err != nil {
		s.writeLine("-ERR %s", err)
		return true
	}

	blob, err := s.srv.blob.Get(context.Background(), msg.BlobKey)
	if err != nil {
		s.writeLine("-ERR Cannot retrieve message")
		return true
	}
	defer blob.Close()

	s.writeLine("+OK %d octets", msg.Size)

	// Write blob content to client, dot-stuffing lines starting with ".".
	// Read blob in chunks.
	buf := make([]byte, 4096)
	for {
		n, err := blob.Read(buf)
		if n > 0 {
			if err := s.dotStuffWrite(buf[:n]); err != nil {
				slog.Warn("pop3 retr write error", "error", err)
				return true
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			slog.Warn("pop3 retr read error", "error", err)
			return true
		}
	}
	_ = s.bw.Flush()

	s.writeLine(".")
	return true
}

// handleDELE marks a message for deletion.
func (s *Session) handleDELE(arg string) bool {
	if arg == "" {
		s.writeLine("-ERR Missing message number")
		return true
	}

	uid, err := strconv.ParseUint(arg, 10, 32)
	if err != nil {
		s.writeLine("-ERR Invalid message number")
		return true
	}

	msg, err := s.getMessageByUID(uint32(uid))
	if err != nil {
		s.writeLine("-ERR %s", err)
		return true
	}

	// Set the \Deleted flag.
	if err := storage.UpdateFlags(context.Background(), s.srv.db, msg.ID, storage.FlagDeleted, storage.FlagDeleted); err != nil {
		s.writeLine("-ERR Cannot mark message for deletion")
		return true
	}

	s.markedDeleted[msg.ID] = true
	s.writeLine("+OK Message %d marked for deletion", msg.UID)
	return true
}

// handleRSET clears all deletion marks.
func (s *Session) handleRSET() bool {
	// Clear all deletion marks from this session.
	for msgID := range s.markedDeleted {
		_ = storage.UpdateFlags(context.Background(), s.srv.db, msgID, 0, storage.FlagDeleted)
	}
	s.markedDeleted = make(map[int64]bool)
	s.writeLine("+OK")
	return true
}

// handleTOP returns headers and top n lines of a message.
func (s *Session) handleTOP(arg string) bool {
	if arg == "" {
		s.writeLine("-ERR Usage: TOP <msg> <n>")
		return true
	}

	parts := strings.SplitN(arg, " ", 2)
	if len(parts) != 2 {
		s.writeLine("-ERR Usage: TOP <msg> <n>")
		return true
	}

	uid, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		s.writeLine("-ERR Invalid message number")
		return true
	}

	n, err := strconv.Atoi(parts[1])
	if err != nil || n < 0 {
		s.writeLine("-ERR Invalid line count")
		return true
	}

	msg, err := s.getMessageByUID(uint32(uid))
	if err != nil {
		s.writeLine("-ERR %s", err)
		return true
	}

	blob, err := s.srv.blob.Get(context.Background(), msg.BlobKey)
	if err != nil {
		s.writeLine("-ERR Cannot retrieve message")
		return true
	}
	defer blob.Close()

	body, err := io.ReadAll(blob)
	if err != nil {
		s.writeLine("-ERR Error reading message")
		return true
	}

	// Split headers and body at \r\n\r\n or \n\n.
	headerEnd := strings.Index(string(body), "\r\n\r\n")
	bodyStart := headerEnd + 4
	if headerEnd < 0 {
		headerEnd = strings.Index(string(body), "\n\n")
		bodyStart = headerEnd + 2
	}
	if headerEnd < 0 {
		// No body, just headers.
		bodyStart = len(body)
		headerEnd = len(body)
	}

	headers := body[:headerEnd]
	bodyContent := body[bodyStart:]

	s.writeLine("+OK")
	// Write headers.
	s.bw.Write(headers)
	s.bw.WriteString("\r\n")

	// Write top n lines of body.
	linesWritten := 0
	for _, line := range strings.Split(string(bodyContent), "\n") {
		if linesWritten >= n {
			break
		}
		line = strings.TrimRight(line, "\r")
		// Dot-stuff.
		if strings.HasPrefix(line, ".") {
			s.bw.WriteString(".")
		}
		s.bw.WriteString(line)
		s.bw.WriteString("\r\n")
		linesWritten++
	}

	s.writeLine(".")
	return true
}

// handleUIDL returns unique ID listing.
func (s *Session) handleUIDL(arg string) bool {
	mbox, err := s.getINBOX()
	if err != nil {
		s.writeLine("-ERR %s", err)
		return true
	}

	msgs, err := storage.ListMessages(context.Background(), s.srv.db, mbox.ID, 0, 0)
	if err != nil {
		s.writeLine("-ERR Cannot list messages")
		return true
	}

	if arg != "" {
		uid, err := strconv.ParseUint(arg, 10, 32)
		if err != nil {
			s.writeLine("-ERR Invalid message number")
			return true
		}
		for _, msg := range msgs {
			if uint32(uid) == msg.UID {
				s.writeLine("+OK %d %s", msg.UID, msg.BlobKey)
				return true
			}
		}
		s.writeLine("-ERR No such message")
		return true
	}

	s.writeLine("+OK")
	for _, msg := range msgs {
		s.writeLine("%d %s", msg.UID, msg.BlobKey)
	}
	s.writeLine(".")
	return true
}

// handleQUIT processes the QUIT command and performs cleanup.
func (s *Session) handleQUIT() bool {
	// Expunge deleted messages.
	if len(s.markedDeleted) > 0 {
		mbox, err := s.getINBOX()
		if err == nil {
			storage.ExpungeMailbox(context.Background(), s.srv.db, mbox.ID)
		}
	}

	s.writeLine("+OK Bye")
	s.bw.Flush()
	return false
}

// getINBOX retrieves the INBOX for the authenticated user.
func (s *Session) getINBOX() (*storage.Mailbox, error) {
	return storage.GetMailbox(context.Background(), s.srv.db, s.userID, "INBOX")
}

// getMessageByUID retrieves a message by UID in the user's INBOX.
func (s *Session) getMessageByUID(uid uint32) (*storage.Message, error) {
	mbox, err := s.getINBOX()
	if err != nil {
		return nil, fmt.Errorf("no INBOX: %w", err)
	}
	return storage.GetMessageByUID(context.Background(), s.srv.db, mbox.ID, uid)
}

// writeLine writes a formatted line to the client, terminated by \r\n.
func (s *Session) writeLine(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	s.bw.WriteString(msg)
	s.bw.WriteString("\r\n")
	_ = s.bw.Flush()
}


// dotStuffWrite writes data to the buffered writer, dot-stuffing any lines
// that start with "." by prepending another ".".
func (s *Session) dotStuffWrite(data []byte) error {
	for i, b := range data {
		if s.startOfLine && b == '.' {
			if _, err := s.bw.Write([]byte("..")); err != nil {
				return err
			}
			s.startOfLine = false
			continue
		}
		if _, err := s.bw.Write(data[i : i+1]); err != nil {
			return err
		}
		s.startOfLine = (b == '\n')
	}
	return nil
}
