package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/rs/xid"
	"github.com/LDCS/sflag"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

type void struct{}

type Event string

type ReaperEventType int

const (
	_ ReaperEventType = iota

	R_ACQUIRED
	R_FREED
	R_DEAD

	R_PRESSURE
)

type ClientStatus int

func (s ClientStatus) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"%s"`, s.String())), nil
}

const (
	C_UNKNOWN ClientStatus = iota

	C_TERMINATED
	C_PENDING
	C_RUNNING
	C_DEAD
	C_DONE
)

func (s ClientStatus) String() string {
	switch s {
	case C_TERMINATED:
		return "terminated"
	case C_PENDING:
		return "pending"
	case C_RUNNING:
		return "running"
	case C_DEAD:
		return "dead"
	case C_DONE:
		return "done"
	}
	return "unknown"
}

type ReaperEvent struct {
	key   string
	event ReaperEventType
}

type Connection struct {
	key  string
	user string
	host string

	client *ssh.Client

	IsDead     bool
	lastEvent  time.Time
	refCounter int
}

func (c *Connection) Start() (err error) {
	if c.client != nil && c.IsDead == false {
		return nil // already started
	}

	c.client, err = ssh.Dial(
		"tcp",
		net.JoinHostPort(c.host, "22"),
		&ssh.ClientConfig{
			User: c.user,
			Auth: SSHConfig.Auth,
		},
	)

	if err != nil {
		c.IsDead = true
		log.Printf("Cannot create a client (user %s): %v\n", c.user, err)
		ReaperQueue <- ReaperEvent{c.key, R_DEAD}
		return err
	}

	return nil
}

func (c *Connection) Close() (err error) {
	if c.client == nil || c.IsDead == true {
		return nil // already closed
	}

	c.IsDead = true
	err = c.client.Close()
	<- MaxConnections
	return err
}

type SessionWriter struct {
	session    *Session
	connection *Connection
	kind       string
}

type SessionReader chan string

func (sw *SessionWriter) Write(p []byte) (int, error) {
	sw.connection.lastEvent = time.Now()
	if len(p) < 1 {
		return 0, nil
	}
	s := string(p)
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	sw.session.Queue <- Event(fmt.Sprintf("[%q, %s, %s]", sw.connection.key, sw.kind, b))
	return len(p), nil
}

func (c SessionReader) Read(p []byte) (int, error) {
	if len(p) < 1 {
		return 0, nil
	}
	data, ok := <-c
	if !ok {
		return 0, io.EOF
	}
	n := copy(p, data)
	if len(p) == n {
		return n, nil
	}
	for n < len(p) {
		data, ok = <-c
		if !ok {
			break
		}
		n += copy(p[n:], data)
	}
	return n, nil
}

func (c *Connection) Run(s *Session, cmd string, cancel chan void) (err error) {
	defer s.Done()

	if c.IsDead {
		s.Queue <- Event(fmt.Sprintf(`[%q, "dead", null]`, c.key))
		return ErrConnectionIsDead
	}

	c.lastEvent = time.Now()

	ReaperQueue <- ReaperEvent{c.key, R_ACQUIRED}

	s.Lock()
	s.Status[c.key] = C_RUNNING
	s.Unlock()

	ch, err := c.client.NewSession()
	if err != nil {
		ReaperQueue <- ReaperEvent{c.key, R_DEAD}
		c.IsDead = true
		log.Printf("Cannot create new session: %v\n", err)
		return err
	}

	if s.Interactive {
		modes := ssh.TerminalModes{
			ssh.ECHO:          0,     // disable echoing
			ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
			ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
		}

		if err := ch.RequestPty("xterm", 80, 25, modes); err != nil {
			log.Printf("Cannot request PTY: %v", err)
			ch.Close()
			return err
		}
	}

	stdin := make(chan string)
	ch.Stdin = SessionReader(stdin)
	ch.Stdout = &SessionWriter{s, c, "null"}
	ch.Stderr = &SessionWriter{s, c, "1"}

	s.Lock()
	s.stdins[c.key] = &stdin
	s.Unlock()

	err = ch.Start(cmd)
	if err != nil {
		ReaperQueue <- ReaperEvent{c.key, R_DEAD}
		c.IsDead = true
		log.Printf("Cannot start ssh session: %v\n", err)
		return err
	}

	errChan := make(chan error)

	go func(c chan<- error) {
		c <- ch.Wait()
	}(errChan)

	err = nil

	select {
	case err = <-errChan:
		rc := 255
		if err == nil {
			rc = 0
			err = ch.Close()
		} else if exitError, ok := err.(*exec.ExitError); ok {
			waitStatus := exitError.Sys().(syscall.WaitStatus)
			rc = waitStatus.ExitStatus()
			err = ch.Close()
		}

		s.Queue <- Event(fmt.Sprintf(`[%q, "exit", %d]`, c.key, rc))
		log.Printf("Done.\n")
		s.Lock()
		s.Status[c.key] = C_DONE
		s.Unlock()

	case <-cancel:
		s.Lock()
		s.Status[c.key] = C_TERMINATED
		s.Unlock()

		s.Queue <- Event(fmt.Sprintf(`[%q, "exit", 255]`, c.key))

		log.Printf("Terminating SSH session (%s)…\n", c.key)
		if err = ch.Signal(ssh.SIGINT); err != nil {
			log.Printf("Cannot signal: %v\n", err)
		}
		if err = ch.Signal(ssh.SIGTERM); err != nil {
			log.Printf("Cannot signal: %v\n", err)
		}
		if err = ch.Signal(ssh.SIGKILL); err != nil {
			log.Printf("Cannot signal: %v\n", err)
		}
		if err = ch.Close(); err != nil {
			log.Printf("Cannot close: %v\n", err)
		}
	}

	s.Lock()
	delete(s.stdins, c.key)
	s.Unlock()

	close(stdin)

	if err != nil && err != io.EOF {
		ReaperQueue <- ReaperEvent{c.key, R_DEAD}
		c.IsDead = true
		log.Println(err)
		return err
	}

	ReaperQueue <- ReaperEvent{c.key, R_FREED}

	return nil
}

type Session struct {
	Queue chan Event `json:"-"`
	Id    string     `json:"id"`

	IsDead      bool `json:"dead"`
	children    []*Connection
	stdins      map[string]*chan string
	Status      map[string]ClientStatus `json:"children"`
	terminator  chan string
	Interactive bool

	sync.Mutex
	sync.WaitGroup
}

func (s Session) Dead() bool {
	return s.IsDead
}

func (s *Session) SetHosts(hosts []string) {
	var user, host string
	default_user := os.Getenv("LOGNAME")

	s.Lock()
	defer s.Unlock()

	for _, h := range hosts {
		parts := strings.SplitN(h, "@", 2)
		switch len(parts) {
		case 0:
			continue
		case 1:
			user = default_user
			host = parts[0]
		case 2:
			user = parts[0]
			host = parts[1]
		}
		Clock.RLock()
		c, ok := Connections[h]
		Clock.RUnlock()

		if !ok {
			log.Printf("Creating a new connection for %s@%s…\n", user, host)
			c = &Connection{key: h, user: user, host: host}
			Clock.Lock()
			Connections[h] = c
			Clock.Unlock()
		}

		s.children = append(s.children, c)
		s.Status[h] = C_UNKNOWN
	}
}

func (s *Session) Run(cmd string) {
	s.Lock()
	s.IsDead = false
	s.Unlock()

	channels := make(map[string]chan void)

	go func() {
		for token := range s.terminator {
			s.Lock()
			IsDead := s.IsDead
			s.Unlock()

			if IsDead {
				log.Println("Session terminator is redundant.")
				break
			}

			log.Printf("Terminating session %s with token %s…\n", s.Id, token)

			if token == "all" {
				s.Lock()
				s.IsDead = true
				s.Unlock()
			}

			for _, c := range s.children {
				k := c.key
				if k != token && token != "all" {
					continue
				}
				log.Printf("Terminating channel %s...\n", k)
				s.Lock()
				st := s.Status[k]
				if st == C_RUNNING || st == C_PENDING || st == C_UNKNOWN {
					s.Status[k] = C_TERMINATED
				}
				s.Unlock()
				switch st {
				case C_RUNNING:
					channels[k] <- void{}
				case C_PENDING:
					fallthrough
				case C_UNKNOWN:
					s.Lock()
					s.Queue <- Event(fmt.Sprintf(`[%q, "error", "killed"]`, k))
					s.Queue <- Event(fmt.Sprintf(`[%q, "exit", 255]`, k))
					c.Close()
					s.Unlock()
				default:
					log.Printf("Job %s was in state %s, cannot terminate.\n", k, st)
				}
			}
		}
	}() // terminator reader

	for _, c := range s.children {
		s.Lock()
		isDead := s.IsDead
		isTerminated := s.Status[c.key] == C_TERMINATED
		s.Unlock()
		if isDead {
			break
		}

		if isTerminated { 
			log.Printf("Skipping %s due to termination status.\n", c.key)
			s.Queue <- Event(fmt.Sprintf(`[%q, "error", "killed"]`, c.key))
			continue
		} else {
			s.Add(1)
		}

		select {
		case MaxConnections <- void{}:
			// we still have at least one vacant slot
		default:
			ReaperQueue <- ReaperEvent{"", R_PRESSURE}
			MaxConnections <- void{}
		}
		go func(c *Connection) {
			s.Lock()
			s.Status[c.key] = C_PENDING
			s.Unlock()
			err := c.Start()
			if err != nil {
				<- MaxConnections
				s.Lock()
				isDead := s.IsDead
				s.Status[c.key] = C_DEAD
				s.Unlock()
				if ! isDead {
					log.Printf("Start failed: %v\n", err)
					s.Queue <- Event(fmt.Sprintf(`[%q, "error", %q]`, c.key, err))
					s.Queue <- Event(fmt.Sprintf(`[%q, "exit", 255]`, c.key))
					s.Done()
					return
				}
			}
			s.Lock()
			channels[c.key] = make(chan void)
			s.Unlock()
			go c.Run(s, cmd, channels[c.key])
		}(c)
	}

	go func() {
		s.Wait()
		log.Printf("Session %s is done.\n", s.Id)

		s.Lock()
		s.Queue <- `[null, "done", null]`
		s.IsDead = true
		s.children = nil
		// s.Status = nil
		s.Unlock()
	}() // session reaper
}

var (
	ErrNoSuchSession     = errors.New("No such session")
	ErrSessionInProgress = errors.New("This session is already running")
	ErrConnectionIsDead  = errors.New("Connection is dead")
	ErrTerminated        = errors.New("SSH session has been terminated")
	ErrSSHNoAuthMethods  = errors.New("No valid SSH authentication methods found")
	SSHConfig            = &ssh.ClientConfig{
		User: os.Getenv("LOGNAME"),
	}
	Connections = make(map[string]*Connection)
	Clock       = sync.RWMutex{}
	ReaperQueue = make(chan ReaperEvent)
	Sessions    = make(map[string]*Session)
	Slock       = sync.RWMutex{}
	HomeDir     = "/root"
)

var MaxConnections chan void

func SSHAgent() (ssh.AuthMethod, error) {
	sshAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		return nil, err
	}
	return ssh.PublicKeysCallback(agent.NewClient(sshAgent).Signers), nil
}

func makeSigner(keyname string) (signer ssh.Signer, err error) {
	fp, err := os.Open(keyname)
	if err != nil {
		return
	}
	defer fp.Close()

	buf, err := ioutil.ReadAll(fp)
	if err != nil { return }
	signer, err = ssh.ParsePrivateKey(buf)
	return
}

func makeKeyring() (signers []ssh.AuthMethod, err error) {
	var signer ssh.Signer

	keys := []string{HomeDir + "/.ssh/id_ed25519", HomeDir + "/.ssh/id_rsa", HomeDir + "/.ssh/id_dsa"}

	for _, keyname := range keys {
		signer, err = makeSigner(keyname)
		if err != nil { continue }
		signers = append(signers, ssh.PublicKeys(signer))
	}
	return
}

func SSHAuth() []ssh.AuthMethod {
	methods := []ssh.AuthMethod{}
	
	m, err := SSHAgent()
	if err != nil {
		log.Println("Cannot connect to SSH agent, trying local keys.")
	} else {
		methods = append(methods, m)
	}

	if err != nil {
		ms, err := makeKeyring()
		if err != nil {
			log.Println(err)
		} else {
			methods = append(methods, ms...)
		}
	}

	if Config.Password != "" {
		methods = append(methods, ssh.Password(Config.Password))
	}

	if len(methods) == 0 {
		panic(ErrSSHNoAuthMethods)
	}

	return methods
}

type SessionParams struct {
	Keys        []string
	Interactive bool
}

type logWriter struct {
}

func (writer logWriter) Write(bytes []byte) (int, error) {
	return fmt.Print(time.Now().UTC().Format("2006-01-02T15:04:05.999Z") + " " + string(bytes))
}

func NewSession(id string, hosts []string) *Session {
	sess := &Session{Id: id}
	sess.terminator = make(chan string, 4)
	sess.Queue = make(chan Event, 512)
	sess.IsDead = true
	sess.Status = make(map[string]ClientStatus)
	sess.stdins = make(map[string]*chan string)
	sess.SetHosts(hosts)

	Slock.Lock()
	Sessions[id] = sess
	Slock.Unlock()

	return sess
}

var Config = struct {
	Server string "IP to listen on | ::1"
	ServerPort string "Port | 53353"
	Password string "User password"
	MaxConnections int "Maximum number of concurrent connections | 512"
	MaxPersist int "Maximum time for a connection to persist (in seconds) | 30"
}{}

func ConnectionReaper() {
	freeTimers := make(map[string]*time.Timer)
	var conn *Connection

	for e := range ReaperQueue {
		Clock.Lock()
		if e.key != "" {
			conn = Connections[e.key]
			if conn == nil {
				panic("reaper got invalid key")
			}
		} else {
			conn = nil
		}
		switch e.event {
		case R_DEAD:
			log.Printf("Reaping dead connection %s…\n", e.key)
			delete(Connections, e.key)
			t, ok := freeTimers[e.key]
			if ok {
				t.Stop()
			}
		case R_ACQUIRED:
			conn.refCounter += 1
			t, ok := freeTimers[e.key]
			if ok {
				t.Stop()
			}
		case R_FREED:
			conn.refCounter -= 1
			if conn.refCounter == 0 {
				log.Printf("Connection %s is now freed.\n", e.key)
				k := e.key
				n := cap(MaxConnections) - len(MaxConnections)
				if Config.MaxPersist > 0 && n > Config.MaxPersist {
					n = Config.MaxPersist
				}
				c := conn
				t := time.AfterFunc(time.Second*time.Duration(n), func() {
					if c.refCounter > 0 {
						log.Printf("Race condition detected for %s.\n", k)
						return
					}
					log.Printf("Going to teardown %s.\n", k)

					Clock.Lock()
					delete(Connections, k)
					Clock.Unlock()

					if err := c.Close(); err != nil {
						log.Printf("Failed to close %s: %v\n", k, err)
					}
				})
				freeTimers[e.key] = t
			}
		case R_PRESSURE:
			log.Println("Pressure is high!")
			oldestK := ""
			oldestV := time.Time{}
			// sort connections by lastEvent
			for k, v := range Connections {
				if v.refCounter > 0 { continue }
				_, ok := freeTimers[k]
				if ! ok { continue }
				if oldestV.IsZero() || v.lastEvent.Before(oldestV) {
					oldestK = k
					oldestV = v.lastEvent
				}
			}
			if oldestK != "" {
				t := freeTimers[oldestK]
				if t == nil { 
					log.Fatalf("No timer for %s!\n", oldestK)
				}
				if !t.Stop() {
					log.Printf("Timer for %s has already fired.\n", oldestK)
				} else {
					log.Printf("Pressure fires timer for %s prematurely.\n", oldestK)
					t.Reset(0)
				}
			} else {
				log.Println("Cannot find a good candidate to stop.")
				log.Println(Connections)
			}
		}
		Clock.Unlock()
	}

	panic("reaper exit")
}

func main() {
	log.SetFlags(0)
	log.SetOutput(new(logWriter))

	gin.SetMode(gin.ReleaseMode)

	router := gin.Default()
	router.GET("/ping", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})
	router.GET("/session/:id/read", func(c *gin.Context) {
		Slock.RLock()
		session, ok := Sessions[c.Param("id")]
		Slock.RUnlock()

		if !ok {
			c.AbortWithError(http.StatusNotFound, ErrNoSuchSession)
			return
		}

		c.Writer.Header().Set("Content-Type", "application/json")
		select {
		case chunk := <-session.Queue:
			// log.Println(chunk)
			c.String(http.StatusOK, string(chunk))
		default:
			session.Lock()
			isDead := session.Dead()
			session.Unlock()
			if isDead {
				c.String(http.StatusOK, `[null, "done", null]`)
			} else {
				chunk := <-session.Queue
				c.String(http.StatusOK, string(chunk))
			}
		}
	})
	router.GET("/session/:id", func(c *gin.Context) {
		Slock.RLock()
		session, ok := Sessions[c.Param("id")]
		Slock.RUnlock()

		if !ok {
			c.AbortWithError(http.StatusNotFound, ErrNoSuchSession)
			return
		}

		session.Lock()
		c.JSON(http.StatusOK, session)
		session.Unlock()
	})
	router.POST("/session/:id", func(c *gin.Context) {
		var sessionParams SessionParams
		if c.Param("id") != "new" {
			c.String(http.StatusNotFound, "expected /new")
			return
		}
		c.Bind(&sessionParams)
		id := xid.New().String()
		sess := NewSession(id, sessionParams.Keys)
		if sessionParams.Interactive {
			sess.Interactive = true
		}
		c.JSON(http.StatusOK, gin.H{"id": id})
	})
	router.POST("/session/:id/write", func(c *gin.Context) {
		Slock.RLock()
		sess, ok := Sessions[c.Param("id")]
		Slock.RUnlock()

		if !ok {
			c.AbortWithError(http.StatusNotFound, ErrNoSuchSession)
			return
		}

		buf := new(bytes.Buffer)
		buf.ReadFrom(c.Request.Body)

		sess.Lock()
		for _, ch := range sess.stdins {
			*ch <- buf.String()
		}
		sess.Unlock()

		c.String(http.StatusOK, "OK")
	})
	router.POST("/session/:id/write/:key", func(c *gin.Context) {
		Slock.RLock()
		sess, ok := Sessions[c.Param("id")]
		Slock.RUnlock()

		if !ok {
			c.AbortWithError(http.StatusNotFound, ErrNoSuchSession)
			return
		}

		buf := new(bytes.Buffer)
		buf.ReadFrom(c.Request.Body)

		sess.Lock()
		ch, ok := sess.stdins[c.Param("key")]
		if ok {
			*ch <- buf.String()
		}
		sess.Unlock()

		if !ok {
			c.AbortWithError(http.StatusNotFound, ErrNoSuchSession)
			return
		}

		c.String(http.StatusOK, "OK")
	})
	router.POST("/session/:id/terminate", func(c *gin.Context) {
		Slock.RLock()
		sess, ok := Sessions[c.Param("id")]
		Slock.RUnlock()

		if !ok {
			c.AbortWithError(http.StatusNotFound, ErrNoSuchSession)
			return
		}

		buf := new(bytes.Buffer)
		buf.ReadFrom(c.Request.Body)
		log.Printf("Terminating key %s of session %s…\n", buf.String(), c.Param("id"))
		sess.terminator <- buf.String()

		c.String(http.StatusOK, "OK")
	})
	router.DELETE("/session/:id", func(c *gin.Context) {
		Slock.RLock()
		sess, ok := Sessions[c.Param("id")]
		Slock.RUnlock()

		if !ok {
			c.String(http.StatusOK, "Already deleted (or never existed).")
			return
		}

		sess.terminator <- "all"

		c.String(http.StatusOK, "OK")
	})
	router.POST("/session/:id/run", func(c *gin.Context) {
		Slock.RLock()
		session, ok := Sessions[c.Param("id")]
		Slock.RUnlock()

		if !ok {
			c.AbortWithError(http.StatusNotFound, ErrNoSuchSession)
			return
		}

		if !session.IsDead {
			c.AbortWithError(http.StatusInternalServerError, ErrSessionInProgress)
			return
		}

		buf := new(bytes.Buffer)
		buf.ReadFrom(c.Request.Body)
		go session.Run(buf.String())
		c.String(http.StatusOK, "OK")
	})
	router.GET("/session", func(c *gin.Context) {
		Slock.RLock()
		c.JSON(http.StatusOK, Sessions)
		Slock.RUnlock()
	})

	go ConnectionReaper()

	usr, err := user.Current()
	if err != nil { panic(err) }
	HomeDir = usr.HomeDir

	for _, name := range []string{".emptyd.conf", ".empty.conf"} {
		raw, err := ioutil.ReadFile(filepath.Join(HomeDir, name))
		if err != nil { continue }
		err = json.Unmarshal(raw, &Config)
		if err != nil { panic(err) }
	}

	sflag.Parse(&Config)

	MaxConnections = make(chan void, Config.MaxConnections)
	SSHConfig.Auth = SSHAuth()

	addr := net.JoinHostPort(Config.Server, Config.ServerPort)
	log.Printf("Starting on %s…", addr)

	panic(router.Run(addr))
}

// vim: ai:ts=8:sw=8:noet:syntax=go
