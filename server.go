package gracehttp

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/labstack/gommon/log"
)

const (
	// GracefulEnvironKey GracefulEnvironKey
	GracefulEnvironKey = "IS_GRACEFUL"
	// GracefulEnvironString GracefulEnvironString
	GracefulEnvironString = GracefulEnvironKey + "=1"
	// GracefulListenerFd GracefulListenerFd
	GracefulListenerFd = 3
)

// Server HTTP server that supported graceful shutdown or restart
type Server struct {
	httpServer *http.Server
	listener   net.Listener

	isGraceful   bool
	signalChan   chan os.Signal
	shutdownChan chan bool
}

// NewServer NewServer
func NewServer(addr string, handler http.Handler, readTimeout, writeTimeout time.Duration) *Server {
	isGraceful := false
	if os.Getenv(GracefulEnvironKey) != "" {
		isGraceful = true
	}

	return &Server{
		httpServer: &http.Server{
			Addr:    addr,
			Handler: handler,

			ReadTimeout:  readTimeout,
			WriteTimeout: writeTimeout,
		},

		isGraceful:   isGraceful,
		signalChan:   make(chan os.Signal),
		shutdownChan: make(chan bool),
	}
}

// ListenAndServe ListenAndServe
func (srv *Server) ListenAndServe() error {
	addr := srv.httpServer.Addr
	if addr == "" {
		addr = ":http"
	}

	ln, err := srv.getNetListener(addr)
	if err != nil {
		return err
	}

	srv.listener = ln
	return srv.Serve()
}

// ListenAndServeTLS ListenAndServeTLS
func (srv *Server) ListenAndServeTLS(certFile, keyFile string) error {
	addr := srv.httpServer.Addr
	if addr == "" {
		addr = ":https"
	}

	config := &tls.Config{}

	if srv.httpServer.TLSConfig != nil {
		*config = *srv.httpServer.TLSConfig
	}

	if config.NextProtos == nil {
		config.NextProtos = []string{"http/1.1"}
	}

	var err error
	config.Certificates = make([]tls.Certificate, 1)
	config.Certificates[0], err = tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}

	ln, err := srv.getNetListener(addr)
	if err != nil {
		return err
	}

	srv.listener = tls.NewListener(ln, config)
	return srv.Serve()
}

// Serve Serve
func (srv *Server) Serve() error {
	go srv.handleSignals()
	err := srv.httpServer.Serve(srv.listener)

	srv.logf("waiting for connections closed.")
	<-srv.shutdownChan
	srv.logf("all connections closed.")

	return err
}

// getNetListener getNetListener
func (srv *Server) getNetListener(addr string) (net.Listener, error) {
	var ln net.Listener
	var err error

	if srv.isGraceful {
		file := os.NewFile(GracefulListenerFd, "")
		ln, err = net.FileListener(file)
		if err != nil {
			err = fmt.Errorf("net.FileListener error: %v", err)
			return nil, err
		}
	} else {
		ln, err = net.Listen("tcp", addr)
		if err != nil {
			err = fmt.Errorf("net.Listen error: %v", err)
			return nil, err
		}
	}
	return ln, nil
}

func (srv *Server) handleSignals() {
	var sig os.Signal

	signal.Notify(
		srv.signalChan,
		syscall.SIGTERM,
		syscall.SIGUSR2,
	)

	for {
		sig = <-srv.signalChan
		switch sig {
		// SIGTERM	15	Term	结束程序(可以被捕获、阻塞或忽略)
		case syscall.SIGTERM:
			srv.logf("received SIGTERM, graceful shutting down HTTP server.")
			srv.shutdownHTTPServer()
		// SIGHUP	1	Term	终端控制进程结束(终端连接断开)
		case syscall.SIGHUP:
			srv.logf("received SIGHUP, graceful shutting down HTTP server.")
			srv.shutdownHTTPServer()
		// SIGINT	2	Term	用户发送INTR字符(Ctrl+C)触发
		case syscall.SIGINT:
			srv.logf("received SIGINT, graceful shutting down HTTP server.")
			srv.shutdownHTTPServer()
		// SIGUSR2	31,12,17	Term	用户保留
		case syscall.SIGUSR2:
			srv.logf("received SIGUSR2, graceful restarting HTTP server.")

			if pid, err := srv.startNewProcess(); err != nil {
				srv.logf("start new process failed: %v, continue serving.", err)
			} else {
				srv.logf("start new process successed, the new pid is %d.", pid)
				srv.shutdownHTTPServer()
			}
		default:
		}
	}
}

func (srv *Server) shutdownHTTPServer() {
	if err := srv.httpServer.Shutdown(context.Background()); err != nil {
		srv.logf("HTTP server shutdown error: %v", err)
	} else {
		srv.logf("HTTP server shutdown success.")
		srv.shutdownChan <- true
	}
}

// start new process to handle HTTP Connection
func (srv *Server) startNewProcess() (uintptr, error) {
	listenerFd, err := srv.getTCPListenerFd()
	if err != nil {
		return 0, fmt.Errorf("failed to get socket file descriptor: %v", err)
	}

	// set graceful restart env flag
	envs := []string{}
	for _, value := range os.Environ() {
		if value != GracefulEnvironString {
			envs = append(envs, value)
		}
	}
	envs = append(envs, GracefulEnvironString)

	execSpec := &syscall.ProcAttr{
		Env:   envs,
		Files: []uintptr{os.Stdin.Fd(), os.Stdout.Fd(), os.Stderr.Fd(), listenerFd},
	}

	fork, err := syscall.ForkExec(os.Args[0], os.Args, execSpec)
	if err != nil {
		return 0, fmt.Errorf("failed to forkexec: %v", err)
	}

	return uintptr(fork), nil
}

func (srv *Server) getTCPListenerFd() (uintptr, error) {
	file, err := srv.listener.(*net.TCPListener).File()
	if err != nil {
		return 0, err
	}
	return file.Fd(), nil
}

func (srv *Server) logf(format string, args ...interface{}) {
	pids := strconv.Itoa(os.Getpid())
	format = "[pid " + pids + "] " + format

	if srv.httpServer.ErrorLog != nil {
		srv.httpServer.ErrorLog.Printf(format, args...)
	} else {
		log.Infof(format, args...)
	}
}
