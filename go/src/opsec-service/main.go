package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"time"

	"github.com/joho/godotenv"
)

// --- GLOBAL VARIABLES & CONSTANTS ---
const LogFilePath = "/var/lib/opsec/opsec_logs.txt"
const TrackingDomain = "https://ancom.space"

// SMTPSenderPass is read from the .env file
var SMTPSenderPass string

// A 1x1 transparent GIF (43 bytes). This is the content served as the tracking pixel.
var trackingPixelGIF = []byte{
	0x47, 0x49, 0x46, 0x38, 0x39, 0x61,
	0x01, 0x00, 0x01, 0x00,
	0x80, 0x00, 0x00,
	0xff, 0xff, 0xff,
	0x21, 0xf9, 0x04,
	0x01, 0x00, 0x00, 0x00, 0x00,
	0x2c, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x01, 0x00,
	0x00,
	0x02, 0x02, 0x44, 0x01, 0x00,
	0x3b,
}

// --- STRUCTS (API) ---
type EmailRequest struct {
	Recipient string `json:"recipient"`
	Message   string `json:"message"`
}

// --- LOGGING FUNCTION (Uses CF-Connecting-IP and X-OPSEC-Signal) ---
func logVisitor(r *http.Request) {
	// 1. Capture Real IP (Passed from Cloudflare via headers)
	realIP := r.Header.Get("CF-Connecting-IP")
	if realIP == "" {
		realIP = r.Header.Get("X-Forwarded-For")
	}
	if realIP == "" {
		realIP = r.RemoteAddr
	}

	// 2. Critical OpSec: We rely on the Nginx-injected secret header
	secretHeader := r.Header.Get("X-OPSEC-Signal")

	eventType := "Web Visit"
	if r.URL.Path == "/" {
		eventType = "Email Open"
	}

	if secretHeader == "Active" || eventType == "Email Open" {
		logEntry := fmt.Sprintf("[%s] EVENT: %s | IP: %s | URL: %s | Agent: %s\n",
			time.Now().Format("2006/01/02 15:04:05"),
			eventType,
			realIP,
			r.URL.Path,
			r.Header.Get("User-Agent"),
		)

		f, err := os.OpenFile(LogFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err == nil {
			defer f.Close()
			f.WriteString(logEntry)
		}
	}
}

// --- EMAIL HANDLER (Direct SMTPS Logic - Fixes SOCKS5/TLS Mismatch) ---
func emailHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req EmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON input", http.StatusBadRequest)
		return
	}

	// --- SMTP DETAILS (SMTPS/TLS Settings) ---
	const smtpHost = "smtp.hostinger.com"
	const smtpPort = "465" // SMTPS port required for SSL/TLS
	// Use the *actual mailbox* username, not the alias
	const senderEmail = "emmet_goldman@ancom.space"
	const subject = "Resend Feature Test"
	to := []string{req.Recipient}
	// ---------------------------------

	// 1. **MIME and HTML Body Construction**
	mimeHeaders := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n"
	pixelURL := fmt.Sprintf("%s/", TrackingDomain)
	trackingPixel := fmt.Sprintf(`<img src="%s" alt="" width="1" height="1" style="display:none;" />`, pixelURL)
	htmlBody := fmt.Sprintf("<html><body>%s<br><br>%s</body></html>", req.Message, trackingPixel)
	fullMessage := fmt.Sprintf("Subject: %s\r\n%s%s", subject, mimeHeaders, htmlBody)

	// --- CUSTOM CONNECTION (SMTPS/TLS FIX) ---
	// 2. Establish raw TCP connection
	conn, err := net.DialTimeout("tcp", smtpHost+":"+smtpPort, 10*time.Second)

	if err != nil {
		fmt.Println("Error establishing TCP connection:", err)
		http.Error(w, "Failed to connect to SMTP server", http.StatusInternalServerError)
		return
	}
	// 3. Wrap connection in TLS (Required for port 465)
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // <--- CRITICAL FIX: Bypass strict certificate check
		ServerName:         smtpHost,
	}
	tlsConn := tls.Client(conn, tlsConfig)

	// 4. Create SMTP client using the TLS-wrapped connection
	c, err := smtp.NewClient(tlsConn, smtpHost)
	if err != nil {
		fmt.Println("Error creating SMTP client:", err)
		http.Error(w, "Failed to create SMTP client", http.StatusInternalServerError)
		return
	}
	defer c.Close()

	// 5. **Authenticate**
	const smtpUsername = senderEmail
	auth := smtp.PlainAuth("", smtpUsername, SMTPSenderPass, smtpHost)

	if err = c.Auth(auth); err != nil {
		fmt.Println("Error authenticating:", err)
		// This line will now only be hit if the password is 100% incorrect.
		http.Error(w, "Failed to authenticate with SMTP server", http.StatusInternalServerError)
		return
	}

	// 6. **Specify Sender and Recipients**
	if err = c.Mail(senderEmail); err != nil {
		fmt.Println("Error setting sender:", err)
		http.Error(w, "Failed to set sender", http.StatusInternalServerError)
		return
	}
	for _, rcpt := range to {
		if err = c.Rcpt(rcpt); err != nil {
			fmt.Println("Error setting recipient:", err)
			http.Error(w, "Failed to set recipient", http.StatusInternalServerError)
			return
		}
	}

	// 7. **Send the Data**
	w_data, err := c.Data()
	if err != nil {
		fmt.Println("Error getting data writer:", err)
		http.Error(w, "Failed to get data writer", http.StatusInternalServerError)
		return
	}

	_, err = w_data.Write([]byte(fullMessage))
	if err != nil {
		fmt.Println("Error writing message data:", err)
		http.Error(w, "Failed to write message data", http.StatusInternalServerError)
		return
	}

	err = w_data.Close()
	if err != nil {
		fmt.Println("Error closing data writer:", err)
		http.Error(w, "Failed to close data writer", http.StatusInternalServerError)
		return
	}

	// 8. **Quit the session**
	c.Quit()

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Email successfully sent to %s", req.Recipient)
}

// --- MAIN ROUTER ---

func handler(w http.ResponseWriter, r *http.Request) {

	// 1. Check for API call
	if r.URL.Path == "/api/email/send" {
		emailHandler(w, r)
		return
	}

	// 2. Serve Tracking Pixel (Root path handles Email Open Tracking Event)
	if r.URL.Path == "/" {
		logVisitor(r)

		w.Header().Set("Content-Type", "image/gif")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.WriteHeader(http.StatusOK)
		w.Write(trackingPixelGIF)
		return
	}

	// Default: 404
	http.NotFound(w, r)
}

// --- INITIALIZATION ---

func main() {
	// 1. Load environment variables
	if err := godotenv.Load(".env"); err == nil {
		fmt.Println("Loaded .env file successfully.")
	} else {
		// Log warning, but continue as environment vars might be set globally
		fmt.Println("Warning: Could not load .env file. Relying on system environment variables.")
	}

	// 2. Read and validate the password
	SMTPSenderPass = os.Getenv("SMTP_PASSWORD")
	if SMTPSenderPass == "" {
		fmt.Println("FATAL ERROR: SMTP_PASSWORD environment variable not set. Service cannot send emails.")
		os.Exit(1)
	}

	// 3. Create secure log directory (0700 permissions)
	os.MkdirAll("/var/lib/opsec", 0700)

	// 4. Set up the router
	http.HandleFunc("/", handler)

	// FIX: Listen on 127.0.0.1:8081 for Nginx reverse proxy access
	listenAddr := "127.0.0.1:8081"
	fmt.Println("Starting system-mgr logging service on", listenAddr, "...")

	// 5. Start the server (This is a blocking call)
	if err := http.ListenAndServe(listenAddr, nil); err != nil {
		fmt.Println("Fatal error starting service:", err)
		os.Exit(1)
	}
}