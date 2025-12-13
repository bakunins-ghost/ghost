package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/mail"
	"net/smtp"
	"os"
	"time"

	"github.com/joho/godotenv"
)

// Define environment variables (loaded in init)
var (
    smtpHost string
    smtpPort string
    smtpUsername string
    smtpPassword string
    senderEmail string // The actual mailbox address (e.g., emmet_goldman@ancom.space)
)

// EmailPayload struct matches the JSON body from the curl request
type EmailPayload struct {
    Recipient string `json:"recipient"`
    Message   string `json:"message"`
}

func init() {
    // 1. Load environment variables from .env file
    // OpSec: Secrets should ONLY be loaded from environment variables
    err := godotenv.Load()
    if err != nil {
        log.Fatal("Error loading .env file. Ensure it is present in the application directory.")
    }

    // 2. Assign values from environment 
    smtpHost = os.Getenv("SMTP_HOST")
    smtpPort = os.Getenv("SMTP_PORT")
    smtpPassword = os.Getenv("SMTP_PASSWORD")
    
    // Hardcoded sender for consistency, using the authentication username
    senderEmail = "emmet_goldman@ancom.space" 
    smtpUsername = senderEmail
    
    if smtpHost == "" || smtpPort == "" || smtpPassword == "" {
        log.Fatal("One or more critical SMTP environment variables are missing.")
    }

    log.Printf("Environment loaded. Host: %s:%s, User: %s", smtpHost, smtpPort, smtpUsername)
}

func main() {
    // Define API routes
    http.HandleFunc("/api/email/send", handleSendEmail)

    // Start the server
    port := ":8081"
    log.Printf("Starting HTTP server on %s", port)
    
    // Configure server for robust connection handling
    server := &http.Server{
        Addr:         port,
        ReadTimeout:  5 * time.Second,
        WriteTimeout: 10 * time.Second,
        IdleTimeout:  15 * time.Second,
    }
    
    if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
        log.Fatalf("Could not listen on %s: %v\n", port, err)
    }
}

// Handler for the /api/email/send endpoint
func handleSendEmail(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Only POST requests are accepted", http.StatusMethodNotAllowed)
        return
    }

    var payload EmailPayload
    err := json.NewDecoder(r.Body).Decode(&payload)
    if err != nil {
        http.Error(w, "Invalid request payload", http.StatusBadRequest)
        return
    }

    err = sendEmail(payload.Recipient, "OpSec Status Update", payload.Message)
    if err != nil {
        log.Printf("Failed to send email to %s: %v", payload.Recipient, err)
        http.Error(w, fmt.Sprintf("Email sending failed: %v", err), http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusOK)
    fmt.Fprintf(w, "Email sent successfully to %s", payload.Recipient)
}

// Core function to establish TLS connection and send email
func sendEmail(toAddress, subject, body string) error {
    serverAddr := fmt.Sprintf("%s:%s", smtpHost, smtpPort)

    // 1. Setup Authentication
    auth := smtp.PlainAuth("", smtpUsername, smtpPassword, smtpHost)

    // 2. Setup TLS Configuration (The Fix)
    tlsConfig := &tls.Config{
        ServerName: smtpHost, 
    }

    // 3. Establish TLS Connection
    conn, err := tls.Dial("tcp", serverAddr, tlsConfig)
    if err != nil {
        return fmt.Errorf("TLS Dial failed: %w", err)
    }

    // 4. Create an SMTP client over the TLS connection
    client, err := smtp.NewClient(conn, smtpHost)
    if err != nil {
        return fmt.Errorf("SMTP client creation failed: %w", err)
    }
    defer client.Close()

    // 5. Authenticate
    if err = client.Auth(auth); err != nil {
        // --- ENHANCED LOGGING HERE ---
        log.Printf("AUTH ERROR DETAILS: Server returned: %v | User: %s | Host: %s", err, smtpUsername, smtpHost)
        // -----------------------------
        return fmt.Errorf("Failed to authenticate with SMTP server: %w", err)
    }

    // 6. Create Message Headers and Body
    from := mail.Address{Name: "OpSec Manager", Address: senderEmail}
    to := mail.Address{Address: toAddress}
    
    headers := make(map[string]string)
    headers["From"] = from.String()
    headers["To"] = to.String()
    headers["Subject"] = subject

    message := ""
    for k, v := range headers {
        message += fmt.Sprintf("%s: %s\r\n", k, v)
    }
    message += "\r\n" + body

    // 7. Send the Mail
    if err = client.Mail(from.Address); err != nil {
        return fmt.Errorf("mail from failed: %w", err)
    }
    if err = client.Rcpt(to.Address); err != nil {
        return fmt.Errorf("mail rcpt failed: %w", err)
    }

    w, err := client.Data()
    if err != nil {
        return fmt.Errorf("client data failed: %w", err)
    }
    
    _, err = w.Write([]byte(message))
    if err != nil {
        return fmt.Errorf("write message failed: %w", err)
    }
    
    err = w.Close()
    if err != nil {
        return fmt.Errorf("close data writer failed: %w", err)
    }

    return client.Quit()
}