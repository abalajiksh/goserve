package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/pem"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

//go:embed templates/upload.html
var templateFS embed.FS

var uploadTmpl *template.Template

func main() {
	port := flag.Int("port", 8000, "port to listen on")
	dir := flag.String("dir", ".", "directory to serve")
	uploadDir := flag.String("uploads", "", "upload destination (default: <dir>/uploads)")
	tlsEnabled := flag.Bool("tls", false, "enable HTTPS (auto-generates self-signed cert if --cert/--key not given)")
	certFile := flag.String("cert", "", "path to TLS certificate file (PEM)")
	keyFile := flag.String("key", "", "path to TLS private key file (PEM)")
	flag.Parse()

	serveDir, err := filepath.Abs(*dir)
	if err != nil {
		log.Fatalf("invalid directory: %v", err)
	}

	uplDir := *uploadDir
	if uplDir == "" {
		uplDir = filepath.Join(serveDir, "uploads")
	}
	uplDir, err = filepath.Abs(uplDir)
	if err != nil {
		log.Fatalf("invalid upload directory: %v", err)
	}

	if err := os.MkdirAll(uplDir, 0o755); err != nil {
		log.Fatalf("cannot create upload directory: %v", err)
	}

	uploadTmpl = template.Must(template.ParseFS(templateFS, "templates/upload.html"))

	mux := http.NewServeMux()

	// Upload endpoint — serves form on GET, handles upload on POST
	mux.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleUploadPage(w, r)
		case http.MethodPost:
			handleUpload(w, r, uplDir)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// Everything else: static file server with directory listing
	fileServer := http.FileServer(http.Dir(serveDir))
	mux.Handle("/", fileServer)

	addr := fmt.Sprintf("0.0.0.0:%d", *port)
	localIP := getLocalIP()

	scheme := "http"
	if *tlsEnabled {
		scheme = "https"
	}

	log.Println("┌─────────────────────────────────────────────┐")
	log.Printf("│  goserve                                    │")
	log.Println("├─────────────────────────────────────────────┤")
	log.Printf("│  Serving   : %-30s│\n", serveDir)
	log.Printf("│  Uploads to: %-30s│\n", uplDir)
	if *tlsEnabled {
		if *certFile != "" {
			log.Printf("│  TLS       : custom cert                    │\n")
		} else {
			log.Printf("│  TLS       : self-signed (auto)              │\n")
		}
	}
	log.Println("├─────────────────────────────────────────────┤")
	log.Printf("│  Local : %s://localhost:%-17s│\n", scheme, fmt.Sprintf("%d", *port))
	if localIP != "" {
		log.Printf("│  LAN   : %s://%-26s│\n", scheme, fmt.Sprintf("%s:%d", localIP, *port))
	}
	log.Printf("│  Upload: %s://%-26s│\n", scheme, fmt.Sprintf("%s:%d/upload", localIP, *port))
	log.Println("└─────────────────────────────────────────────┘")

	server := &http.Server{
		Addr:         addr,
		Handler:      loggingMiddleware(mux),
		ReadTimeout:  5 * time.Minute,
		WriteTimeout: 5 * time.Minute,
	}

	if *tlsEnabled {
		if *certFile != "" && *keyFile != "" {
			// User-provided certificate
			log.Printf("  Using certificate: %s", *certFile)
			log.Fatal(server.ListenAndServeTLS(*certFile, *keyFile))
		} else if *certFile != "" || *keyFile != "" {
			log.Fatal("both --cert and --key must be specified together")
		} else {
			// Auto-generate self-signed certificate
			tlsCfg, err := generateSelfSignedTLS(localIP)
			if err != nil {
				log.Fatalf("failed to generate self-signed cert: %v", err)
			}
			server.TLSConfig = tlsCfg
			log.Printf("  Self-signed cert generated (valid 1 year, ECDSA P-256)")
			log.Printf("  SHA-256 fingerprint will appear in browser warning — safe to accept on LAN")
			log.Fatal(server.ListenAndServeTLS("", ""))
		}
	} else {
		log.Fatal(server.ListenAndServe())
	}
}

func handleUploadPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	uploadTmpl.Execute(w, nil)
}

func handleUpload(w http.ResponseWriter, r *http.Request, uplDir string) {
	// 2 GB max
	r.Body = http.MaxBytesReader(w, r.Body, 2<<30)

	if err := r.ParseMultipartForm(64 << 20); err != nil {
		http.Error(w, fmt.Sprintf("parse error: %v", err), http.StatusBadRequest)
		return
	}

	files := r.MultipartForm.File["files"]
	if len(files) == 0 {
		http.Error(w, "no files provided", http.StatusBadRequest)
		return
	}

	var results []string

	for _, fh := range files {
		src, err := fh.Open()
		if err != nil {
			results = append(results, fmt.Sprintf("FAIL %s: %v", fh.Filename, err))
			continue
		}

		// Sanitize filename — strip path components
		name := filepath.Base(fh.Filename)
		name = sanitizeFilename(name)
		destPath := filepath.Join(uplDir, name)

		// Don't overwrite: append timestamp if exists
		if _, err := os.Stat(destPath); err == nil {
			ext := filepath.Ext(name)
			base := strings.TrimSuffix(name, ext)
			name = fmt.Sprintf("%s_%d%s", base, time.Now().UnixMilli(), ext)
			destPath = filepath.Join(uplDir, name)
		}

		dst, err := os.Create(destPath)
		if err != nil {
			src.Close()
			results = append(results, fmt.Sprintf("FAIL %s: %v", fh.Filename, err))
			continue
		}

		written, err := io.Copy(dst, src)
		src.Close()
		dst.Close()

		if err != nil {
			results = append(results, fmt.Sprintf("FAIL %s: %v", fh.Filename, err))
		} else {
			results = append(results, fmt.Sprintf("OK   %s (%s)", name, humanSize(written)))
			log.Printf("  ↑ uploaded: %s (%s)", name, humanSize(written))
		}
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintln(w, strings.Join(results, "\n"))
}

func sanitizeFilename(name string) string {
	// Replace anything sketchy
	replacer := strings.NewReplacer(
		"..", "_",
		"/", "_",
		"\\", "_",
		"\x00", "_",
	)
	return replacer.Replace(name)
}

func humanSize(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("  %s %s %s [%v]", r.RemoteAddr, r.Method, r.URL.Path, time.Since(start).Round(time.Millisecond))
	})
}

func generateSelfSignedTLS(localIP string) (*tls.Config, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"goserve (self-signed)"},
			CommonName:   "goserve",
		},
		NotBefore:             now,
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		// SANs — critical for modern browsers
		DNSNames:    []string{"localhost", "goserve.local"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	// Add detected LAN IP to SANs
	if ip := net.ParseIP(localIP); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load keypair: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
			return ipNet.IP.String()
		}
	}
	return "0.0.0.0"
}
