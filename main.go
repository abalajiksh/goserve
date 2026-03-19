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
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

//go:embed templates/upload.html
var templateFS embed.FS

var uploadTmpl *template.Template

// Set at build time via ldflags
var (
	version = "dev"
	commit  = "unknown"
)

func main() {
	port := flag.Int("port", 8000, "port to listen on")
	dir := flag.String("dir", ".", "directory to serve")
	uploadDir := flag.String("uploads", "", "upload destination (default: <dir>/uploads)")
	tlsEnabled := flag.Bool("tls", false, "enable HTTPS (auto-generates self-signed cert if --cert/--key not given)")
	certFile := flag.String("cert", "", "path to TLS certificate file (PEM)")
	keyFile := flag.String("key", "", "path to TLS private key file (PEM)")
	openFirewall := flag.Bool("open-firewall", false, "auto-open firewalld for local subnet (requires firewall-cmd, cleaned up on exit)")
	maxUploadMB := flag.Int("max-upload", 2048, "maximum upload size in MB (default: 2048 = 2 GB)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("goserve %s (commit: %s)\n", version, commit)
		os.Exit(0)
	}

	maxUploadBytes := int64(*maxUploadMB) << 20

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

	// Human-readable upload limit for the HTML template
	maxUploadLabel := humanSize(maxUploadBytes)

	mux := http.NewServeMux()

	// Upload endpoint — serves form on GET, handles upload on POST
	mux.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleUploadPage(w, r, maxUploadLabel)
		case http.MethodPost:
			handleUpload(w, r, uplDir, maxUploadBytes)
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
	log.Printf("│  goserve %-35s│\n", version+" ("+commit+")")
	log.Println("├─────────────────────────────────────────────┤")
	log.Printf("│  Serving   : %-30s│\n", serveDir)
	log.Printf("│  Uploads to: %-30s│\n", uplDir)
	log.Printf("│  Max upload: %-30s│\n", maxUploadLabel)
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
	if *openFirewall {
		log.Printf("│  Firewall: auto-open (subnet)                │\n")
	}
	log.Println("└─────────────────────────────────────────────┘")

	// Firewall management
	var firewallCleanup func()
	if *openFirewall {
		cleanup, err := openFirewalld(*port, localIP)
		if err != nil {
			log.Printf("  ⚠ firewall: %v", err)
		} else {
			firewallCleanup = cleanup
		}
	}

	// Signal handling for graceful cleanup
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("\n  Caught %s, shutting down…", sig)
		if firewallCleanup != nil {
			firewallCleanup()
		}
		os.Exit(0)
	}()

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

func handleUploadPage(w http.ResponseWriter, r *http.Request, maxUploadLabel string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	uploadTmpl.Execute(w, map[string]string{
		"MaxUpload": maxUploadLabel,
	})
}

func handleUpload(w http.ResponseWriter, r *http.Request, uplDir string, maxBytes int64) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)

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

// getLocalSubnet returns the CIDR notation for the local network interface
// that owns the given IP (e.g. "192.168.1.0/24").
func getLocalSubnet(localIP string) (string, error) {
	targetIP := net.ParseIP(localIP)
	if targetIP == nil {
		return "", fmt.Errorf("invalid IP: %s", localIP)
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if ipNet.IP.Equal(targetIP) {
				// Mask the IP to get the network address
				network := ipNet.IP.Mask(ipNet.Mask)
				ones, _ := ipNet.Mask.Size()
				return fmt.Sprintf("%s/%d", network, ones), nil
			}
		}
	}

	return "", fmt.Errorf("no interface found for %s", localIP)
}

// openFirewalld adds a firewalld rich rule scoped to the local subnet.
// Returns a cleanup function that removes the rule.
func openFirewalld(port int, localIP string) (func(), error) {
	// Check if firewall-cmd exists
	fwCmd, err := exec.LookPath("firewall-cmd")
	if err != nil {
		return nil, fmt.Errorf("firewall-cmd not found (not using firewalld?)")
	}

	// Check if firewalld is running
	check := exec.Command(fwCmd, "--state")
	if out, err := check.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("firewalld not running: %s", strings.TrimSpace(string(out)))
	}

	subnet, err := getLocalSubnet(localIP)
	if err != nil {
		return nil, fmt.Errorf("detect subnet: %w", err)
	}

	richRule := fmt.Sprintf(
		`rule family="ipv4" source address="%s" port port="%d" protocol="tcp" accept`,
		subnet, port,
	)

	// Add the rule
	add := exec.Command(fwCmd, "--add-rich-rule", richRule)
	if out, err := add.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("add rule: %s (%w)", strings.TrimSpace(string(out)), err)
	}

	log.Printf("  🔓 firewall: opened port %d for %s", port, subnet)

	cleanup := func() {
		rm := exec.Command(fwCmd, "--remove-rich-rule", richRule)
		if out, err := rm.CombinedOutput(); err != nil {
			log.Printf("  ⚠ firewall cleanup failed: %s (%v)", strings.TrimSpace(string(out)), err)
		} else {
			log.Printf("  🔒 firewall: closed port %d for %s", port, subnet)
		}
	}

	return cleanup, nil
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
