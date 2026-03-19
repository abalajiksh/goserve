# goserve

A single-binary local file server and upload tool written in Go. Zero external dependencies, TLS support out of the box, and no broken pipes.

## Why?

If you've ever needed to quickly serve files on a LAN — sharing a build artifact with a colleague, pulling a config onto an embedded device, or testing something in a browser — you've probably reached for one of the usual suspects. They all have friction.

### Python's `http.server` breaks under real use

```bash
python3 -m http.server 8000 --bind 0.0.0.0
```

Everyone knows this one-liner. It works fine until it doesn't. The server is single-threaded and has a well-known broken pipe problem: when a client disconnects mid-transfer (browser tab closed, `curl` interrupted, mobile device locked), Python throws `BrokenPipeError: [Errno 32] Broken pipe` and often crashes or hangs the server entirely. This is especially common when:

- Serving large files (ISOs, FLACs, firmware images) where partial downloads are normal
- Multiple devices are browsing simultaneously
- Mobile browsers aggressively drop idle connections
- Range requests from download managers or media players trigger edge cases

The `ThreadingHTTPServer` variant (default since Python 3.7) helps with concurrency but doesn't fix the broken pipe handling — the exception still propagates uncleanly, logs get noisy, and the server can end up in a bad state. There's no built-in upload support either, so file transfer is one-directional.

### Nginx works but isn't quick

Nginx is the correct production answer, but it's overkill for "serve this directory for 10 minutes on the office LAN":

- Most distro packages (`apt install nginx`) ship without `ngx_http_autoindex_module` enabled, or with it compiled in but the config pointing at a default welcome page — you need to write a config file to get directory listing
- On minimal or embedded systems, you may need to compile from source with `--with-http_autoindex_module` to enable directory browsing at all:

```bash
# The dance you do when you just wanted to list files
wget https://nginx.org/download/nginx-1.26.x.tar.gz
tar xzf nginx-1.26.x.tar.gz
cd nginx-1.26.x
./configure \
    --with-http_ssl_module \
    --with-http_autoindex_module \
    --prefix=/opt/nginx
make -j$(nproc)
sudo make install
```

- Then you still need a config:

```nginx
server {
    listen 8000;
    server_name _;
    root /path/to/serve;
    autoindex on;
    autoindex_exact_size off;
    autoindex_localtime on;

    # Upload? Now you need a DAV module or a separate backend.
    # Good luck.
}
```

- File upload requires `ngx_http_dav_module` (another compile-time flag) or proxying to a separate application
- Managing `nginx.conf`, starting/stopping the daemon, making sure nothing conflicts with an existing install — it all adds up

None of this is hard, but it takes 15 minutes when you needed 15 seconds.

### goserve: one binary, done

```bash
./goserve -dir ~/shared -tls
```

Directory listing, file upload, HTTPS. No config files, no dependencies, no daemons.

## Installation

**From source (requires Go 1.22+):**

```bash
git clone https://github.com/<you>/goserve.git
cd goserve
go build -o goserve .
```

Version and commit ID can be injected at build time via ldflags:

```bash
go build -ldflags "-X main.version=1.0.0 -X main.commit=$(git rev-parse --short HEAD)" -o goserve .
```

Running `./goserve -version` will then print `goserve 1.0.0 (commit: abc1234)`. Without ldflags, it defaults to `dev (commit: unknown)`.

The binary is fully self-contained — the HTML upload page is embedded at compile time via `//go:embed`. Copy it anywhere.

**Cross-compile for another machine:**

```bash
VERSION=1.0.0
COMMIT=$(git rev-parse --short HEAD)
LDFLAGS="-X main.version=$VERSION -X main.commit=$COMMIT"

# For a Raspberry Pi
GOOS=linux GOARCH=arm64 go build -ldflags "$LDFLAGS" -o goserve-arm64 .

# For a colleague's Mac
GOOS=darwin GOARCH=arm64 go build -ldflags "$LDFLAGS" -o goserve-macos .

# Windows
GOOS=windows GOARCH=amd64 go build -ldflags "$LDFLAGS" -o goserve.exe .
```

## Usage

```bash
# Serve current directory on port 8000 (same as python3 -m http.server)
./goserve

# Serve a specific directory on a different port
./goserve -dir ~/Music -port 9090

# Custom upload destination
./goserve -uploads /tmp/incoming

# Set a custom upload limit (in MB, default 2048 = 2 GB)
./goserve -max-upload 4096    # 4 GB
./goserve -max-upload 512     # 512 MB

# HTTPS with auto-generated self-signed certificate
./goserve -tls

# HTTPS with your own certificate (mkcert, Let's Encrypt, office CA, etc.)
./goserve -tls -cert server.crt -key server.key

# Print version and exit
./goserve -version
```

On startup, goserve prints your LAN address so you can reach it from other devices immediately:

```
┌─────────────────────────────────────────────┐
│  goserve                                    │
├─────────────────────────────────────────────┤
│  Serving   : /home/user/shared              │
│  Uploads to: /home/user/shared/uploads      │
│  TLS       : self-signed (auto)             │
├─────────────────────────────────────────────┤
│  Local : https://localhost:8000             │
│  LAN   : https://192.168.1.42:8000         │
│  Upload: https://192.168.1.42:8000/upload   │
└─────────────────────────────────────────────┘
```

## Features

**File serving** — Directory listing with download links, MIME type detection, and range request support (resumable downloads work out of the box). Go's `net/http` handles concurrent connections natively via goroutines — no threading model to worry about, no broken pipes.

**File upload** — Drag-and-drop web UI at `/upload` with multi-file support and a progress bar. Also works headlessly:

```bash
curl -F "files=@firmware.bin" http://192.168.1.42:8000/upload
curl -k -F "files=@firmware.bin" https://192.168.1.42:8000/upload  # self-signed
```

**TLS** — Three modes, zero external dependencies (Go stdlib `crypto/*`):

| Flag | Behavior |
|------|----------|
| *(none)* | Plain HTTP |
| `-tls` | Auto-generates an ECDSA P-256 self-signed cert (valid 1 year). LAN IP, `localhost`, and `::1` added as SANs automatically. |
| `-tls -cert FILE -key FILE` | Uses your own PEM certificate and key |

The self-signed cert includes your detected LAN IP as a Subject Alternative Name, so modern browsers will show a matchable warning rather than a generic name mismatch error. This matters when testing new browser versions that enforce strict TLS validation.

**Firewall** — On Fedora/RHEL/CentOS systems with `firewalld`, the `--open-firewall` flag auto-detects your local subnet (e.g. `192.168.1.0/24`) and adds a scoped rich rule so other devices on the LAN can connect. The rule is automatically removed on Ctrl+C / SIGTERM — no stale holes left behind:

```bash
# Just works — detects subnet, opens port, cleans up on exit
./goserve -tls -open-firewall

# What it does under the hood:
# firewall-cmd --add-rich-rule='rule family="ipv4" source address="192.168.1.0/24" port port="8000" protocol="tcp" accept'
# ... on exit:
# firewall-cmd --remove-rich-rule='...'
```

If `firewall-cmd` isn't found or firewalld isn't running, it prints a warning and continues — the flag is a no-op on systems without firewalld.

**Safety defaults:**

- Uploaded files never overwrite existing ones (timestamp suffix appended on collision)
- Filenames are sanitized (path traversal sequences stripped)
- 2 GB upload limit
- Request logging with remote address and timing on every request

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-port` | `8000` | Port to listen on |
| `-dir` | `.` | Directory to serve |
| `-uploads` | `<dir>/uploads` | Upload destination directory (auto-created) |
| `-tls` | `false` | Enable HTTPS |
| `-cert` | | Path to TLS certificate file (PEM). Requires `-key`. |
| `-key` | | Path to TLS private key file (PEM). Requires `-cert`. |
| `-open-firewall` | `false` | Auto-open firewalld for local subnet, cleaned up on Ctrl+C |
| `-max-upload` | `2048` | Maximum upload size in MB |
| `-version` | | Print version and exit |

## Project structure

```
goserve/
├── main.go                # Server, upload handler, TLS generation, logging
├── templates/
│   └── upload.html        # Upload UI (embedded into binary via go:embed)
├── go.mod
├── LICENSE
└── README.md
```

## Tips

**Locally-trusted cert with mkcert** (eliminates browser warnings entirely):

```bash
mkcert -install                          # one-time: install local CA
mkcert localhost 192.168.1.42            # generates cert + key
./goserve -tls -cert localhost+1.pem -key localhost+1-key.pem
```

**Ephemeral sharing via tmpfs:**

```bash
mkdir /tmp/share && ./goserve -dir /tmp/share -tls
```

**Upload from the command line:**

```bash
# Single file
curl -F "files=@report.pdf" http://host:8000/upload

# Multiple files in one request
curl -F "files=@a.txt" -F "files=@b.txt" http://host:8000/upload
```

**Quick alias for your shell:**

```bash
alias serve='goserve -tls -open-firewall'
```

## Comparison

| | `python3 -m http.server` | nginx | goserve |
|---|---|---|---|
| Setup time | Instant | Minutes to hours | Instant |
| Directory listing | Yes | Requires config (+ possible recompile) | Yes |
| File upload | No | Requires DAV module or proxy | Yes (web UI + curl) |
| TLS | No | Yes (config required) | Yes (`-tls` flag) |
| Firewall handling | Manual | Manual | Auto (`-open-firewall`) |
| Concurrent connections | Fragile | Excellent | Excellent |
| Broken pipe handling | Crashes/hangs | Clean | Clean |
| Single binary | No (needs Python) | No (needs config + libs) | Yes |
| Cross-compilation | N/A | Painful | `GOOS=x GOARCH=y go build` |

## License

[MIT](LICENSE)
