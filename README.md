## Foxhole Firewall Daemon

Go-based daemon that tails your web server logs, evaluates requests against YAML-defined rules, and applies IP bans via either local iptables or a remote HTTP firewall API.

### Features

- YAML configuration with hot-reload via fsnotify
- Pluggable log parsers (nginx, apache, caddy, traefik)
- Rule engine with per-IP error thresholds
- Firewall backends: iptables, HTTP API, Vultr, Proxmox
- Ban manager with automatic unban, whitelist, and dry-run mode
- IPv6 support across all backends
- systemd unit file for easy deployment

---

### Getting Started from Scratch

New to this? No problem. Here's everything you need to know to get up and running.

#### What does this thing do?

Foxhole watches your web server's access logs in real-time. When it sees an IP address generating too many errors (like repeated 404s or 500s), it automatically bans that IP using your firewall. After a configurable amount of time, it automatically unbans them.

Think of it as a bouncer for your web server that kicks out troublemakers but lets them back in after they've cooled off.

#### Step 1: Get the binary

**Option A: Download a release** (easiest)

Head to the [Releases](../../releases) page and download the binary for your system.

**Option B: Build from source**

```bash
# Make sure you have Go 1.22+ installed
go build -o fwld ./cmd/fwld
```

#### Step 2: Set up the config file

```bash
# Create the config directory
sudo mkdir -p /etc/foxhole-fw

# Copy the example config
sudo cp configs/example.yaml /etc/foxhole-fw/config.yaml

# Lock down permissions (config may contain API keys)
sudo chmod 600 /etc/foxhole-fw/config.yaml
```

#### Step 3: Edit the config

Open `/etc/foxhole-fw/config.yaml` in your favorite editor. Here's what you need to change:

```yaml
log:
  # Point this to YOUR web server's access log
  path: /var/log/nginx/access.log

  # Pick the right parser for your server:
  # - nginx_combined (default nginx)
  # - apache_common (default apache)
  # - caddy (JSON format)
  # - traefik (JSON format)
  parser: nginx_combined

backend:
  # Start with iptables if you're on Linux
  type: iptables
  iptables:
    table: filter
    chain: INPUT

  # IMPORTANT: Start with dry_run: true to test without actually banning anyone!
  dry_run: true

  # Your own IP so you don't lock yourself out
  whitelist:
    - 127.0.0.1
    - YOUR.IP.ADDRESS.HERE

rules:
  # This rule bans IPs that hit errors on any GET request
  - id: general-protection
    description: Ban IPs with too many errors
    method: GET
    path: /
    max_errors: 10      # After 10 errors...
    window: 1m          # ...within 1 minute...
    ban_duration: 10m   # ...ban for 10 minutes
```

#### Step 4: Test it (dry run mode)

With `dry_run: true` in your config, foxhole will log what it *would* do without actually changing your firewall:

```bash
# Run it manually first to see what happens
sudo ./fwld -config /etc/foxhole-fw/config.yaml
```

You should see output like:
```
INFO foxhole-fw starting (version=dev)
INFO config loaded from /etc/foxhole-fw/config.yaml (backend=iptables)
INFO firewall backend initialized: iptables
```

Generate some 404 errors by visiting non-existent pages, and you'll see:
```
INFO DRY-RUN ban: ip=1.2.3.4 rule=general-protection backend=iptables until=2024-01-15T10:30:00Z
```

#### Step 5: Go live

Once you're happy with the behavior:

1. Set `dry_run: false` in your config
2. Make sure your IP is in the whitelist!
3. Install as a systemd service:

```bash
# Copy files into place
sudo cp fwld /usr/local/bin/
sudo cp deploy/systemd/fwld.service /etc/systemd/system/

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable --now fwld

# Check it's running
sudo systemctl status fwld

# Watch the logs
sudo journalctl -u fwld -f
```

#### Step 6: Verify it's working

Check that iptables rules are being created:

```bash
sudo iptables -L INPUT -n | grep DROP
```

You should see entries for banned IPs.

---

### Quick Reference

#### Commands

```bash
# Check version
fwld -version

# Run with custom config
fwld -config /path/to/config.yaml

# View service logs
sudo journalctl -u fwld -f

# Check current bans (iptables)
sudo iptables -L INPUT -n | grep DROP
```

#### Config highlights

| Setting | Description |
|---------|-------------|
| `log.path` | Path to your web server's access log |
| `log.parser` | `nginx_combined`, `apache_common`, `caddy`, or `traefik` |
| `backend.type` | `iptables`, `http_api`, `vultr`, or `proxmox` |
| `backend.dry_run` | Set `true` to test without making changes |
| `backend.whitelist` | IPs/CIDRs that are never banned |
| `rules[].max_errors` | Error threshold before banning |
| `rules[].window` | Time window for counting errors |
| `rules[].ban_duration` | How long to ban offending IPs |

#### Supported backends

| Backend | Use case |
|---------|----------|
| `iptables` | Local Linux server with iptables/ip6tables |
| `http_api` | Generic HTTP API (roll your own) |
| `vultr` | Vultr Cloud Firewall |
| `proxmox` | Proxmox VE node or VM firewall |

---

### Troubleshooting

**"Permission denied" errors**
- Foxhole needs root to modify iptables. Run with `sudo` or as a systemd service.

**Not seeing any bans**
- Check that `dry_run` is set to `false`
- Verify the log path is correct and readable
- Make sure your parser matches your log format
- Check that you're generating actual 4xx/5xx errors

**Locked yourself out**
- If you have console access, run: `sudo iptables -F INPUT`
- Always add your IP to the whitelist before going live!

**Config changes not taking effect**
- Foxhole hot-reloads config on file changes
- Check the logs for "config reloaded successfully"
- If there's a syntax error, the old config stays active

---

### Development

**Building from source:**
```bash
go build -o fwld ./cmd/fwld
```

**Running tests and linting:**
```bash
go test ./...
golangci-lint run ./...
```

**Creating a release:**
Tag a commit with a version to trigger the release workflow:
```bash
git tag v1.0.0
git push origin v1.0.0
```

This builds multi-arch binaries (linux/amd64, linux/arm64), generates checksums, and publishes a GitHub Release.

---

### License

MIT
