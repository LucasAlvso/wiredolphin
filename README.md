Since this program requires Linux-specific APIs, you need to cross-compile:

```bash
# Use the build script
./build.sh

# Or manually cross-compile
GOOS=linux GOARCH=amd64 go build -o wiredolphin-linux-amd64
```

Then transfer the binary to a Linux system:
```bash
scp wiredolphin-linux-amd64 user@linux-host:~/wiredolphin
```

### Using Docker Compose (recommended on Linux)

This repository includes a Dockerfile and a `docker-compose.yml` to run the analyzer with the right capabilities and persistent logs.

Requirements:
- Run on a Linux host that has the target interface (e.g., `tun0`) in its network namespace.
- Docker Engine and Docker Compose.

Quick start (Linux host):

```powershell
# From the repository root
docker compose up -d

# CSV logs will be written to ./logs
ls logs
```

Customize the interface (defaults to `tun0`):

```powershell
$env:IFACE = "eth0"; docker compose up -d --build
# or for Bash: IFACE=eth0 docker compose up -d --build
```

Stop:

```powershell
docker compose down
```

Notes:
- The service uses `network_mode: host` so it can see host interfaces. On Docker Desktop for Windows/macOS, this refers to the Linux VM and will not expose your host OS interfaces. To analyze real `tun0` traffic, run on the Linux proxy host itself.
- The container runs with `CAP_NET_RAW` (and `NET_ADMIN`) to open raw sockets. Root inside the container is required, but the service is not fully privileged.

## Usage

Run the monitor with root privileges:

```bash
sudo ./wiredolphin [interface]
```

By default, it monitors the `tun0` interface. To monitor a different interface:

```bash
sudo ./wiredolphin eth0

### Output

CSV log files are continuously written and flushed so you can inspect them live:

- `camada_internet.csv` – IPv4/IPv6/ICMP details (timestamp, protocol, IPs, proto number, ICMP info, bytes)
- `camada_transporte.csv` – TCP/UDP details (timestamp, protocol, IPs/ports, bytes)
- `camada_aplicacao.csv` – Application layer (HTTP/DHCP/DNS/NTP) summary

When running via Compose, these files are in `./logs`.
```