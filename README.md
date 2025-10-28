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

### Using Docker Compose with traffic_tunnel (recommended on Linux)

This repository includes a Dockerfile and a `docker-compose.yml` to run the analyzer with the right capabilities and persistent logs.

Requirements:
- Run on a Linux host that has the target interface (e.g., `tun0`) in its network namespace.
- Docker Engine and Docker Compose.

Prepare the tunnel sources for image build:

1. Download/clone the `traffic_tunnel` project under `./tunnel/` in this repository.
	- Ensure there is a `Makefile` and building `make` produces a `traffic_tunnel` binary.
	- The Docker build will compile it in a dedicated build stage and bake it into the image.

Quick start (Linux host):

```powershell
# From the repository root
docker compose up -d --build

# CSV logs will be written to ./logs
ls logs
```

Customize:

```powershell
# Analyzer interface (created by tunnel):
$env:IFACE = "tun0"; docker compose up -d --build

# Underlay interface used by the tunnel server inside the container (typically eth0):
$env:TUN_UNDERLAY_IF = "eth0"; docker compose up -d --build

# Skip starting the tunnel (if you manage it externally) and only run the analyzer inside the container:
$env:TUN_START = "false"; docker compose up -d --build

# Optionally set the TUN address (applied if the tunnel binary didn't assign one):
$env:TUN_ADDR_CIDR = "172.31.66.1/24"; docker compose up -d --build

# Control NAT (MASQUERADE) on the underlay interface:
$env:TUN_ENABLE_NAT = "true"; docker compose up -d --build

# Bash equivalents:
# IFACE=tun0 TUN_UNDERLAY_IF=eth0 docker compose up -d --build
# TUN_START=false docker compose up -d --build
```

Stop:

```powershell
docker compose down
```

Clients (optional):

1. Place client scripts from the traffic_tunnel project under `./tunnel/clients/` (e.g., `client1.sh`, `client2.sh`).
2. Bring up the environment with two example clients:

```powershell
docker compose up -d --build
```

Each client container runs `traffic_tunnel` in client mode using its script and waits for its own tun0. You can enable basic traffic generation by setting `PING_TARGET` environment variables for clients in `docker-compose.yml` or via overrides.

Notes:
- The image builds `traffic_tunnel` from the sources in `./tunnel` and runs it in server mode (`-s`) on `$TUN_UNDERLAY_IF`, creating `$IFACE` (tun0 by default) inside the container; the analyzer attaches to it.
- The container requires `CAP_NET_ADMIN` and `CAP_NET_RAW`, and `/dev/net/tun` to create the virtual interface; compose sets these up.
- On Docker Desktop for Windows/macOS, all of this runs inside the Linux VM. To observe real host traffic, prefer running on a Linux host where you control the underlay interface.
- Client scripts are not included here; copy the ones from the `traffic_tunnel` project into `./tunnel/clients`. If the script requires a server IP/host, use the server container name `wiredolphin` (on the same Docker network) or set an explicit IP.
 - The entrypoint ensures the `$IFACE` is up, assigns `$TUN_ADDR_CIDR` if there is no IP, and optionally enables NAT if `$TUN_ENABLE_NAT=true`.

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