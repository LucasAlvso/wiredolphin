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

### Using Docker/Podman (Any OS)

You can also build and run in a Linux container:

```bash
# Build in container
docker run --rm -v $(pwd):/app -w /app golang:1.21 go build -o wiredolphin

# Run (requires privileged mode for raw sockets)
docker run -it --rm --privileged --network host \
  -v $(pwd):/app -w /app golang:1.21 ./wiredolphin tun0
```

## Usage

Run the monitor with root privileges:

```bash
sudo ./wiredolphin [interface]
```

By default, it monitors the `tun0` interface. To monitor a different interface:

```bash
sudo ./wiredolphin eth0
```