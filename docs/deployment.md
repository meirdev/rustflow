# Deployment

This page covers recommendations for running RustFlow on Linux.

## systemd

Example systemd service files are available in [`contrib/systemd`](../contrib/systemd/).

Install the service file and the environment file it reads:

```bash
sudo cp contrib/systemd/rustflow-collector.service /etc/systemd/system/
sudo mkdir -p /etc/rustflow
sudo cp contrib/systemd/collector.env /etc/rustflow/
sudo systemctl daemon-reload
```

The unit reads its arguments from `EnvironmentFile=/etc/rustflow/collector.env`, so the
service will fail to start if that file is missing. Keeping the arguments there means the
unit itself stays untouched across upgrades — edit `/etc/rustflow/collector.env` to change
how the collector runs.

The unit runs as a `rustflow` system user, which systemd does not create for you:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin rustflow
```

The output directory is handled by `StateDirectory=rustflow`, so systemd creates
`/var/lib/rustflow` and gives it to the service user on first start.

Enable and start the service:

```bash
sudo systemctl enable --now rustflow-collector
```

Check its status:

```bash
systemctl status rustflow-collector
```

Follow the logs:

```bash
journalctl -u rustflow-collector -f
```

## UDP Socket Buffers

For high flow rates, the default Linux UDP receive buffer may be too small.

Check the current limits:

```bash
sysctl net.core.rmem_default
sysctl net.core.rmem_max
```

The limits can be increased using `sysctl`. For example:

```conf
net.core.rmem_default = 16777216
net.core.rmem_max = 16777216
```

Apply the configuration:

```bash
sudo sysctl --system
```

The appropriate buffer size depends on the expected flow rate and available system memory.

## Privileged Ports

Listening on ports below `1024` normally requires elevated privileges.

Instead of running the collector as root, the binary can be granted permission to bind to privileged ports:

```bash
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/rustflow
```

This is not required when listening on ports above `1024`.

## Packet Capture

The IPFIX exporter captures packets directly from a network interface and requires sufficient privileges.

It can be run as root:

```bash
sudo rustflow export -i eth0
```

See [Exporter](exporter.md) for exporter configuration.
