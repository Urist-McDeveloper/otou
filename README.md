# otou - Obfuscated Tunnel Over UDP

Simple IPv4 tunnel over UDP that makes its packets look like nothing in particular:
* used encryption scheme makes every byte of UDP payload look uniformly random;
* packet length is obfuscated by appending random number of bytes (1 to 8) .

Uses entirely connectionless and mostly stateless communication protocol
(server does keep track of client addresses to send packets back). As a result, there is no:

* peer verification beyond knowing the shared secret (any client can impersonate other clients or even the server);
* built-in protection against replay attacks and other fancy security features.

Linux only (for now).

## Usage

```
Usage: otou [OPTIONS] COMMAND

Options:
  -c, --config PATH   use PATH instead of default config file location
  -h, --help          print this message and exit
  -v, --version       print version and exit

Common commands:
  genkey              generate a random 32-byte secret key
  run                 start main process

Client mode commands:
  routes [up|down]    set/reset gateway routes
```

### Server

1. setup `otou run` daemon (for example as a `systemd` service);
2. configure NAT routing for tunnel IP (like `iptables -t nat -s 10.13.37.1/24 -A POSTROUTING -j MASQUERADE`).

### Client

1. setup `otou run` daemon (for example as a `systemd` service);
2. run `otou routes up` to send all network packets through the tunnel;
3. run `otou routes down` to restore normal network configuration.

### Example systemd service

```
[Unit]
Description=Obfuscated Tunnel Over UDP
After=network.target

[Service]
Type=exec
Restart=always
ExecStart=/path/to/otou run

[Install]
WantedBy=default.target
```

Put this in  `/etc/systemd/system/otou.service` and run:

```
systemctl daemon-reload
systemctl start otou
systemctl enable otou
```

## Configuration

Default location is `/etc/otou.json`.
See example configuration for [client](src/config_client_example.json) and [server](src/config_server_example.json).

* `tun_name`: 1 to 15 bytes.
* `tun_addr`: has an implicit `/24` mask. Must be unique among all peers (including the server);
  if two peers use the same address their packets **will** get mixed.
* `bind`: servers should probably set the port explicitly.
* `key`: 32 bytes in hex format; can be generated with `otou genkey`.
  Example key (all zeroes) is rejected in release builds.
* `client`: if not null otou will run in client mode. This field is mutually exclusive with `server`;
   * `tun_keep`: persist TUN interface and its routes after the main process shuts down.
     May be used to prevent internet access in case the daemon dies suddenly.
   * `server_addr`: self-explanatory I hope.
* `server`: if not null otou will run in server mode. This field is mutually exclusive with `client`;
   * `peers`: all known TUN IPs with optional labels.
     Packets sent from an unknown IP will be silently dropped. This is not a security feature;
     the goal is to encourage assigning unique addresses to unique clients to prevent accidental address reuse.

## How to build

1. Download Zig v0.13 (https://ziglang.org/download);
2. clone this repo: `git clone https://github.com/Urist-McDeveloper/otou.git`;
3. run `zig build --release=safe`.

For cross-compiling, CPU selection and everything else look into the Zig build system.

# TODO

Priority:

* test if linking libc can improve performance;

Backlog:

* add some options to control inter-client communication;

Maybe someday:

* automatic NAT management for server mode (iptables are deprecated);
* automatic DNS setup (if requested via config file);
* Docker images for server mode;

Most likely never:

* IPv6 support;
