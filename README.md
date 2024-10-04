# otou - Obfuscated Tunnel Over UDP

```
Usage: otou [OPTIONS] COMMAND

Options:
  -c, --config PATH   use PATH instead of default config file location
  -h, --help          print this message and exit
  -v, --version       print version and exit

Commands:
  genkey              generate a random 32-byte secret key
  run                 start daemon
  down                shut down daemon and restore network configuration
  status              display status of daemon
  reload              apply configuration changes to the running daemon
```

# Configuration

Default location is `/etc/otou.json`.
See example configuration for [client](src/config_client_example.json) and [server](src/config_server_example.json).

Constraints and clarifications:

* `common.tun_name` -- 1 to 8 bytes.
* `common.tun_addr` -- has an implicit `/24` mask. Must be unique among all peers (including the server);
  if two peers use the same address their packets **will** get mixed.
* `common.tun_keep` -- persist TUN interface and its routes after the daemon shuts down on its own,
  i.e. without calling `otou down`. May be used to prevent internet access in case the daemon dies suddenly.
* `common.bind` -- servers should probably set the port explicitly.
* `common.key` -- 32 bytes in hex format; can be generated with `otou genkey`.
  Example key (all zeroes) is rejected in release builds.
* `client` -- if not null `otou run` will use client mode. This field is mutually exclusive with `server`.
* `server` -- if not null `otou run` will use server mode. This field is mutually exclusive with `client`:
  * `peers` -- all known TUN IPs with optional labels.
    Packets sent from an unknown IP will be silently dropped. This is not a security feature;
    the goal is to encourage assigning unique addresses to unique clients to prevent accidental address reuse.

# TODO

Priority:

* implement all the commands;
* actually implement all the logic described in Configuration section;
* automatic setup/tear-down of TUN interface and routes (client mode);

Backlog:

* add some options to control inter-client communication;
* add random padding to messages for better obfuscation;

Maybe someday:

* automatic DNS setup (if requested via config file);
* IPv6 support;
