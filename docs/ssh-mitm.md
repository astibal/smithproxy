# SSH MITM

Smithproxy can terminate SSHv2 on both sides, authenticate upstream with the
password supplied by the client, relay SSH channels, and capture the decoded
channel byte stream. SSHv1 is deliberately blocked. Build with `USE_LIBSSH=Y`
and install the system `libssh` and `libssh-dev` packages.

## Host key and profile

Generate a dedicated MITM host key readable by the Smithproxy process:

```sh
ssh-keygen -q -t ed25519 -N '' -f /etc/smithproxy/ssh_host_ed25519_key
```

Configure a profile and assign it to a TCP policy:

```libconfig
ssh_profiles = {
    default = {
        host_key = "/etc/smithproxy/ssh_host_ed25519_key";
        shell = "pass";
        exec = "pass";
        subsystem = "pass";
        pty = "pass";
        environment = "pass";
        local_forward = "pass";
        remote_forward = "pass";
        x11 = "reject";
        agent = "reject";
    };
};

policy = (
    {
        name = "inspect-ssh";
        proto = "tcp";
        src = [ "any", "any6" ]; sport = [ "all" ];
        dst = [ "any", "any6" ]; dport = [ "ssh" ];
        ssh_profile = "default";
        action = "accept"; nat = "auto";
    }
);
```

Every feature value is either `pass` or `reject`:

| Option | SSH operation |
|---|---|
| `shell` | interactive shell request |
| `exec` | one-shot command execution |
| `subsystem` | subsystem such as SFTP |
| `pty` | PTY allocation and resize |
| `environment` | environment variable requests |
| `local_forward` | `direct-tcpip` channels (`ssh -L`, `-D`) |
| `remote_forward` | remote listener and `forwarded-tcpip` (`ssh -R`) |
| `x11` | X11 request and server-opened X11 channels |
| `agent` | agent request and server-opened agent channels |

The default created by the CLI passes all features. Restrict X11 and agent
forwarding explicitly when they are not needed.

## CLI configuration

```text
configure terminal
edit ssh_profiles
add inspected
edit inspected
set host_key /etc/smithproxy/ssh_host_ed25519_key
set shell pass
set exec pass
set subsystem pass
set pty pass
set environment pass
set local_forward pass
set remote_forward pass
set x11 reject
set agent reject
end
edit policy [2]
set ssh_profile inspected
end
save config
execute reload
```

Use `show config ssh_profiles` to inspect the saved profiles. Runtime commands:

```text
diag proxy session ssh-info
diag proxy session list ssh 8
debug set com.ssh 8
debug set com.ssh.shell 8
debug set com.ssh.exec 8
```

At diagnostic verbosity, the session output includes the selected profile,
client and mirrored server banners, transport state, plaintext byte counters,
and current channel counts.

## Plaintext capture

Decoded SSH channel data is emitted to the selected content profile capture.
PCAPNG Enhanced Packet Block comments annotate channel opens/closes, shell,
exec, subsystem, PTY, environment, forwarding, X11, agent and relay direction.
The packets intentionally contain an internal plaintext stream rather than
wire-format SSH, so Wireshark does not need to dissect them as SSH.

Current authentication support is password only. Public-key and keyboard-
interactive authentication attempts are rejected instead of being bypassed.
