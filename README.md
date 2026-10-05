# multi-vpn-manager (`mvm.py`)

A single-file terminal control center for **split-tunnel VPNs** on Linux:

- **NetworkManager VPNs from the GUI**: OpenVPN, L2TP/IPsec, WireGuard and other NM plugin types
- **sshuttle** tunnels ("VPN over SSH")

Only the IPs/CIDRs you list go through each tunnel. A VPN **never becomes your default route**,
and it stays out of the way of other VPNs on the machine (Windscribe, ExpressVPN, v2ray/xray,
sing-box, clash, WireGuard, plain openvpn, …).

```
python3 mvm.py          # colourful TUI (offers to install textual + rich into ./.venv)
python3 mvm.py doctor   # troubleshooting; works with no packages installed
```

---

## Features

| Area | What you get |
|---|---|
| **Discovery** | Lists every VPN defined in the GUI (NetworkManager) plus your sshuttle profiles. Press `a` to *adopt* a GUI VPN. |
| **Routes** | Each VPN has its own list of IPs, CIDRs and **IP ranges** that go through it. Edit the list in the TUI, or import a `.txt` file. |
| **Up / down / restart** | `nmcli` brings the GUI profile up, then the routes are added. For sshuttle, the process is started and watched. |
| **Credentials** | Read from the GUI profile: shows whether each secret is saved in the profile, kept in the keyring, or asked every time, and whether it's actually stored. `s` saves all secrets into the profile **in one call**, because writing them one by one makes NetworkManager erase the earlier ones. Values are never shown or logged. |
| **Status / analysis** | Interface, local IP, gateway, uptime, traffic and rate sparkline. Route health checks where each IP *really* goes right now (`ip route get`). |
| **Routing map** | A tree of VPN → routes → actual path. Flags IPs claimed by two VPNs. Also shows the other VPNs and the default route. |
| **Logs** | Each VPN has its own log (`logs/<vpn>.log`), shown next to the matching journal lines from NetworkManager, the openvpn/l2tp plugins, pppd, xl2tpd, charon and sshuttle. The log updates live in the TUI. |
| **Troubleshoot** | Grouped checks, each with a hint. Many have a one-key fix (`f`): install the sudoers rule, set never-default, re-apply routes, store secrets. Deep mode also checks that the server is reachable, SSH key login, Python on the sshuttle remote, and gateway ping. |
| **Other VPNs** | Detects Windscribe, ExpressVPN, NordVPN, Mullvad, WARP, Tailscale, v2ray/xray, sing-box, clash/mihomo, Hiddify, NekoRay, plain openvpn, other sshuttle processes and unknown tun/ppp/wg interfaces. Says which one owns the default route. |
| **Autostart** | Optional per VPN, through a `systemd --user` unit (`multi-vpn-manager@<vpn>.service`, with retries at login). |
| **Colours** | 24-bit true colour by default, even over SSH, tmux or screen where `COLORTERM` is lost. Override with `--colors truecolor/256/16`, `MVM_COLORS=…` or the Settings tab. `mvm colors` prints a test strip. |

## Requirements

- Linux with **Python 3.10+**
- **NetworkManager** (`nmcli`) plus the plugins you use:
  `network-manager-openvpn-gnome`, `network-manager-l2tp-gnome`, …
- `iproute2` (`ip`) and `sudo`
- Optional: `sshuttle` (for SSH tunnels), `journalctl` (for system logs), `systemd --user` (for autostart)
- The TUI uses the Python packages `textual` and `rich`. `bootstrap` installs them into `./.venv`; the CLI works without them.

```bash
sudo apt install network-manager network-manager-openvpn-gnome network-manager-l2tp-gnome sshuttle python3-venv
```

## Install (copy anywhere)

```bash
mkdir -p ~/multi-vpn-manager && cd ~/multi-vpn-manager
cp /path/to/mvm.py .
python3 mvm.py doctor             # see what's missing
python3 mvm.py bootstrap          # creates ./.venv with textual + rich
python3 mvm.py sudoers install    # one-time, asks for your sudo password
python3 mvm.py                    # TUI
```

Run it as **your normal desktop user, not with sudo**. NetworkManager secrets live in your session
keyring, and sshuttle uses your SSH keys. Privileged steps run through `sudo -n` and need the sudoers rule.

### The sudoers rule

`mvm sudoers install` checks the file with `visudo` and then writes `/etc/sudoers.d/multi-vpn-manager`.
The rule allows, without a password:

- `ip route *`, `ip -4 route *`, `ip -4 rule *` and `ip link delete *`, used to add and remove routes, rules and leftover ppp links
- sshuttle's own firewall helper, exactly as printed by `sshuttle --sudoers-no-modify`

Use `mvm sudoers show` to preview it and `mvm sudoers check` to test it. To remove it: `sudo rm /etc/sudoers.d/multi-vpn-manager`.

> Note (from sshuttle's own docs): anyone allowed to run sshuttle's helper as root can also use it to run other
> commands as root. Only install the rule on a machine where you are the admin anyway.

## Quick start

```bash
python3 mvm.py list                                         # GUI VPNs + managed ones
python3 mvm.py adopt "My Office VPN" --routes-file office-ips.txt
python3 mvm.py new-sshuttle jump --remote user@203.0.113.10:22 --routes-file jump-ips.txt
python3 mvm.py up office            # connect + routes
python3 mvm.py status               # table + details + other VPNs
python3 mvm.py graph                # routing map
python3 mvm.py down office
```

A routes file has one entry per line. `#` comments, commas and spaces are fine.

### Route formats

| Entry | Meaning |
|---|---|
| `192.0.2.22` | one IP (`/32`) |
| `10.20.0.0/16` | CIDR block |
| `10.0.0.5-10.0.0.20` or `10.0.0.5 - 10.0.0.20` | IP range, inclusive |
| `10.0.0.5-20` | shorthand: the last octet changes |
| `10.1.2.*` / `10.1.*.*` | wildcard, the same as `/24` / `/16` |

Ranges are kept in the config exactly as you wrote them. When routes are applied, each range is split into
the smallest set of CIDR blocks: `10.0.0.5-10.0.0.20` becomes `.5/32 .6/31 .8/29 .16/30 .20/32`. The routing map
shows a range as one node with its blocks underneath. `mvm routes NAME list` shows each range with its expansion.
A range that is exactly one block, such as `10.0.0.0-10.0.0.255`, is saved as that CIDR.
Limits: at most 64 blocks per range, and nothing that covers `0.0.0.0/0`.

## TUI keys

| Key | Action | Key | Action |
|---|---|---|---|
| `1`–`6` | Dashboard · VPNs · Routing map · Logs · Troubleshoot · Settings | `g` | refresh now |
| `u` / `d` / `t` | up / down / restart the selected VPN | `p` | (re)apply routes to a running VPN |
| `e` | edit routes, gateway and options (checked as you type) | `s` | store credentials in the GUI profile |
| `a` | adopt a GUI VPN that isn't managed yet | `n` | new sshuttle profile |
| `o` | toggle autostart | `l` | show logs of the selected VPN |
| `f` | apply the fix of the selected troubleshoot row | `q` | quit |

## CLI reference

```
mvm.py                         TUI
mvm.py list                    GUI VPNs + managed profiles
mvm.py status [NAME] [--watch] [--json]
mvm.py up NAME [--retries N] | down NAME | restart NAME | apply NAME
mvm.py routes NAME [list|add ENTRY..|rm ENTRY..|import FILE..|clear]   ENTRY = IP | CIDR | a-b range | a.b.c.*
mvm.py adopt PROFILE [--name N] [--routes-file F]... [--gateway IP]
mvm.py new-sshuttle NAME --remote user@host[:port] [--routes-file F] [--ssh-args "..."]
mvm.py delete NAME             forget it (config -> .deleted; GUI profile untouched)
mvm.py secrets NAME            store credentials in the GUI profile (hidden prompt)
mvm.py doctor [NAME] [--deep] [--fix] [--json]
mvm.py logs NAME [-n 80] [-f] [-j]      -j adds the system journal lines
mvm.py graph | foreign | colors
mvm.py autostart NAME on|off
mvm.py sudoers [install|show|check]
mvm.py bootstrap
mvm.py --colors truecolor|256|16 ...
```

## How it stays out of other VPNs' way

When a VPN comes up:

1. `ipv4/ipv6.never-default=yes` is set on the GUI profile, and any default route the server pushes through the tunnel is deleted.
2. Existing `/32` routes for your IPs are removed from the tables listed in *Settings → clean tables*
   (default `main, windscribe`). These are, for example, the exclusion routes Windscribe adds.
3. Each IP gets a route through the tunnel in `main`, using the PPP peer as gateway, or a device route on tun.
4. It also gets a policy rule, `to <IP> lookup main priority 30`, so another VPN's policy routing
   (ExpressVPN's fwmark tables, WireGuard full-tunnel setups, …) can't take the IP over.
5. If you re-apply routes to a running VPN, routes you have since removed from its config are deleted too.
6. Everything it added is recorded in `state/<vpn>.json`. **Down removes only those routes and rules.**
   If another VPN that's still up claims the same IPs, they are handed back to it.

Also:

- L2TP often leaves `ppp0` behind after disconnecting. It is removed if it's still there.
- The tunnel interface is found from the VPN's own IPv4 address. NetworkManager's `GENERAL.IP-IFACE` field is not used, because for a VPN it reports the physical network card.

## Files (next to `mvm.py`)

```
configs/<vpn>.json   routes + options (backups in backups/, deleted -> .json.deleted)
state/<vpn>.json     what is currently applied (iface, gateway, routes, rules, sshuttle pid)
logs/<vpn>.log       per-VPN log (rotated at 1 MB)
.mvm.json            settings
.venv/               textual + rich (created by bootstrap)
```

Example `configs/office.json`:

```json
{
  "name": "office",
  "kind": "nm-openvpn",
  "nm_uuid": "aab20b0d-....",
  "nm_name": "My Office VPN",
  "routes": ["10.20.0.0/16", "192.0.2.22/32"],
  "gateway": "auto",
  "autostart": false,
  "never_default": true,
  "ssh_remote": "",
  "ssh_args": "",
  "note": ""
}
```

## Troubleshooting

| Symptom | Fix |
|---|---|
| `sudo: a password is required` | `python3 mvm.py sudoers install` |
| Asked for the VPN password or PSK at every boot | `s` in the TUI, or `mvm secrets NAME`: stores **all** secrets in the profile |
| IP still goes out the normal connection | Troubleshoot → route health → `f` (re-apply). If another VPN uses its own routing table, add that table to *clean tables* in Settings. |
| sshuttle exits immediately | `mvm doctor NAME --deep`: SSH key login (use `ssh-copy-id`), Python on the remote, sudoers rule |
| Colours look banded or peach | `python3 mvm.py colors`; start with `--colors truecolor`, or `--colors 256` if the terminal has no 24-bit support |
| No journal lines in Logs | `sudo usermod -aG systemd-journal $USER`, then log out and back in |
