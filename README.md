# Ansible Role: Threat Hunting ([Ludus](https://ludus.cloud))

An Ansible Role that installs [Zeek](https://github.com/zeek/zeek) and
[RITA](https://github.com/activecm/rita) on a Debian or Ubuntu host, turning it
into a network threat hunting sensor for a Ludus range.

Zeek sniffs an interface and rotates protocol logs hourly. RITA imports those
logs into ClickHouse and scores host pairs for beaconing, long connections,
DNS tunneling, strobes, and threat intel hits - the analysis you would
otherwise do by hand against `conn.log`.

The role has two modes, set with `ludus_threat_hunting_mode`:

| Mode | Runs on | Does |
| --- | --- | --- |
| `sensor` (default) | Debian / Ubuntu | Zeek + RITA + ClickHouse, receives agent traffic, scores it |
| `agent` | Debian / Ubuntu / Windows | Mirrors a copy of the victim's own traffic to the sensor |

> [!IMPORTANT]
> A VM only sees its own traffic by default. Either put agents on the victims
> (below) or mirror at the hypervisor - otherwise Zeek runs happily and
> produces logs containing nothing but the sensor's own conversations.

> [!WARNING]
> RITA discards internal→internal connections at import time. RITA's stock
> `internal_subnets` is all of RFC1918, and every host in a Ludus range is
> RFC1918 - so the stock config throws away essentially all range traffic.
> This role defaults to something that works in a range instead. See
> [Internal subnets](#internal-subnets-read-this).

## Requirements

**Sensor:**

- A Debian 12/13 or Ubuntu 22.04/24.04 VM.
- 4+ CPU, 8+ GB RAM, and 50+ GB disk. ClickHouse and Zeek are both memory and
  disk hungry; a 2 GB VM will OOM during import.
- Outbound internet access on the VM at deploy time (apt repositories, GitHub
  releases, Docker Hub / GHCR).

**Agents:**

- Linux: Debian 12/13 or Ubuntu 22.04/24.04. No internet access needed beyond
  `iproute2`, which is already present on Ludus templates.
- Windows: Windows 10 2004+ / Server 2022+ for the default `pktmon` backend.
  Server 2019 and Windows 10 1809 ship an older `pktmon` with different flags
  and will not work - use the `dumpcap` backend there.
- Ansible collections `ansible.windows` and `community.windows` for Windows
  agents. Both ship with the `ansible` package that Ludus installs.

## What gets installed

Sensor mode:

| Component | Source | Lands at |
| --- | --- | --- |
| Docker Engine + compose v2 | `download.docker.com` apt repo | system |
| Zeek | `security:zeek` OBS apt repo | `/opt/zeek` |
| RITA v5 | GitHub release installer tarball | `/usr/local/bin/rita`, `/opt/rita`, `/etc/rita` |
| ClickHouse + syslog-ng | RITA's docker compose stack | containers |
| Import timer | this role | `ludus-rita-import.timer` |
| Mirror receiver (optional) | this role | `zeek-mirror-receiver.service`, `zeek-pcap-receiver.service` |

Agent mode:

| Component | Platform | Lands at |
| --- | --- | --- |
| GRE mirror via `tc mirred` | Linux | `zeek-mirror-agent.service` |
| `pktmon` / `dumpcap` streamer | Windows | `ZeekMirrorAgent` scheduled task, `C:\ludus\threat_hunting\` |

## Role Variables

Available variables are listed below, along with default values (see
`defaults/main.yml`):

    # sensor -> Zeek + RITA analysis host (Debian/Ubuntu only)
    # agent  -> victim machine that mirrors its own traffic to a sensor
    ludus_threat_hunting_mode: sensor

### Sensor components

    # Install Docker Engine + the compose v2 plugin. RITA requires both.
    # Set to false if Docker is already installed by another role.
    ludus_threat_hunting_install_docker: true

    # Install and configure Zeek (the sensor).
    ludus_threat_hunting_install_zeek: true

    # Install and configure RITA (the analysis engine).
    ludus_threat_hunting_install_rita: true

### Zeek

    # Package from the security:zeek OBS repository.
    #   zeek      -> current feature release
    #   zeek-lts  -> current long term support release (recommended)
    #   zeek-7.0  -> a specific pinned feature branch
    ludus_threat_hunting_zeek_package: zeek-lts

    # Install prefix used by the OBS packages.
    ludus_threat_hunting_zeek_prefix: /opt/zeek

    # Interface Zeek sniffs. Empty means the VM's default route interface.
    ludus_threat_hunting_zeek_interface: ""

    # Set promiscuous mode and disable NIC offloads on the sniffing interface.
    ludus_threat_hunting_zeek_tune_interface: true

    # Networks written to networks.cfg (Site::local_nets).
    # Empty means "derive from the sensor's own /24".
    ludus_threat_hunting_zeek_local_networks: []

    # Log rotation interval in seconds. The import timer assumes hourly.
    ludus_threat_hunting_zeek_log_rotation_interval: 3600

    # Emit JSON logs instead of Zeek's default TSV. RITA reads both.
    ludus_threat_hunting_zeek_json_logs: false

    # Extra @load lines appended to the site script.
    ludus_threat_hunting_zeek_extra_scripts: []

    # Run `zeekctl cron` every 5 minutes to restart crashed workers.
    ludus_threat_hunting_zeek_enable_cron: true

### RITA

    ludus_threat_hunting_rita_version: v5.1.2

    # Optional tarball checksum, e.g. "sha256:abc123...". Undefined = skip.
    # ludus_threat_hunting_rita_checksum: "sha256:..."

    # Dataset name RITA imports into and `rita view` reads from.
    ludus_threat_hunting_rita_database: ludus

    # Subnets RITA treats as internal. Empty means "the sensor's own /24".
    # Read the "Internal subnets" section below before changing this.
    ludus_threat_hunting_rita_internal_subnets: []

    # Always keep connections touching these, overriding every other filter.
    ludus_threat_hunting_rita_always_included_subnets: []
    ludus_threat_hunting_rita_always_included_domains: []

    # Drop connections touching these at import time. Useful for muting the
    # Ludus router, DNS server, and update mirrors.
    ludus_threat_hunting_rita_never_included_subnets: []
    ludus_threat_hunting_rita_never_included_domains: []

    # Drop inbound external->internal connections. Leave true for C2 hunting;
    # set false if you also want to see scanning against the range.
    ludus_threat_hunting_rita_filter_external_to_internal: true

    # Threat intel feeds, one IP or domain per line at the far end.
    ludus_threat_hunting_rita_online_feeds:
      - https://feodotracker.abuse.ch/downloads/ipblocklist.txt

    # Local feed files written to /etc/rita/threat_intel_feeds/.
    # Each entry: {name: my-c2.txt, content: "10.2.10.99\nevil.example.com\n"}
    ludus_threat_hunting_rita_custom_feeds: []

    # Phone home to check for a newer RITA release on every run.
    ludus_threat_hunting_rita_update_check: false

    # Minimum unique connections before a host pair is scored for beaconing.
    ludus_threat_hunting_rita_beacon_unique_connection_threshold: 4

### Automated import

    # Install a systemd timer that imports each rotated hour of Zeek logs.
    ludus_threat_hunting_rita_import_enabled: true

    # systemd OnCalendar expression. Default fires 10 minutes past the hour so
    # zeekctl has finished rotating and compressing.
    ludus_threat_hunting_rita_import_oncalendar: "*-*-* *:10:00"

    # Import as a rolling dataset. Required for RITA's first-seen scoring.
    ludus_threat_hunting_rita_import_rolling: true

### Mirror receiver (sensor mode)

    # Build the aggregation bridge and point Zeek at it instead of the NIC.
    ludus_threat_hunting_mirror_enabled: false

    # Bridge Zeek sniffs when the mirror receiver is enabled.
    ludus_threat_hunting_mirror_bridge: zeekmon0

    # IPs of Linux agents sending GRE mirrors here. One gretap device each.
    ludus_threat_hunting_mirror_gre_agents: []

    # Accept pcap streams from Windows agents. One listener serves all.
    ludus_threat_hunting_mirror_accept_pcap_stream: false
    ludus_threat_hunting_mirror_pcap_stream_port: 4789

### Agent mode

    # IP of the sensor to mirror to. Required when mode is agent.
    ludus_threat_hunting_sensor_ip: ""

    # Interface to mirror. Empty means the default route interface.
    ludus_threat_hunting_agent_interface: ""

    # GRE tunnel MTU on Linux agents.
    ludus_threat_hunting_agent_gre_mtu: 1462

    # Windows agents stream pcap over TCP to this port on the sensor.
    ludus_threat_hunting_agent_stream_port: 4789

    # Windows capture backend: pktmon (built in) or dumpcap (needs Npcap).
    ludus_threat_hunting_agent_windows_backend: pktmon

    # Working directory on Windows agents.
    ludus_threat_hunting_agent_windows_path: C:\ludus\threat_hunting

    # Seconds of traffic per pktmon capture cycle.
    ludus_threat_hunting_agent_pktmon_chunk_seconds: 60

    # dumpcap backend only.
    ludus_threat_hunting_agent_dumpcap_path: C:\Program Files\Wireshark\dumpcap.exe
    ludus_threat_hunting_agent_windows_interface: 1

    # Extra BPF appended to the Windows dumpcap capture filter.
    ludus_threat_hunting_agent_capture_filter: ""

## Internal subnets (read this)

RITA is built for perimeter monitoring. At import time it drops any connection
where **both** endpoints are inside `internal_subnets`, on the assumption that
you only care about traffic leaving your network. Its shipped default is:

```
10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fd00::/8
```

Every host in a Ludus range lives in `10.x.x.x`. Using RITA's default here
means every beacon from a range workstation to a range C2 VM is filtered out
before it is ever scored, and `rita view` shows an empty dataset.

This role therefore defaults `internal_subnets` to **the sensor's own /24
only**. Traffic from the sensor's VLAN to any other VLAN - including your C2
VM - is then internal→external, and gets scored normally.

Pick the shape that matches your scenario:

| Scenario | Setting |
| --- | --- |
| C2 VM on another VLAN in the range (typical) | leave the default |
| C2 on the real internet, range is "the network" | set to the RFC1918 list below |
| Hunting one specific victim VLAN, everything else is "outside" | set to that VLAN's /24 |

```yaml
role_vars:
  ludus_threat_hunting_rita_internal_subnets:
    - 10.0.0.0/8
    - 172.16.0.0/12
    - 192.168.0.0/16
    - fd00::/8
```

Also worth muting the range infrastructure so it does not dominate the
results - the Ludus router at `.254` is both the DNS server and the default
gateway for every VM, so it appears in nearly every connection:

```yaml
role_vars:
  ludus_threat_hunting_rita_never_included_subnets:
    - "{{ ludus_dns_server }}/32"
```

## Agents

A Proxmox VM's NIC only receives frames addressed to it plus broadcast, so the
sensor cannot see victim traffic on its own. Agent mode solves that from
inside the guest: each victim duplicates its own traffic to the sensor, no
hypervisor access required.

Everything converges on one bridge, so there is still exactly one Zeek
instance, one log directory, and one RITA dataset regardless of agent count:

```
 linux victim                                     sensor
 ┌────────────────────────┐                  ┌──────────────────────────┐
 │ eth0 ──tc mirred──▶ zmirtx ──GRE─────────▶│ zmir0 ─┐                 │
 └────────────────────────┘                  │        ├─▶ zeekmon0 ─▶ zeek
 ┌────────────────────────┐                  │ zmir1 ─┘        ▲        │
 │ eth0 ──tc mirred──▶ zmirtx ──GRE─────────▶│                 │        │
 └────────────────────────┘                  │                 │        │
 ┌────────────────────────┐   pcap over TCP  │  socat ─▶ editcap ─▶ tcpreplay
 │ pktmon / dumpcap ──────────────────:4789─▶│                          │
 └────────────────────────┘                  └──────────────────────────┘
   windows victim                                   ─▶ /opt/zeek/logs ─▶ rita
```

### Linux agents

`tc mirred` clones every frame on the victim's interface into a `gretap`
tunnel terminated on the sensor. Both directions are covered - an ingress
qdisc for inbound, a root qdisc for outbound. Nothing is captured to disk and
no analysis runs on the victim.

The egress side carries one guard worth knowing about: once mirroring is on,
the GRE packets the agent generates are themselves outbound traffic on the
same interface. A higher-priority `flower` filter matches GRE destined for the
sensor and passes it through unmirrored, which is what stops the host from
drowning in its own feedback.

### Windows agents

Windows has no kernel packet-mirroring primitive - no `tc mirred` equivalent,
no supported way to hand frames to a remote host as they are forwarded. So the
agent captures and streams instead. The sensor injects whatever arrives onto
the same bridge, so from Zeek's side the two agent types are identical.

| Backend | Needs | Latency | Trade-off |
| --- | --- | --- | --- |
| `pktmon` (default) | nothing, built into Windows | ~1 capture cycle | blind window while each chunk uploads |
| `dumpcap` | Npcap/Wireshark pre-installed | live | none, but see below |

The default is `pktmon` because it needs nothing installed. It cannot stream,
so traffic is captured in fixed chunks, converted with `pktmon etl2pcap`, and
uploaded between captures. Capture and upload never overlap, which is exactly
what keeps the agent from recording its own upload and amplifying it - the
cost is a short blind window each cycle.

> [!NOTE]
> This role does **not** install Npcap. Npcap's free installer has no silent
> mode, so it cannot be automated. To use the `dumpcap` backend, install
> Wireshark (which bundles Npcap) into the Ludus template first; the role
> asserts that `dumpcap.exe` exists and fails clearly if it does not.

### Alternative: mirror at the hypervisor

If you would rather not touch the victims, mirror at the Ludus host instead.
`<victim-tap>` and `<sensor-tap>` are the `tapXXXiY` interfaces of the two
VMs, visible with `ip link`:

```bash
# ingress (traffic into the victim)
tc qdisc add dev <victim-tap> ingress
tc filter add dev <victim-tap> parent ffff: matchall \
    action mirred egress mirror dev <sensor-tap>
# egress (traffic out of the victim)
tc qdisc add dev <victim-tap> handle 1: root prio
tc filter add dev <victim-tap> parent 1: matchall \
    action mirred egress mirror dev <sensor-tap>
```

Tap interfaces are recreated on VM start, so this is not persistent - re-run
after redeploying the range. Leave `ludus_threat_hunting_mirror_enabled` off
when doing this; the sensor should sniff its own NIC.

## Usage

Verify the sensor is capturing:

```bash
zeekctl status
ls /opt/zeek/logs/current/
```

Check the import timer:

```bash
systemctl list-timers ludus-rita-import.timer
journalctl -u ludus-rita-import.service -n 50
```

Import manually (any directory of Zeek logs):

```bash
rita import --database=ludus --logs=/opt/zeek/logs/2026-08-03 --rolling
```

Browse results in the terminal UI, or dump CSV:

```bash
rita view ludus
rita view ludus --stdout > findings.csv
```

Reset a dataset after changing filters - filtering happens at *import* time,
so config changes do not apply retroactively:

```bash
rita delete ludus
rita import --database=ludus --logs=/opt/zeek/logs/2026-08-03 --rebuild
```

### Checking agents

On the sensor, confirm the bridge exists and agent devices are enslaved to it:

```bash
ip -br link show master zeekmon0
systemctl status zeek-mirror-receiver zeek-pcap-receiver
# packets should be climbing
tcpdump -ni zeekmon0 -c 20
```

On a Linux agent, confirm the tunnel and the mirror filters:

```bash
systemctl status zeek-mirror-agent
tc -s filter show dev eth0 parent ffff:   # inbound mirror, with counters
tc -s filter show dev eth0 parent 1:      # outbound: pass rule then mirror
```

On a Windows agent:

```powershell
Get-ScheduledTask ZeekMirrorAgent | Get-ScheduledTaskInfo
Get-Content C:\ludus\threat_hunting\agent.log -Tail 20
```

## Dependencies

None. Windows agents use the `ansible.windows` and `community.windows`
collections, both of which ship with the `ansible` package Ludus installs.

## Example Playbook

```yaml
- hosts: threat_hunting_hosts
  roles:
    - Whispergate.ludus_threat_hunting
  vars:
    ludus_threat_hunting_rita_database: hunt
    ludus_threat_hunting_zeek_interface: ens19
```

## Example Ludus Range Config

```yaml
ludus:
  - vm_name: "{{ range_id }}-hunter"
    hostname: "{{ range_id }}-HUNTER"
    template: ubuntu-24.04-x64-server
    vlan: 20
    ip_last_octet: 50
    ram_gb: 8
    cpus: 4
    linux: true
    roles:
      - whispergate.ludus_threat_hunting
    role_vars:
      ludus_threat_hunting_rita_database: hunt
      # Mute the range router so it does not dominate every finding
      ludus_threat_hunting_rita_never_included_subnets:
        - "{{ ludus_dns_server }}/32"
      # RITA enforces a minimum of 4 for this value
      ludus_threat_hunting_rita_beacon_unique_connection_threshold: 4
      # Receive from the agents below
      ludus_threat_hunting_mirror_enabled: true
      ludus_threat_hunting_mirror_gre_agents:
        - 10.{{ range_second_octet }}.20.52          # the Linux victim
      ludus_threat_hunting_mirror_accept_pcap_stream: true

  - vm_name: "{{ range_id }}-victim-win"
    hostname: "{{ range_id }}-VICTIM-WIN"
    template: win11-22h2-x64-enterprise-template
    vlan: 20
    ip_last_octet: 51
    ram_gb: 4
    cpus: 2
    windows:
      sysprep: true
    roles:
      - whispergate.ludus_threat_hunting
    role_vars:
      ludus_threat_hunting_mode: agent
      ludus_threat_hunting_sensor_ip: 10.{{ range_second_octet }}.20.50

  - vm_name: "{{ range_id }}-victim-lin"
    hostname: "{{ range_id }}-VICTIM-LIN"
    template: ubuntu-24.04-x64-server
    vlan: 20
    ip_last_octet: 52
    ram_gb: 2
    cpus: 2
    linux: true
    roles:
      - whispergate.ludus_threat_hunting
    role_vars:
      ludus_threat_hunting_mode: agent
      ludus_threat_hunting_sensor_ip: 10.{{ range_second_octet }}.20.50
```

Agent IPs have to be written out on the sensor because a role only ever sees its own host's facts; there is no cross-VM discovery.

Deploy the sensor first so the listener is up before agents start sending:

```bash
ludus range deploy -t user-defined-roles --limit "{{ range_id }}-hunter"
ludus range deploy -t user-defined-roles \
    --limit "{{ range_id }}-victim-win,{{ range_id }}-victim-lin"
```

Install and iterate on the role locally with:

```bash
ludus ansible roles add -d ./ludus_threat_hunting --force
ludus range deploy -t user-defined-roles --limit "{{ range_id }}-hunter" \
    --only-roles ludus_threat_hunting
```

## Notes and limitations

- **Standalone Zeek only.** One process, one interface. A cluster layout needs
  an AF_PACKET or PF_RING load balancer plugin that the OBS packages do not
  ship, and pays off only above roughly 1 Gbps sustained.
- **Import granularity is one hour.** The timer imports the previous rotated
  hour, so findings lag live traffic by up to ~70 minutes. For a demo, run
  `rita import` by hand against `/opt/zeek/logs/current/`.
- **Beacon scoring needs time.** RITA's duration and histogram subscores want
  6–12 hours of coverage. A 20-minute capture will surface strobes and threat
  intel hits but score beacons poorly.
- **Filters apply at import.** Changing `internal_subnets` or the
  never/always lists does nothing to already-imported data. Re-import with
  `--rebuild`.
- **RITA's ClickHouse volume grows without bound.** Stop the stack and
  `docker volume rm rita_clickhouse_persistent` to reclaim it.

### Agent-specific

- **Mirroring doubles the victim's egress.** Every frame is sent twice, once
  to its real destination and once to the sensor. On a busy victim this is
  visible in throughput and, on Windows, in CPU.
- **The mirror is not invisible.** A GRE tunnel to the sensor and a
  `ZeekMirrorAgent` scheduled task are both trivially discoverable from inside
  the guest. This is instrumentation for a lab, not a covert collector - if
  the scenario involves an attacker with local admin who looks around,
  mirror at the hypervisor instead.
- **GRE fragments at full MTU.** A mirrored 1500-byte frame plus GRE headers
  exceeds the underlay MTU, so tunnels are created `nopmtudisc ignore-df` and
  the outer packet fragments. If the range path MTU is below 1500, lower
  `ludus_threat_hunting_agent_gre_mtu`.
- **Windows `pktmon` has a blind window.** Capture stops during each upload,
  so roughly the upload duration of every cycle is missed. Shorten
  `ludus_threat_hunting_agent_pktmon_chunk_seconds` to reduce the gap, or use
  the `dumpcap` backend if Npcap is available.
- **Agent lists are static.** The sensor creates one gretap per entry in
  `ludus_threat_hunting_mirror_gre_agents`. Adding a Linux agent means
  re-running the role against the sensor too.
- **Untested paths.** The role has not been deployed against a live Ludus
  range from this workspace. The Windows `pktmon` → `etl2pcap` → TCP →
  `editcap` → `tcpreplay` chain in particular is the least exercised part -
  verify with `tcpdump -ni zeekmon0` on the sensor before trusting an empty
  RITA dataset to mean "no findings".

## License

BSD 2-Clause
