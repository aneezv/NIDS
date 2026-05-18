# Demo Commands Reference

A copy-paste-ready cheatsheet for the live demo. Every command here has
been tested against the `final-sprint` build of the detector. Replace
`10.0.0.50` with your victim VM's IP everywhere.

---

## VM roles at a glance

| VM | IP (default) | What runs here |
|---|---|---|
| Controller | wherever | `python app.py` + dashboard at `:5000/dashboard` |
| Sensor + victim | `10.0.0.50` | `sudo python3 sensor.py` (whitelisted from analysis) |
| Router | `10.0.0.1` | `start_router.sh` + ipset/iptables |
| Attacker | external IP | runs the commands in this file |

> The **attacker** VM is where you run both the normal traffic and the
> attack commands. From the model's perspective, the attacker is "an
> external source whose traffic is being analysed."

---

## ✅ Pre-demo sanity check (run 5 minutes before going live)

On the **attacker** VM:

```bash
cd attacker
./prepare_attack.sh                  # set up routing to victim subnet
ping -c 3 10.0.0.50                  # confirm reachability
```

On the **controller**, open the dashboard. Confirm:
- Alerts panel: empty
- Sensors panel: your sensor shows `online`, recent heartbeat, non-null CPU
- Blocked IPs: empty

If anything is firing already, fix it before showing the demo.

---

## 🟢 Normal Traffic Commands

These all produce traffic that the model is trained to recognise as
benign. Run them from the **attacker** VM (or any non-whitelisted
machine on the same VLAN).

### Tier 1 — bulletproof safe

```bash
# Ping — matches the `ping` training cluster
ping -c 20 -i 0.5 1.1.1.1

# DNS lookups — single UDP/53, matches `dns` cluster
dig @1.1.1.1 example.com
dig @8.8.8.8 kernel.org wikipedia.org

# Plain HTTP GET — single TCP/80, low rate
curl -v http://example.com

# Plain HTTPS GET — single TCP/443, low rate
curl -v https://example.com

# Download a single small file from a single server
wget -O /tmp/test.html http://example.com/
```

### Tier 2 — realistic user activity (still safe)

```bash
# Slow sustained download — matches `moderate` cluster (20-300 pps)
curl --limit-rate 200k -o /tmp/file \
    http://ipv4.download.thinkbroadband.com/10MB.zip

# Sequential website checks
for site in example.com kernel.org wikipedia.org gnu.org; do
    dig +short $site
    curl -s -o /dev/null -w "%{http_code} from $site\n" http://$site
    sleep 3
done

# Normal package update (apt is single-source, predictable)
sudo apt update
```

### Tier 3 — audience-visible browsing

For when you need a real-looking web session on screen:

```bash
# One-time install
sudo apt install -y w3m

# Text browser — single connection per site, no CDN drama
w3m https://www.kernel.org
w3m https://en.wikipedia.org/wiki/Intrusion_detection_system
```

### Ambient background traffic during the demo

```bash
# Runs continuously, touches a rotating set of safe single-domain servers.
# Keeps the dashboard populated with legitimate flows.
./normal_traffic.sh
```

Run this in a tmux pane before you start the live demo. The audience
sees the dashboard ticking with normal flows but zero alerts — that's
the "normal traffic isn't touched" story.

### ❌ Don't run these (will trigger false positives)

| Command | Why |
|---|---|
| `curl https://youtube.com` | CDN edge-server roulette |
| `curl https://google.com` | Same |
| Opening a desktop browser | DNS-prefetch + parallel CDN connections |
| `iperf3 -c <server>` | Indistinguishable from a UDP flood |
| `aria2c` / BitTorrent | Many peers = high `distinct_ports` (looks like a scan) |
| `nmap` on anything | Literally what we trained against |

---

## 🔴 Attack Commands

All confirmed working against the `final-sprint` build. Run from the
**attacker** VM. Each one shows a different feature signature the model
catches.

### 1. ICMP Ping Flood — easiest visceral demo

```bash
sudo hping3 -1 --flood 10.0.0.50
```

| Signature | Expected | Cluster |
|---|---|---|
| proto=1, port=0, frame≈64, very high rate | **100% conf, block in <10s** | `icmp_flood` |

Talking point: *"A classic layer-3 DDoS — the kind that knocks services offline by saturating bandwidth. Detected purely on rate."*

### 2. UDP Flood with randomised destination ports

```bash
sudo hping3 --udp --flood --destport ++0 10.0.0.50
```

| Signature | Expected | Cluster |
|---|---|---|
| proto=17, very high rate, **many `distinct_ports`** | **100% conf, immediate** | `udp_flood` (random-port variant) |

Talking point: *"More sophisticated — randomising destination ports tries to evade simple rate-based filters. Our system catches it because high port diversity from a single source is itself anomalous."*

### 3. SYN flood to an uncommon port

```bash
sudo hping3 -S --flood -p 4444 10.0.0.50
```

| Signature | Expected | Cluster |
|---|---|---|
| flags=0x02, port=4444 (not in normal training), high rate | **High conf, block fires** | `syn_flood` |

> ℹ️ **Don't** use port 80 or 22 — high-rate single-port SYN traffic to
> common web/SSH ports overlaps with normal heavy traffic in feature
> space. Uncommon ports give cleaner detection.

Alternative: incrementing-port SYN flood (catches via `distinct_ports`):

```bash
sudo hping3 -S --flood --destport ++0 10.0.0.50
```

### 4. Fast SYN scan — the classic recon attack

```bash
sudo nmap -sS -T4 10.0.0.50
```

| Signature | Expected | Cluster |
|---|---|---|
| flags=0x02, **distinct_ports = 100+** per 5s window | **100% conf, block in <5s** | `scan` |

### 5. Stealth SYN scan — the showpiece

```bash
sudo nmap -sS -T2 10.0.0.50
```

| Signature | Expected | Cluster |
|---|---|---|
| flags=0x02, distinct_ports = ~20-50 per 5s, low rate | **100% conf** | `scan` |

Talking point: *"At -T2 timing the scanner is throttling itself to avoid simple rate-based detection. But the **port diversity** signal is still loud — that's the feature we added specifically for this. The model wasn't told what a scan is; it learned the boundary of normal and a scan falls outside it."*

### 6. Slow stealth scan — the viva-defense moment

```bash
sudo nmap -sS -T1 10.0.0.50
```

| Signature | Expected | Notes |
|---|---|---|
| Very low rate, distinct_ports accumulates across 5s window | **100% conf** | The 5-second port-tracking window catches what rate-based detection can't |

If a judge asks "but what about *really* slow scans?" — the honest
answer is: at `-T0` (paranoid mode, 5+ minutes between probes) our 5s
window can't accumulate enough ports. That's an explicit knob — longer
window = catch slower scans = more memory. We chose 5s as a
practitioner's sweet spot.

---

## 🧹 Reset between demos

```bash
# Stop all attack tools cleanly
sudo pkill -f hping3
sudo pkill nmap

# Unban an IP via API (or use the dashboard's Unban button)
curl -X POST http://<controller>:5000/api/action/unban \
    -H "X-NIDS-Auth: $API_KEY" \
    -H "Content-Type: application/json" \
    -d '{"ip": "<attacker-ip>"}'
```

Or just wait 5 minutes — first-offense bans auto-expire (300s).

---

## 🎬 Recommended demo order (8-10 minutes)

| # | Step | Time | Narration |
|---|---|---|---|
| 1 | Start `./normal_traffic.sh` in a tmux pane | 0:00 | "Here's the network with normal traffic flowing. Notice the dashboard sees legitimate flows but raises no alerts." |
| 2 | Show a single `curl http://example.com` | 1:00 | "A user requests a webpage — completes cleanly, no alert. The system is paying attention but not interfering." |
| 3 | Run **ICMP flood** | 2:00 | "Now an attacker launches a volumetric attack." Show block fire. "Detected on rate, blocked at the router." |
| 4 | Wait 30s, show block in dashboard | 3:00 | "Block is time-limited — auto-expires after 5 minutes. Reversible enforcement is one of our design principles." |
| 5 | Run **stealth nmap scan** | 4:00 | "A more subtle attack — reconnaissance. The attacker is throttling to evade simple rate detection." Show block. "Caught via port-diversity, not rate. The model wasn't told what a scan is — it learned the boundary of normal." |
| 6 | Run **UDP rand-port flood** | 5:30 | "A sophisticated attack mixing volume and port diversity." Show block. |
| 7 | Whitelist the attacker IP via dashboard | 7:00 | "Operator-in-the-loop. The verification layer can be overridden." |
| 8 | Re-run the same attack — show no block | 7:30 | "Whitelisted IPs cannot be blocked. Human authority over ML signal — that's the core of our verification layer." |

---

## Troubleshooting on demo day

| Symptom | Fix |
|---|---|
| Sensor not running | `cd sensor && sudo python3 sensor.py` on victim VM |
| No alerts firing at all | Check sensor heartbeat in dashboard. If offline → restart sensor. |
| Alerts fire but no block | Check controller's `BLOCK_THRESHOLD` (default 35) and sensor trust. A low-trust sensor needs corroboration. |
| Attacker IP already banned from a previous test | Click "Unban" on dashboard OR wait 5 minutes. |
| Firewall scripts failing | `ls -la controller/block_ip.sh controller/unblock_ip.sh` — confirm they exist and are executable. |
