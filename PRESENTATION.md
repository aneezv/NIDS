# NIDS — Presentation Script & Viva Defense

> **A Verification-Based Perimeter IDS for Internet-Facing Server Networks**

This document is the speaking script and Q&A defense for the live demo.
Read it once before the presentation, glance at it during, refer to the
viva section if you get questions.

The framing of this entire project is a **perimeter IDS that protects
servers**, not an endpoint protection tool. That's the deliberate scope
decision that defines what we built and what we explicitly didn't.

---

## 🎯 The 30-second elevator pitch

> "Anomaly-based intrusion detection has a chronic problem: machine
> learning produces too many false positives to safely automate
> blocking. Block the wrong IP and you've DoS'd your own users.
>
> Our system separates **detection** from **enforcement** with a
> **verification layer** in between. The sensor uses an unsupervised
> Isolation Forest to flag potential threats. The controller aggregates
> evidence — frequency, multi-sensor corroboration, IP history, sensor
> trust — and only enforces if the verified confidence exceeds a
> threshold. The enforcement is time-limited and reversible at the
> router. The principle is: **ML is a signal, not an authority.**"

If you have to cut this for time, just say the last sentence.

---

## 📐 The threat model (slide this in early — it solves all the scope questions)

**Who we protect:** an internet-facing server network — webservers,
mail servers, APIs, game servers. The kind of network where the
protected hosts *receive* traffic from the public internet.

**Who we defend against:** external attackers performing volumetric
attacks (floods) or reconnaissance (port scans) against the protected
network.

**What we explicitly do NOT protect against:** endpoint/client-side
threats. Users browsing the web, malware on a user laptop, data
exfiltration from inside the network — those are different problem
classes with different deployment models. A perimeter IDS sits *in
front of* servers, not behind a user's browser.

**Why this framing matters:** every real IDS deployment — Snort,
Suricata, Cloudflare, AWS Shield — makes this same scope decision. It
isn't an excuse, it's how the technology is meant to be deployed.

---

## 🏗️ Architecture overview

```
        [ Public Internet ]
                │
                ▼
       [ IDS Sensor ]  ← captures packets via tshark, extracts 7 flow features
                │       per source IP, scores with Isolation Forest
                │
       (HTTP alert, signed with API key)
                │
                ▼
     [ Verification Controller ]  ← aggregates evidence:
                │                    - cumulative threat over time window
                │                    - multi-sensor evidence aggregation
                │                    - sensor trust score
                │                    - IP persistence across time buckets
                │                  ← only enforces if total > threshold
                │
     (shell exec block_ip.sh)
                │
                ▼
       [ Router Enforcement ]   ← ipset + iptables block, time-limited,
                                  reversible, IP whitelist-protected
```

Three components, three responsibilities, no single point of authority.

---

## 🧠 The Isolation Forest — choices we made and why

| Choice | Why |
|---|---|
| **Unsupervised** | Detects unknown attacks. A supervised model only catches what it was labelled on — useless against zero-days. |
| **Trained on normal-only data** | Textbook IF setup. Mixing attacks into training teaches the model that attacks are part of normal — which we observed empirically and fixed. |
| **7 features, including `distinct_dst_ports_per_window`** | The port-diversity feature is what makes scan detection work. A normal client hits 1-3 ports; a scan hits 30+. |
| **RobustScaler in the pipeline** | Handles outliers in feature scales (byte rates span 6 orders of magnitude). |
| **n_estimators = 300** | Past 300, Isolation Forest plateaus on this feature count. Wasted compute beyond that. |

### Why not deep learning?

> "Deep learning needs labelled data we don't have, doesn't generalise
> to unknown attacks any better than Isolation Forest in this setting,
> and adds significant inference cost. Our claim is system-level
> novelty — the verification layer — not algorithmic novelty in the
> classifier."

### Why not a hybrid model (RF + IF)?

> "We explored that. A RandomForest only flags what's similar to its
> training labels — which contradicts our 'detect unknown attacks'
> claim. We chose to stay pure unsupervised. The trade-off is some
> missed detections on attacks that look like normal traffic at the
> rate level; we cover this with cumulative scoring at the controller
> instead."

---

## 🛡️ The verification layer — the actual research contribution

This is what makes the project distinct from "we ran Isolation Forest
on packets."

For each incoming alert, the controller computes:

```
total_threat = cumulative_score          # sum of recent alerts for this IP
             + weighted_impact           # current alert × (sensor_trust / 100)
             + correlation_bonus         # +10 per extra reporting sensor (capped +20)
             + persistence_bonus         # +5 if seen in 3+ time-buckets in last hour
```

Then a **trust-adjusted threshold**:

| Sensor trust | Required threshold | Behaviour |
|---|---|---|
| ≥ 75 | base (35) | High-trust, standard bar |
| 40-74 | base × 1.5 (52.5) | Mid-trust, harder to block |
| < 40, multi-sensor | base × 2 (70) | Low-trust, very hard |
| < 40, single sensor | 999 (effectively never) | **Cannot block unilaterally** |

The last row is the key safety property: a single low-trust sensor
**cannot** trigger enforcement alone. Corroboration is required.

Verdicts:
- **BLOCK** — total > required → router enforcement fires
- **BORDERLINE** — total ≥ base but < required → queued for honeypot follow-up
- **UNVERIFIED** — total < base → no action, sensor trust decreases

Sensor trust adjusts on outcomes: +5 for correct block, -1 for whitelist false positive, and a slow decay back toward 50 over time (so no sensor is permanently "good" or "bad").

---

## 📊 Evaluation — what we can actually defend

**Held-out evaluation** (synthetic normal + attack samples, attack samples never in training):

- True positive rate: **92.2%**
- False positive rate: **13.4%**

**Targeted scenario tests** (`verify_model.py`, 15 hand-coded cases):

- 7/7 normal flows score 0% anomalous (including YouTube TCP/UDP,
  gaming, web browsing, Steam download, ping, multi-tab browsing)
- 3/3 scan variants caught at 100% (fast, stealth, slow-stealth)
- 4/5 flood variants in alert range (ICMP, UDP×2, TCP SYN)
- 1 edge case (TCP SYN flood at minimum rate / common port) overlaps
  with normal traffic in feature space — handled by cumulative scoring
  at the controller

Don't oversell the numbers. Say *"on our representative test set"*,
not *"in production"*.

---

## 🎬 Live demo flow (use this as a checklist during the demo)

Open the dashboard on the projector. Have a tmux pane with
`./normal_traffic.sh` already running. Refer to
`attacker/DEMO_COMMANDS.md` for the exact commands.

| Step | Say | Do |
|---|---|---|
| 1 | "Here's the network with normal traffic flowing." | Point at the dashboard — flows incrementing, zero alerts. |
| 2 | "Single user request — nothing fires." | `curl http://example.com` from attacker VM. |
| 3 | "Now a volumetric attack — classic ICMP flood." | `sudo hping3 -1 --flood 10.0.0.50` |
| 4 | "Caught on rate. Blocked at the router." | Show block in dashboard. Show `sudo ipset list` on router. |
| 5 | "More subtle — a reconnaissance scan, throttled to evade rate detection." | `sudo nmap -sS -T2 10.0.0.50` |
| 6 | "Caught on port diversity, not rate. The model wasn't told what a scan is — it learned the boundary of normal, and a scan falls outside." | Show block. This is the strongest moment of the demo — emphasise it. |
| 7 | "The operator can override." | Whitelist the attacker IP via the dashboard. |
| 8 | "Whitelisted IPs cannot be blocked — human authority over ML." | Re-run the attack. No block fires. |
| 9 | "Blocks are time-limited and reversible. The system fails safely." | Show expired block clearing from the table. |

If you finish early, you can add: low-trust sensor demo (cannot block
unilaterally), config-update via dashboard, honeypot queue browse. But
the 8 steps above are the core story.

---

## ❓ Viva Q&A — anticipated questions with prepared answers

### Scope / threat model questions

**Q: "What if a user behind your sensor browses YouTube? Won't your model block them?"**

> *"That's outside our threat model. We're a perimeter IDS protecting
> servers, not an endpoint protection system. The protected hosts run
> server software — they receive traffic, they don't initiate
> browsing. Endpoint protection has different requirements: per-host
> baselines, egress filtering, and a different enforcement model since
> you can't auto-block your own users. Every real perimeter IDS makes
> this same scope decision."*

**Q: "Can you detect data exfiltration?"**

> *"Not in this design. Exfiltration is an outbound threat with
> fundamentally different signals — upload/download asymmetry,
> destination reputation, per-host baselines. Our 7 features measure
> volume and port spread; none captures direction asymmetry. Extending
> to exfiltration would require an `upload_ratio` feature, baseline
> traffic profiles per internal host, and probably a different
> enforcement model — alert-and-investigate rather than auto-block."*

**Q: "What about application-layer attacks — SQL injection, XSS, command injection?"**

> *"Out of scope. We work at the network/transport layer — packets,
> ports, rates. Layer-7 attack detection requires HTTP-protocol
> parsing, payload inspection, and signature matching. That's what
> tools like ModSecurity do — they're complementary to us, not the
> same product."*

### Model / ML questions

**Q: "Why Isolation Forest? Why not a deep learning model?"**

> *"Three reasons. First, deep models need labelled data we don't have
> at sufficient scale for our threat space. Second, the claim we want
> to defend is detection of *unknown* attacks — Isolation Forest is
> built for that; deep classifiers are not. Third, our novelty is the
> verification layer, not the classifier. Adding deep learning would
> blow up inference cost without strengthening the actual contribution."*

**Q: "How do you handle concept drift — your model goes stale over time?"**

> *"Two mechanisms. First, periodic retraining on recent normal traffic
> — but with a strict filter: any traffic the controller verified as
> malicious is excluded from the retraining set. That prevents
> attackers from poisoning the model by sustained low-rate attacks
> they hope get learned as normal. Second, the sensor trust score
> decays over time, so a sensor's verdict carries less weight if it
> hasn't been corroborated recently."*

**Q: "What's your false-positive rate?"**

> *"On our held-out evaluation, 13.4% of normal samples score below
> the model's anomaly threshold. But that's just the model. The
> verification layer is what determines whether anything actually gets
> blocked — and it requires cumulative threat above 35, trust-adjusted
> up to 70, before enforcement fires. A single false-positive alert
> from a single sensor doesn't block anything. That's the design."*

**Q: "Why train on normal-only data?"**

> *"That's the textbook Isolation Forest setup. If you mix attack
> samples into training, the model learns that attacks are part of
> the normal distribution and stops flagging them. We actually
> discovered this empirically — our initial trainer mixed both classes
> and was missing 4 of 6 attack types. Switching to normal-only
> training jumped true-positive rate from 79% to 92%."*

**Q: "What if an attacker mimics normal traffic exactly?"**

> *"Then we won't catch it at the sensor — that's an honest limitation
> of any anomaly detector. But the verification layer's job is to be
> conservative: it requires multiple alerts, corroboration, and
> persistence over time. An attacker who perfectly mimics normal can't
> actually achieve their attack goal — flooding doesn't work at normal
> rates, scanning doesn't work at one-port-at-a-time. The attack
> primitive forces them outside normal."*

### System / verification layer questions

**Q: "What's actually novel about your verification layer?"**

> *"The architectural separation. Most academic anomaly-detection IDS
> papers stop at 'the model says anomalous → block.' That's the source
> of the false-positive problem. Our contribution is the explicit
> aggregation step between detection and enforcement — combining
> repeated evidence, multi-sensor corroboration, IP history, and
> trust-weighted scoring before any action. The verification layer is
> the safety mechanism; the ML is just one of its inputs."*

**Q: "Walk me through your trust-weighted scoring."**

> *"Every sensor starts at trust 50. A correct block adds 5; a
> whitelist-bypass false positive subtracts 1. The required threat
> threshold to trigger a block depends on the reporting sensor's
> trust — high-trust sensors need score 35, mid-trust need 52, low-trust
> need 70. A low-trust sensor alone literally cannot trigger
> enforcement — the required threshold becomes 999, which is
> unreachable. This means a compromised or misconfigured sensor can't
> unilaterally DoS the network."*

**Q: "What if a sensor is compromised?"**

> *"The trust system is the first line of defence — a compromised
> sensor whose alerts don't get corroborated by other sensors will
> drift to low trust and lose enforcement authority. The whitelist is
> the second line — admin-defined IPs are unblockable regardless of
> sensor verdict. And enforcement is reversible — even if a bad block
> fires, it's time-limited and the admin can manually unban."*

**Q: "Why time-limited blocks instead of permanent?"**

> *"Reversibility is a core principle. A wrong block is recoverable; a
> permanent ban based on a noisy ML signal is operationally
> dangerous. Time-limited blocks also handle dynamic IP addresses —
> blocking an IP that gets reassigned to an innocent user later is a
> real problem if your ban is forever."*

### Implementation questions

**Q: "Why ipset instead of just iptables rules?"**

> *"ipset uses a hash-based data structure — O(1) lookup regardless
> of how many IPs are blocked. Adding iptables rules linearly
> degrades packet processing speed. With ipset, the controller can
> block thousands of IPs without affecting throughput on the router."*

**Q: "How does the sensor scale?"**

> *"Each sensor handles its own packet processing locally — the
> controller only sees alerts, not raw traffic. The flow-state table
> is bounded to 10k entries with LRU eviction so a single sensor can't
> leak memory under attack. Multi-sensor deployment is supported by
> the controller — sensors send heartbeats every 30s and the
> verification layer can aggregate from multiple sources."*

**Q: "What happens if the controller crashes?"**

> *"Sensors queue alerts locally if the controller is unreachable —
> see `retry_worker` in sensor.py. The queue is unbounded in memory;
> long outages would eventually OOM the sensor, which is a real
> production concern we'd address with bounded queue + dead-letter
> handling. For the demo scale, the queue just drains when the
> controller comes back."*

---

## 🚧 Honest limitations (preempt these — say them yourself)

If you list these in your last slide BEFORE the Q&A, judges will
respect the honesty and stop asking gotcha questions. Frame each as
"this would be the natural next iteration":

1. **No application-layer detection.** Can't detect SQL injection,
   slowloris, or app-layer DDoS. Would need L7 inspection (ModSecurity
   complement).

2. **Slow-and-low scans below 5-second window granularity are missed.**
   `nmap -T0` paranoid mode (5+ min between probes) escapes our port
   accumulation window. Tunable: bigger window catches slower scans at
   the cost of memory.

3. **No outbound/exfiltration detection.** Outbound threats need
   different features (upload ratio, destination reputation) and a
   different enforcement model. Out of scope by design.

4. **Single-port high-rate SYN floods at common ports are borderline.**
   Overlaps with heavy normal traffic in feature space; cumulative
   scoring at the controller catches sustained attacks but single-shot
   demos are unreliable. Would benefit from a `syn_only_ratio` feature.

5. **Synthetic training data.** Our trainer generates realistic but
   synthetic flows. Production deployment would train on captured
   normal traffic from the actual protected network. The architecture
   supports this — the trainer is one file.

6. **Linux-only enforcement layer.** `ipset` and `iptables` are
   Linux-specific. Cross-platform deployment would need Windows
   Firewall / BSD pf adapters.

---

## 🎤 Closing line

> "Our contribution isn't a smarter classifier — it's a safer
> architecture for using an existing classifier. Anomaly detection
> alone isn't deployable in production because of false positives.
> Anomaly detection plus aggregation plus trust plus reversibility
> *is* deployable. That's what we built."

---

## Last checklist (do these the night before)

- [ ] Pull `final-sprint` branch on every VM
- [ ] Re-train the model on the sensor VM: `cd sensor && python3 train.py`
- [ ] Confirm `verify_model.py` shows 92% held-out TPR
- [ ] Confirm controller starts cleanly: `python app.py` on controller VM
- [ ] Confirm sensor heartbeats are arriving (dashboard shows sensor online)
- [ ] Confirm `./prepare_attack.sh` succeeds from attacker VM
- [ ] Test one attack end-to-end: `sudo hping3 -1 --flood 10.0.0.50` → block fires
- [ ] Reset state: `curl POST /api/action/unban` or wait for auto-expiry
- [ ] Record a backup screencast of the working demo — insurance against demo-day network failure
- [ ] Print this document, mark it up, rehearse the spoken parts twice
