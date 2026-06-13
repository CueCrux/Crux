# Crux README Demo Video — Production Brief

Companion to `readme-mockup-2026-06-12.html` (§2 video slot). Goal: the first-scroll asset that
**demonstrates the moat instead of claiming it** — store → query → tamper → verification fails loudly.

---

## 1. The two-cut strategy (don't make one video)

| | Cut A — README hero | Cut B — Intro / VO |
|---|---|---|
| Length | **40s** | **75–90s** |
| Audio | **None** (strip the track) | Voiceover + light music bed |
| Text | On-screen captions carry the story | VO carries it; captions still present |
| Where | GitHub README (uploaded mp4), docs quickstart | Website hero, X/LinkedIn, YouTube, launch post |
| Size | **≤ 10MB hard limit** (GitHub inline video) | No limit (host on site/YouTube) |
| Source | VHS terminal renders + console screen capture | Same footage + edited intro/outro |

Why silent-first for Cut A: GitHub's inline player **does not autoplay and most readers won't
enable sound**. If the story needs audio, the README cut fails. Record once, narrate Cut B only.

**Poster-frame trick:** GitHub uses the video's **first frame as the thumbnail**. Make frame one a
designed title card (logo + "Memory your agents can prove." + a subtle ▶ affordance). Hold it 2–3s.

---

## 2. Cut A — shot list (40s, 7 beats)

| # | Time | Screen content | Caption (on-screen, JetBrains Mono) |
|---|---|---|---|
| 1 | 0:00–0:03 | **Title card** (= poster frame): arc-loop logo, dark `#0B1322` bg | *Memory your agents can prove.* |
| 2 | 0:03–0:08 | Terminal: `docker compose up -d` → `✓ crux ready · :14800 http · :14801 mcp` (pre-pulled image — no download wait) | *One binary. No API keys.* |
| 3 | 0:08–0:15 | Store a fact (CLI or Claude Code MCP call) → response shows the receipt id `crown:e7a1…9c44` | *Every write returns a signed receipt.* |
| 4 | 0:15–0:22 | Query it: `--token-budget 500` → 1 hit · `312 tokens` in the output | *Retrieval under a hard token budget.* |
| 5 | 0:22–0:27 | **Console b-roll**: the **3D receipt-chain view** (see `docs/Images/Receipt.png`) — orbit briefly, click the new receipt block → inspector shows `✓ accepted` | *Verify any write — in-browser or offline.* |
| 6 | 0:27–0:36 | The kill shot: `dd` flips one byte in a segment file → `corecruxctl verify-store` → red `✗ TAMPER DETECTED — chain broken at receipt N` | *Flip one byte. The chain breaks loudly.* |
| 7 | 0:36–0:40 | **End card**: "Don't believe this README — verify it." + `docker compose up -d` + repo URL | — |

Beat rules: no beat longer than ~9s; beat 6 gets the most time (it's the moat); cut every pause —
if a command takes 4s, show 1s of spinner then jump-cut to the result.

---

## 3. Cut B — VO script (~85s, ~205 words @ ~145 wpm)

Reuses all Cut A footage; adds ~15s intro (problem) and ~15s outro (platform + CTA), plus 5–10s of
console/passport b-roll mid-piece.

> **[0:00 – hook, over title card + quick agent-forgetting montage or just the title]**
> "Every AI agent has the same problem: it forgets. And every memory tool has the same answer —
> trust us. Crux takes a different position: don't trust anything. Verify it."
>
> **[0:12 – over beat 2]**
> "Crux is a local-first memory daemon. One command, one binary — no API keys, and nothing ever
> leaves your machine."
>
> **[0:22 – over beat 3]**
> "Every fact your agent stores comes back with a cryptographically signed receipt."
>
> **[0:30 – over beat 4]**
> "Retrieval takes a hard token budget — the daemon trims to fit, so your context window stays
> yours."
>
> **[0:40 – over beat 5 + passport/coord b-roll]**
> "The embedded console shows every write, who made it, at what trust tier — and verifies the
> signature in the browser."
>
> **[0:52 – over beat 6, let the red error breathe]**
> "And if anything — anyone — tampers with the store? Flip a single byte… and the chain breaks.
> Loudly. Offline. No vendor required."
>
> **[1:08 – outro, over end card / platform diagram]**
> "Crux. Memory, retrieval, and receipts for AI agents. Standalone by design — platform by choice.
> docker compose up, and own your agent's memory."

VO delivery notes: calm, dry, slightly amused at beat 6 — the product is confident, not shouty.
Record at 48kHz, mono is fine, -16 LUFS for web.

---

## 4. Recording specs

### Terminal beats (2, 3, 4, 6) — use VHS (charmbracelet/vhs)
Reproducible per release; re-render instead of re-recording. One `.tape` per beat → edit together.

```tape
# docs/demo/tapes/02-quickstart.tape
Output renders/02-quickstart.mp4
Set FontFamily "JetBrains Mono"
Set FontSize 22
Set Width 1920
Set Height 1080
Set Padding 60
Set TypingSpeed 35ms
Set Theme { "background": "#0B1322", "foreground": "#E8EEF7", "green": "#22C55E", "red": "#F26D6D", "yellow": "#F5B041" }
Hide
Type "export PS1='$ '" Enter
Type "clear" Enter
Show
Sleep 800ms
Type "docker compose up -d"
Enter
Sleep 2.5s
```

Rules:
- Font ≥ 22pt at 1080p — README videos get watched at half-width; small text dies.
- Pre-seed `./demo-data` with a seed script so queries return instantly; **pre-pull the image**.
- Scratch data dir + throwaway tokens only. Never a real `/data`, never a real JWT on screen.
- Keep the tapes + seed script in `docs/demo/` — that's the "re-recordable every release" promise.
- Beat 6 tamper command: `printf '\x00' | dd of=./demo-data/shards/seg-000007.crux bs=1 seek=1337 conv=notrunc`
  — verify the real `verify-store` output format first and let the red line sit on screen ~3s.

### Console beats (5, b-roll) — screen capture
- Lead with the **3D views** (receipt chain, work graph — `docs/Images/Receipt.png` /
  `Execplan 3D.png` show what to frame). They're the most cinematic 5 seconds available and
  nothing competitors have. A slow orbit + one click + inspector slide-in is the whole shot.
- 1920×1080 browser window, **125% zoom**, bookmarks bar hidden, demo-seeded data (no real
  execplan slugs / live session ids — coordinate with what the mockup screenshots will show).
- OBS or any 60fps capture; move the cursor slowly and deliberately; one action per shot.
- Dark console theme to match the terminal renders.

### Title/end cards
- Build in the editor (or export from the mockup's hero styling): `#0B1322` bg, arc-loop logo,
  JetBrains Mono. Title card doubles as the GitHub poster frame — make it composition-perfect.

---

## 5. Edit & encode

- Editing: hard cuts > crossfades; captions bottom-left in JetBrains Mono with the README accent
  colors (green/cyan/amber per beat); 2–4 frame "punch" on the TAMPER DETECTED reveal is the one
  permitted flourish. Respect the beat table — total ≤ 40s.
- Frame rate 30fps (terminal content gains nothing from 60).
- **Cut A encode (target ≤ 9.5MB):**
  ```bash
  ffmpeg -i cutA-master.mov -an -vf "scale=1920:-2,fps=30" \
    -c:v libx264 -preset slow -crf 27 -pix_fmt yuv420p readme-demo.mp4
  ```
  Terminal footage is flat-color and compresses extremely well — 1080p/40s lands ~5–8MB at crf 27.
  If over budget: crf 29, then 1600px wide. `-an` strips audio (bytes + silent-first by design).
- **Cut B encode:** same video settings, keep audio `-c:a aac -b:a 128k`, no size constraint.
- Embed in README: drag-drop the mp4 into the README editor on github.com (it uploads to
  user-attachments and renders inline). Markdown `![]()` does NOT render video — must be the
  uploaded-attachment URL on its own line.

---

## 6. QA checklist before shipping

- [ ] Frame 1 is the title card (check the GitHub thumbnail after upload)
- [ ] Watchable and fully comprehensible **muted** (Cut A has no audio track at all)
- [ ] Legible at 50% size (phone test)
- [ ] No secrets/tokens/real paths/real session ids in any frame (scrub frame-by-frame at beats 3–6)
- [ ] `verify-store` output in beat 6 matches the real CLI (don't fake the moat shot)
- [ ] ≤ 10MB; plays inline on a draft README in a private repo first
- [ ] Tapes + seed script committed under `docs/demo/` so the next release can re-render
- [ ] Cut B VO claims match the README's verified claims (no numbers that aren't in the repo)
