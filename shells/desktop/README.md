# Crux desktop shell

The Crux desktop shell is a Tauri v2 connection manager for the existing web
console. A named profile either starts the bundled `corecruxd` sidecar or
attaches to a daemon that is already running. The shell remains in-tree and is
workspace-excluded per OD-31; it does not add a second console implementation.

Milestone M1 implements both lifecycle modes and resolves OD-42 by reusing the
daemon's existing static agent-token bearer authentication for attach profiles.
It does not add a daemon authentication mechanism. The token is resolved by
native Rust through the operating-system credential client and injected by a
shell-owned loopback proxy. It is never placed in profile JSON, a URL, web
storage, page JavaScript, a Tauri command, or an operator-facing error.

## Architecture

```text
                                  attach profile
                           +---------------------------+
                           | existing corecruxd        |
                           | HTTP loopback or HTTPS    |
                           | static bearer auth        |
                           +-------------^-------------+
                                         | native HTTP; bearer injected here
+----------------------- Crux desktop shell ------------------------+
| OS credential store --> native broker --> 127.0.0.1:<ephemeral>  |
|                                            profile proxy          |
|                                                  ^                |
|                                                  | no Tauri IPC   |
|                                      Tauri webview /console       |
|                                                  |                |
| bundled profile                                 v                |
| lifecycle supervisor --> bundled corecruxd on loopback/auth off  |
+-------------------------------------------------------------------+
```

There are three crates, each with its own `[workspace]` so none joins the root
daemon workspace:

| Crate | Path | Local role |
|---|---|---|
| `crux-shell-lifecycle` | `lifecycle/` | Dependency-free sidecar spawn, readiness, shutdown, and Drop backstop. |
| `crux-shell-connection` | `connection/` | Lean profile store, URL policy, local-plan hashing and path authorisation, health model, finite backoff, platform credential broker, secret wrapper, and loopback proxy; its direct dependencies are exact-pinned `blake3` and `getrandom`. |
| `crux-desktop-shell` | `app/` | Thin Tauri integration, tray/window policy, and pinned Rustls HTTP adapter. Requires the WebKit/GTK toolchain on Linux. |

The app uses exact dependency pins. Its attach transport is `ureq =3.3.0` with
Rustls and normal WebPKI certificate and hostname validation. Redirect following,
environment proxy discovery, response decompression, and insecure TLS overrides
are disabled. Probes have a five-second per-request deadline; forwarded requests
have a 30-second deadline, so browser EventSource clients reconnect instead of
letting a quiet hostile stream retain an old profile token. Credential lookup
uses fixed platform clients, so no extra keychain crate or plaintext fallback
is present.

## Connection profiles

Non-secret connection configuration is stored durably as
`<Tauri app-data>/connection-profiles-v1.json`. The platform app-data root is
resolved by Tauri for application identifier `com.cuecrux.crux`; do not assume
a portable relative path. Replacement is atomic on Unix and uses a recoverable
same-directory backup sequence on Windows. The document is schema version 1 and
names exactly one active profile:

```json
{
  "schema_version": 1,
  "active_profile": "local",
  "profiles": [
    {
      "name": "local",
      "mode": "bundled",
      "url": "",
      "token-ref": null,
      "local-plan-root": "/home/operator/workspace/.agent/execplans"
    },
    {
      "name": "operations",
      "mode": "attach",
      "url": "https://crux.example.com",
      "token-ref": "operations-agent-token",
      "local-plan-root": null
    }
  ]
}
```

On first launch, an absent store is created with one active bundled profile
named `Local`. An invalid or unreadable existing store is not overwritten: the
window shows a native configuration error, profile actions are disabled, and
the operator must correct the file and restart Crux.

Profile names must be unique. A bundled profile has no token reference; its URL
is normally empty because the shell allocates the sidecar port. An attach
profile requires an origin-only URL and a `token-ref`. The reference is the
credential-store lookup key, not the bearer, and uses only ASCII letters,
digits, `.`, `_`, `~`, `-`, or `:` so it is safe at both fixed native-client
boundaries. Missing or unknown JSON fields are
rejected, which also prevents adding a plaintext `token` field. A missing,
locked, malformed, or unavailable credential fails closed and produces an
explicit native-owned status page.

`local-plan-root` is optional and defaults to `null` for schema-v1 profiles
created before M5a. When configured on the active profile, the shell hashes the
raw bytes of top-level `<slug>.md` files with BLAKE3 and exposes the immutable
slug-to-hash map at document start as `window.CRUX_LOCAL_PLAN_HASHES`. Without a
configured root, no hash map is injected. A profile switch builds a fresh
isolated webview with that profile's own initialization script; hashes never
transit through the outgoing page.

### Lifecycle ownership

| Mode | Daemon ownership | Authentication | Exit and switch behaviour |
|---|---|---|---|
| `bundled` | The shell starts the packaged sidecar through `crux-shell-lifecycle`. | Auth off on an ephemeral loopback port, unchanged from the shipped shell. | The shell shuts down only the sidecar handle it owns; shutdown and Drop preserve the no-orphan invariant. |
| `attach` | The operator or service manager owns an already-running daemon. | Existing static agent-token bearer, retrieved from the OS credential store. | The shell never starts, restarts, signals, or stops the daemon. Closing the app only stops the shell proxy. |

Switching changes and safely persists the active profile without restarting
the app. Every activation binds a new `127.0.0.1` ephemeral status-proxy port
before the webview is repointed; attach mode continues through that proxy after
it becomes ready, while bundled mode navigates directly to its live sidecar.
As soon as a switch reserves a new generation, the old proxy is synchronously
quiesced into a native status state: its shared forwarding credential is made
inactive, tracked sockets are closed, and a newly admitted request cannot reach
that upstream. A request already dispatched before quiescence retains only its
bounded 30-second transport budget while the old proxy performs a bounded drain.
The webview uses an in-memory/incognito browser profile, and the shell clears
browsing data before every profile switch; failure to clear blocks the switch.
Native status pages clear cache, cookies, and storage. The attach handshake
clears cache and storage before redirecting while preserving its newly minted
session cookie.
The different origin and clearing isolate web storage across profiles, while
forwarded daemon request and response cookie headers are removed.
Switching away from bundled mode releases only the shell-owned sidecar.
Switching away from attach mode cannot affect the external daemon.

## Credential provisioning

The daemon and credential store must contain the same static agent token. The
profile stores only the lookup reference. Tokens must be 32–256 bytes using the
daemon token alphabet: ASCII letters, digits, `.`, `_`, `~`, and `-`.
Attach credential lookup is implemented for Linux and Windows; unsupported
platforms fail closed. Bundled mode retains its existing platform support.

### Linux Secret Service

Runtime prerequisites are an active Secret Service provider in the user's
D-Bus session and the client at the fixed path `/usr/bin/secret-tool` (commonly
provided by the `libsecret-tools` package). Store the token under the exact
attributes used by the broker; this command reads the secret from standard
input rather than a command-line argument:

```bash
/usr/bin/secret-tool store --label='Crux operations agent token' \
  service com.cuecrux.crux token-ref operations-agent-token
```

Enter only the bearer when prompted. `operations-agent-token` must match the
profile's `token-ref`. A missing helper, absent D-Bus session, denied unlock,
locked collection, missing item, or lookup timeout is an unavailable
credential; the app does not consult an environment variable or file instead.

### Windows PasswordVault

Runtime lookup uses Windows Credential Manager through WinRT
`Windows.Security.Credentials.PasswordVault`, launched by the native host with
the fixed Windows PowerShell path. The credential resource is
`com.cuecrux.crux`; its user name is the profile's `token-ref`. Windows
PowerShell 5.1 and an accessible user Credential Locker are therefore runtime
prerequisites.

The following provisioning session prompts without putting the token in the
command history and clears the temporary unmanaged copy:

```powershell
$null = [Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
$secret = Read-Host 'Static agent token' -AsSecureString
$pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret)
try {
  $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
  $vault = New-Object Windows.Security.Credentials.PasswordVault
  $item = New-Object Windows.Security.Credentials.PasswordCredential(
    'com.cuecrux.crux', 'operations-agent-token', $plain)
  $vault.Add($item)
} finally {
  [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
  Remove-Variable plain, secret -ErrorAction SilentlyContinue
}
```

Replace `operations-agent-token` with the profile reference. Missing, locked,
denied, or timed-out PasswordVault access fails closed; there is no plaintext or
environment fallback.

## Transport and browser boundary

Attach URLs are origins only: no user information, base path, query, fragment,
backslash, or zero port. Exact `localhost` is normalized to `127.0.0.1` so it
does not depend on ambient DNS or hosts-file resolution.

| Attach URL | Result | Reason |
|---|---|---|
| `http://localhost:14800` | Allowed, normalized to `http://127.0.0.1:14800` | Exact localhost. |
| `http://127.0.0.1:14800` or `http://[::1]:14800` | Allowed | Literal loopback address. |
| `https://127.0.0.1:14800` | Allowed if its certificate validates normally | HTTPS is accepted; no certificate bypass exists. |
| `http://192.168.1.20:14800` or `http://crux.example.com` | Rejected | Plain HTTP is loopback-only. |
| `https://crux.example.com` | Allowed if its chain and hostname validate | Non-loopback origins require HTTPS. |
| `https://user@crux.example.com/base?x=1` | Rejected | Credentials, paths, queries, and fragments are outside the profile contract. |

For attach mode, the webview loads the shell's loopback proxy, never the daemon
origin. A one-time shell-minted URL secret establishes an HttpOnly,
`SameSite=Strict` proxy-session cookie; every forwarded method must present that
in-memory session ID before bearer injection. Browser origin/fetch evidence is
an additional check, while all caller cookies (including the proxy cookie),
authorization, forwarding, and hop-by-hop headers are removed upstream. It
disables upstream redirect following. Same-origin redirects are rewritten to proxy-relative locations;
foreign-origin, scheme-relative, and non-HTTP redirects such as `file://` are
blocked. `Set-Cookie`, refresh navigation, attachment responses, and unsafe
response headers are stripped or blocked. A reflected token blocks a response
header name or value and is replaced with `[REDACTED]` in a streamed response
body.

The default Tauri capability declares an empty permission list and no remote
URL grant. Profile, keychain, lifecycle, tray, and navigation operations stay in
native Rust; remote console content receives no Tauri IPC, filesystem, shell,
dialog, keychain, or updater permission. The bundled fallback document uses a
`default-src 'none'` CSP. Proxy responses replace daemon CSP headers with a
shell-owned same-origin policy and deny framing, referrers, privileged browser
features, and cross-origin resources. Navigation is limited to the active
profile proxy plus the live bundled-sidecar origin. An external HTTP(S) target
is denied in the webview and placed in a one-item native tray approval queue. A
`file:` navigation is likewise denied and may only queue a decoded path that
canonicalises to a real lowercase-`.md` file strictly inside the active
profile's canonical `local-plan-root`. The operator's native tray action
re-authorises a local path immediately before handoff. Scripted navigation
cannot spawn a handler or replace a pending target, and a profile switch
discards it. Traversal, symlink escape, outside absolute paths, other
extensions, directories, and missing files fail closed. Other schemes, new
windows, and downloads are denied. Linux handoff uses the fixed
`/usr/bin/xdg-open` client; Windows uses the system `rundll32.exe` handler.

## Health, status, and switching

Every activation probes `/healthz`, followed by `/v1/version`. The latter is
the forward-compatible hook for M2: schema-version-1 `runtime_capabilities` are
summarized while unknown fields, an absent descriptor, and future schema
versions are tolerated.

| Status | Meaning and rendering |
|---|---|
| `ok` | `/healthz` and `/v1/version` returned usable 2xx responses and no reported degradation was found. The console loads and the tray marks the profile healthy. |
| `degraded` | The daemon answered but reported `ok=false`, sync/capability degradation, a non-2xx response, or an unusable version descriptor. The reason is visible in the tray/status surface rather than discarded. |
| `unreachable` | The daemon cannot be reached, or native credential, transport, or startup work failed. The proxy renders an escaped native-owned error page instead of a blank webview. |

Before a probe completes, the status proxy serves a connecting page and the
tray reason says that a connection check is in progress. Attach retries are
finite and visible: the default exponential schedule permits five delays
(`250ms`, `500ms`, `1s`, `2s`, `4s`) after the initial probe and then leaves the
profile explicitly unreachable. Bundled startup retains the lifecycle crate's
bounded readiness budget and likewise stops at a rendered error. There is no
background infinite retry loop. The tray contains one status-bearing row per
profile plus explicit Retry and Quit actions. Retry or a new profile selection
starts a fresh bounded activation; bundled Retry restarts only the shell-owned
daemon.

## Local verification

Both support crates are WebKit-independent and can be checked on a host without
webkit2gtk. Lifecycle is std-only; connection has two exact-pinned direct
dependencies:

```bash
(cd shells/desktop/lifecycle && cargo fmt --check && cargo clippy --locked --all-targets -- -D warnings && cargo test --locked)
(cd shells/desktop/connection && cargo fmt --check && cargo clippy --locked --all-targets -- -D warnings && cargo test --locked)
```

The connection test suite contains checks for profile round-trip and
secret-field rejection, URL policy, schema-v1 health parsing, degradation and
unreachable states, bounded backoff, same-origin enforcement, bearer
replacement, the one-time session handshake, cookie enforcement/stripping and
rotation, credential-output validation, token redaction, and a hostile upstream
that returns cookies and foreign or `file://` redirects. M5a also covers raw-byte
plan hashes, missing/ignored plan roots, canonical path escape attempts, exact
origin matching, public-link classification, and stale generation rejection.

On a machine without the WebKit/GTK development packages, limit app checks to
formatting and structural validation:

```bash
rustfmt --edition 2021 --check shells/desktop/app/src/main.rs shells/desktop/app/src/upstream.rs
cargo metadata --locked --no-deps --manifest-path shells/desktop/app/Cargo.toml
python3 -m json.tool shells/desktop/app/tauri.conf.json >/dev/null
python3 -m json.tool shells/desktop/app/capabilities/default.json >/dev/null
typos shells/desktop/
git diff --check
```

The Linux job in `.github/workflows/desktop-shell.yml` is the compile gate for
the Tauri crate and must build it with the checked-in lockfile and WebKit/GTK
packages. Packaging still stages `corecruxd` into Tauri's `externalBin` slot;
the existing icon generation and platform signing/notarisation process is
unchanged.

## Operator validation checklist

Run the manual M1 security and lifecycle pass on packaged Linux and Windows
builds. Record platform, app build, daemon build, and date with the result.

- [ ] Configure one bundled profile and two attach profiles targeting different
      live daemons; provision distinct static tokens under their `token-ref`
      values.
- [ ] Switch between all profiles from the tray. Each console re-renders without
      restarting the app, browsing data from the prior origin is cleared, and
      the connecting page remains visible until the tray settles on
      `ok`/`degraded`/`unreachable`.
- [ ] Make an attach daemon unreachable. Confirm a reasoned native error page,
      the finite visible retry sequence, and no silent retry after exhaustion.
- [ ] Lock or disable the platform credential store and remove a credential.
      Confirm both cases fail closed with a sanitized state and do not read a
      token from profile JSON, environment, URL, console storage, or a file.
- [ ] Capture webview storage, HTTP traffic, and shell/daemon logs while using
      attach mode. Confirm the bearer appears only on the native proxy-to-daemon
      request and nowhere in browser-visible content or persisted shell data.
- [ ] Exercise a hostile daemon response containing `Set-Cookie`, a foreign
      redirect, a `file://` redirect, an attachment, and reflected token bytes.
      Confirm navigation/download is denied and no token reaches a response.
- [ ] Attempt Tauri IPC, a new window, a non-HTTP external scheme, and access
      from the previous profile origin. Confirm each is denied; confirm a normal
      external HTTP(S) link queues exactly one labelled tray approval and opens
      in the system browser only after that native action is selected. Confirm
      scripted repeats do not spawn handlers or replace the pending target.
- [ ] Switch bundled to attach and quit. The attach daemon must survive; the
      previously shell-owned sidecar and both profile proxies must not.
- [ ] Switch attach to bundled and quit. The external daemon must survive; the
      current bundled sidecar must shut down, with Drop/exit as the backstop.
- [ ] Repeat the existing clean-VM install, bundled-sidecar SHA, startup failure,
      and no-orphan checks before shipping an installer.

The runtime credential prompts, OS-store lock behaviour, system-browser handoff,
real WebKit navigation hooks, packet/log inspection, cross-daemon switching, and
process ownership assertions are intentionally operator-gated because the
headless development host cannot prove them.
