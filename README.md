# J.O.S.H. Bug Bounty Workbench




J.O.S.H. is a local helper for authorized bug-bounty research. It checks a target against the scanner operator's exact host allowlist, runs bounded passive checks, asks AI to explain observed indicators when configured, and prepares an editable claim draft for the researcher to review.

## Start the dashboard
<img width="903" height="276" alt="image" src="https://github.com/user-attachments/assets/292c78ee-7d5e-4733-8c15-ebe15a33c9c0" />

Python 3.9 or newer is required; there are no third-party Python packages.

Add one exact hostname per line to `allowed_hosts.txt` in the project folder. `working_targets.txt` lists copyable URLs whose hostnames are in that file. These files control what J.O.S.H. can contact; they do not establish that a bounty program authorizes testing. Check the program's scope and rules before each assessment.

Start the dashboard from PowerShell or CMD:

```powershell
py -3 sources\jam.py
```

Or use the Bash launcher:

```bash
bash 'shell scripts/frontend/wat-frontend.bash'
```

Open `http://127.0.0.1:8000`. J.O.S.H. also rejects hosts resolving to non-public IP addresses. The current scan makes one ordinary GET request, reads at most 64 KiB, and does not follow redirects, crawl, submit forms, inject payloads, or exploit services. Keep the default bind address (`127.0.0.1`). Findings are indicators, not proof of exploitable bugs.

The dashboard asks for the program name, policy link, and target, then requires you to confirm that the target and passive scan are in scope. The policy link is saved as a report reference; J.O.S.H. does not automatically verify program membership or scope. It creates an editable claim draft and offers Markdown and JSON downloads. It never submits a claim to a bounty platform.

## Enter URLs from the command line

The `sources/ml.py` command-line helper prompts for one or more URLs and sends them through the same passive assessment function used by the dashboard. It uses the same `allowed_hosts.txt` file:

```powershell
py -3 sources\ml.py
```

Enter URLs one per line, press Enter on a blank line when finished, then type `YES` to confirm you are authorized. You can also pass URLs directly with `py -3 sources\ml.py --url https://example.com`; add `--json` for JSON output. This helper is an input/assessment bridge, not a trained machine-learning model. It observes the same allowlist and passive-scan limits as the dashboard.

## Triage and locations

Transparent local rules rank findings and provide a fallback summary. When Anthropic is configured, Claude adds a plain-language explanation based only on the check name, severity, and generic indicator description. The exact URL, page path, cookie name, and cookie value stay local. The model cannot confirm exploitability; verify its advice against the evidence. Reports can be exported as JSON from the dashboard.

### Configure the AI

You need an Anthropic API key from your Anthropic account. You can enter it in the dashboard's **AI helper** panel; J.O.S.H. keeps that key in server memory for the current session only, and the **Clear key** button removes it. The key is not saved in a file or browser storage. You can also configure it as an environment variable before starting the server. Never put it in a source file or commit it. In PowerShell:

```powershell
$secureKey = Read-Host 'Anthropic API key' -AsSecureString
$env:ANTHROPIC_API_KEY = [System.Net.NetworkCredential]::new('', $secureKey).Password
$env:JOSH_PORT = '8001'
& '.\shell scripts\frontend\wat-frontend.ps1'
```

Port 8001 lets you use the newly configured process alongside an already-running dashboard on port 8000; open `http://127.0.0.1:8001`. The dashboard shows the configured host list. Claude is called only after you choose **Run assessment** and there are findings to explain. That API use may incur charges under your Anthropic account. If no key is configured or the API is unavailable, J.O.S.H. displays its local rule-based summary instead.

## Honeypot

The dashboard process also acts as a small decoy for `/.env`, `/.git/config`, `/admin`, `/login`, `/phpmyadmin`, and `/wp-admin`. It returns a generic response and does not execute commands or retain request bodies. It keeps at most 200 events in memory (UTC time, path, method, source IP, and a truncated user agent); restarting the server clears them. The status feed is at `/honeypot/status` on the local dashboard server.

This is a development monitor, not a hardened internet-facing honeypot. Do not bind it to a public interface. It does not block, attribute, or retaliate against clients.
