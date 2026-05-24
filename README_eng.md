# RDP Login Monitor

PowerShell toolkit for monitoring Windows logons with Telegram and/or Email (SMTP) notifications.

## Recommended layout

- Installation root: **`C:\ProgramData\RDP-login-monitor\`**.
- Main script: **`Login_Monitor.ps1`** — Security log **`4624`/`4625`** (behavior depends on OS type: workstation vs server/domain controller), **aggregated `4625` burst alerts** (two tiers: IP+user and IP-only), optional **Remote Connection Manager `1149`** when the log is available (often useful for RDP-enabled workstations), **RD Gateway** events **`302`/`303`** when the gateway role/log is present, on the **DC where the monitor runs** (hostname matches **`$LockoutMonitorDomainController`**) — **`4740`** (account lockout + IPs from IIS ActiveSync), **daily report** (active sessions via `quser`), **heartbeat**, **log rotation**, alerts via Telegram and/or Email.
- Scheduled tasks: run **`Login_Monitor.ps1 -InstallTasks`** to register:
  - `RDP-Login-Monitor` (main monitor),
  - `RDP-Login-Monitor-Watchdog` (process health check every 5 minutes).
- Domain delivery and upgrades: **`Deploy-LoginMonitor.ps1`** + **`version.txt`** on a share such as `NETLOGON`. After a successful deploy, the startup notification may include an update note (file **`deploy_last_update.txt`** next to logs).
- Deployment docs: **[Docs/README.md](Docs/README.md)** (RDP monitor, Exchange, NETLOGON).
- **`Encrypt-DpapiForRdpMonitor.ps1`** — optional helper to prepare DPAPI-protected Base64 for the bot token / chat id and SMTP password (`$MailSmtpPasswordProtectedB64` in the settings file).
- **RDP monitor local settings:** **`login_monitor.settings.ps1`** in the install directory (template **`login_monitor.settings.example.ps1`**). When **`Login_Monitor.ps1`** is auto-updated from the share, the settings file is **not overwritten** (same pattern as **`exchange_monitor.settings.ps1`** for Exchange).

## Notable behavior

- **`.ps1` encoding**: `.editorconfig` and `.gitattributes` encourage **`*.ps1`** as **UTF-8 with BOM** and **CRLF**, reducing mojibake and PowerShell parse issues.
- **Log encoding**: `login_monitor.log` / `watchdog.log` are written as **UTF-8 with BOM** (BOM is applied to existing files if missing) so viewers like **FAR Manager** do not mis-detect encoding.
- **`auditpol` on Russian Windows**: auditing checks use the **`Вход/выход`** category and **`Вход в систему` / `Выход из системы`** subcategories (expect **`Успех и сбой`**), avoiding errors such as `0x00000057` when English names like `Logon` are absent on a localized OS.
- **Stability**: `auditpol` is invoked via full path `%SystemRoot%\System32\auditpol.exe` (no PATH dependency); stdout and stderr are merged via `ProcessStartInfo`.
- **`4625` burst alerts**: when `$FailedLogonRateLimitEnabled` is true — tier 1: **5** failures in **60** s per **IP+user**; tier 2: **12** in **60** s per **IP** (spray). Below thresholds, individual `4625` alerts are sent; during a burst, aggregated alerts replace per-event noise. No automatic IP blocking. Tune at the top of `Login_Monitor.ps1`.
- **Exchange Mail Security** (`Exchange-MailSecurity.ps1`): Exchange server only — queues, external forwarding, watchdog. See **[Docs/exchange-mail-security.md](Docs/exchange-mail-security.md)**.

## 1) Preparation

1. Create the install folder:
   - `C:\ProgramData\RDP-login-monitor\`
2. Copy at least:
   - `Login_Monitor.ps1`
   - `login_monitor.settings.example.ps1` → rename to **`login_monitor.settings.ps1`** and configure (see step 3)
   - (for domain rollout on a share) `Deploy-LoginMonitor.ps1`, `version.txt`, and `login_monitor.settings.example.ps1`
3. Configure **`C:\ProgramData\RDP-login-monitor\login_monitor.settings.ps1`** (do not put secrets in `Login_Monitor.ps1` — they are overwritten on deploy):
   - **Telegram:** `$TelegramBotToken` / `$TelegramChatID` or `...ProtectedB64`
   - **Email (SMTP):** `$MailSmtpHost`, `$MailFrom`, `$MailTo`, `$MailSmtpPort` (default 587), optionally `$MailSmtpUser` / `$MailSmtpPassword` (or `$MailSmtpPasswordProtectedB64` via DPAPI), `$MailSmtpStartTls` / `$MailSmtpSsl`
   - **Order:** `$NotifyOrder` — empty = auto (Telegram → Email, configured channels only); otherwise `telegram,email`, `email`, etc. (`tg`, `mail` are accepted)
4. Run elevated (Security log access and task registration).
5. Logs and auxiliary files:
   - `C:\ProgramData\RDP-login-monitor\Logs\`
6. (Optional) Suppress some Security alerts via **`ignore.lst`** — see **section 7** below.
7. (Optional) AD account lockout monitoring on a DC — in **`login_monitor.settings.ps1`**: **`$LockoutMonitorDomainController`** (short hostname of the machine **where the monitor is installed and running**), **`$NetBiosDomainName`**, **`$ExchangeIisLogPath`**, **`$ExchangeIisLogMinutesBeforeLockout`** (default 30), **`$ExchangeIisLogTailLines`** (default 5000), **`$ExchangeServerHostForIisExclude`**. Alerts include the user from event **4740** and client IPs from IIS within the time window before lockout. In **`ignore.lst`** use prefix **`4740:`** or **`all:`** — see **`ignore.lst.example`**.
8. Heartbeat: if **`Logs\last_heartbeat.txt`** is not updated for longer than **`$HeartbeatStaleAlertMultiplier` × `$HeartbeatInterval`** (default 2×1 h) — alert via Telegram/Email.

## 2) Manual run

Use this to validate startup/logic without registering scheduled tasks.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\ProgramData\RDP-login-monitor\Login_Monitor.ps1"
```

The monitor keeps running in the session until you stop it (for example `Ctrl+C`).

## 3) Task Scheduler

You do not need to create tasks manually in the GUI.

Run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\ProgramData\RDP-login-monitor\Login_Monitor.ps1" -InstallTasks
```

The script registers `RDP-Login-Monitor` and `RDP-Login-Monitor-Watchdog`, then triggers an immediate first run.

For domain deployment from a share you do not configure the scheduler on clients by hand — use `Deploy-LoginMonitor.ps1` (see [Docs/deploy-rdp-login-monitor.md](Docs/deploy-rdp-login-monitor.md)).

## 4) Post-install checks

- Logs:
  - `C:\ProgramData\RDP-login-monitor\Logs\login_monitor.log`
  - `C:\ProgramData\RDP-login-monitor\Logs\watchdog.log`
- Heartbeat:
  - `C:\ProgramData\RDP-login-monitor\Logs\last_heartbeat.txt` updates on **`$HeartbeatInterval`** (hourly by default).
- Daily report: after the first daily window (default **09:00**, controlled by **`$DailyReportHour`** / **`$DailyReportMinute`** in `Login_Monitor.ps1`), a `quser` summary is sent (Telegram/Email); last run marker: `Logs\last_daily_report.txt`.
- Stale heartbeat: if **`last_heartbeat.txt`** is stale beyond **`$HeartbeatStaleAlertMultiplier` × `$HeartbeatInterval`** — alert via Telegram/Email (see preparation step 8).
- At startup (Telegram/Email): **notification channels** line (actual delivery order) plus RDS/4740 mode per configuration.
- Startup message (Telegram): with **RD Session Host** (or broader RDS session components, not gateway-only) you get the RDS/RDP session-host line; when the **RD Gateway** log is available you get a separate line about connections to **internal targets** through the gateway (302/303). A gateway-only node does not duplicate the “session host” wording.

## 5) Automatic restart on failure

`-Watchdog` inside `Login_Monitor.ps1`:

- looks for `powershell.exe` / `pwsh.exe` whose command line references `Login_Monitor.ps1`;
- if the main monitor is missing, starts it;
- if the monitor is already running, does not spawn a second instance.

## 6) Extra parameters and other repo files

- **`-SkipScheduledTaskMaintenance`**: during normal monitor startup, skip verification/recreation of scheduled tasks (if you manage tasks only via **`-InstallTasks`** or manually).
- **`Install-DeployScheduledTask.ps1`** — helper to run **`Deploy-LoginMonitor.ps1`** from a share on a schedule (see **[DEPLOY.md](DEPLOY.md)**).
- **`Watchdog_RDP_Monitor.ps1`** and **`Install-ScheduledTasks.ps1`** — **alternate** layout with a separate watchdog script and default paths under **`D:\Soft`**. For new installs, prefer the built-in **`-Watchdog`** in **`Login_Monitor.ps1`** and tasks **`RDP-Login-Monitor`** / **`RDP-Login-Monitor-Watchdog`**.
- **`ignore.lst.example`** in the repo is a template for **`ignore.lst`** to suppress selected Security notifications (see section 7).
- **`login_monitor.settings.example.ps1`** — template for **`login_monitor.settings.ps1`** (Telegram, SMTP, 4740, local IP exclusions). Deploy may create `login_monitor.settings.ps1` from the example on first install.

## 7) Suppressing Security alerts: `ignore.lst`

Place a file **`C:\ProgramData\RDP-login-monitor\ignore.lst`** next to **`Login_Monitor.ps1`**. By default rules apply to **`4624`/`4625`**; prefix **`4740:`** (or **`lockout:`**) — account lockouts only; **`all:`** — logons and **4740**. For **4740**, rule type **`ip:`** is matched against IPs from IIS ActiveSync. Built-in script exclusions still apply to all event types except **4740** (lockouts use **`ignore.lst`** and built-in user checks only).

**RD Gateway (`302`/`303`)**, **RCM `1149`**, the daily report, and heartbeat **are not controlled** by this file.

### How the file is loaded

- The file is read during event processing; entries are **cached in memory**. If **`LastWriteTimeUtc`** changes (save after edit), the list is **reloaded automatically** — no monitor restart required.
- Encoding: **UTF-8** (`Get-Content -Encoding UTF8`). A UTF-8 BOM at the start of a line is stripped when parsing.
- Blank lines are skipped. Lines starting with **`#`** or **`;`** are comments.
- If the line contains **`:`**, the **first** colon splits the line: the left part (trimmed) selects the rule kind, the right part is the value. If the right part is empty, the line is ignored.
- If there is **no** colon, the whole trimmed line is one “match-any” value (see below).

### Scope prefix (at the start of the line, before the rule type)

| Prefix | Events |
| --- | --- |
| *(none)* | **4624**, **4625** |
| `4740:`, `lockout:` | **4740** |
| `all:`, `*:` | **4624**, **4625**, **4740** |

Example: `4740:user:svc_sync` — do not alert on lockout for that account.

### Rule kinds (left part before the first `:` after the scope prefix)

| Left part (case-insensitive regex fragments) | Event field |
| --- | --- |
| `рабоч`, `workstation`, `wks` | workstation name (**WorkstationName** and similar XML fields) |
| `польз`, `username`, `subject`, `account`, `target user`, whole word `user` | user name (**TargetUserName**, etc.) |
| `ip`, `ip адрес`, `ipaddress`, `адрес ip` | source IP (**IpAddress**, etc.) when present |

If the left part matches none of the above but a colon exists, the parser behaves like the Telegram line splitter: kind is **Any**, value is **only the right part** (the label on the left is discarded).

### “Any” matching (no colon, or unknown label before `:`)

Evaluated in order:

1. If the value looks like **IPv4**, it is compared to the event source IP (exact match).
2. If the value contains **`\`**, it is matched against the **account**: full `DOMAIN\user` equality **or** SAM after the last `\` (e.g. rule `IVANOV` matches `DOMAIN\IVANOV`).
3. Otherwise: exact match against **workstation name** first, then the same account rules as in step 2.

Explicit **User** / **Workstation** / **Ip** kinds only compare their respective field (user rules use the same full-name and SAM behavior as step 2).

### Examples and deployment

- See **`ignore.lst.example`** in the repo; copy it to the server as **`ignore.lst`** and edit.
- **`Deploy-LoginMonitor.ps1`** does **not** copy or overwrite **`ignore.lst`** or **`login_monitor.settings.ps1`**; if settings are missing, Deploy creates them once from **`login_monitor.settings.example.ps1`** on the share.

## Keywords (for discovery)

`rdp`, `rd-gateway`, `rdp-gateway`, `rds`, `remote-desktop`, `windows-security-log`, `eventlog`, `event-id-4624`, `event-id-4625`, `event-id-4740`, `event-id-302`, `event-id-303`, `account-lockout`, `active-sync`, `exchange`, `iis`, `smtp`, `email`, `powershell`, `telegram-bot`, `watchdog`, `gpo`, `netlogon`, `domain-deployment`, `windows-server`, `monitoring`
