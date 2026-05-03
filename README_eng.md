# RDP Login Monitor

PowerShell toolkit for monitoring Windows logons with Telegram notifications.

## Recommended layout

- Installation root: **`C:\ProgramData\RDP-login-monitor\`**.
- Main script: **`Login_Monitor.ps1`** — Security log **`4624`/`4625`** (behavior depends on OS type: workstation vs server/domain controller), optional **Remote Connection Manager `1149`** when the log is available (often useful for RDP-enabled workstations), **RD Gateway** events **`302`/`303`** when the gateway role/log is present, **daily report** to Telegram (active sessions via `quser`), **heartbeat**, **log rotation**, Telegram alerts.
- Scheduled tasks: run **`Login_Monitor.ps1 -InstallTasks`** to register:
  - `RDP-Login-Monitor` (main monitor),
  - `RDP-Login-Monitor-Watchdog` (process health check every 5 minutes).
- Domain delivery and upgrades: **`Deploy-LoginMonitor.ps1`** + **`version.txt`** on a share such as `NETLOGON`. After a successful deploy, the startup Telegram message may include an update note (file **`deploy_last_update.txt`** next to logs).
- Full deploy/GPO guidance: **[DEPLOY.md](DEPLOY.md)**.
- **`Encrypt-DpapiForRdpMonitor.ps1`** — optional helper to prepare DPAPI-protected Base64 for the bot token / chat id.

## Notable behavior

- **`.ps1` encoding**: `.editorconfig` and `.gitattributes` encourage **`*.ps1`** as **UTF-8 with BOM** and **CRLF**, reducing mojibake and PowerShell parse issues.
- **Log encoding**: `login_monitor.log` / `watchdog.log` are written as **UTF-8 with BOM** (BOM is applied to existing files if missing) so viewers like **FAR Manager** do not mis-detect encoding.
- **`auditpol` on Russian Windows**: auditing checks use the **`Вход/выход`** category and **`Вход в систему` / `Выход из системы`** subcategories (expect **`Успех и сбой`**), avoiding errors such as `0x00000057` when English names like `Logon` are absent on a localized OS.
- **Stability**: `auditpol` is invoked via `cmd.exe` with merged stdout/stderr so `$ErrorActionPreference = 'Stop'` does not abort on stderr-only output.

## 1) Preparation

1. Create the install folder:
   - `C:\ProgramData\RDP-login-monitor\`
2. Copy at least:
   - `Login_Monitor.ps1`
   - (for domain rollout on a share) `Deploy-LoginMonitor.ps1` and `version.txt`.
3. Edit `Login_Monitor.ps1` and set the bot token / chat:
   - `$TelegramBotToken` or `$TelegramBotTokenProtectedB64`
   - `$TelegramChatID` or `$TelegramChatIDProtectedB64`
4. Run elevated (Security log access and task registration).
5. Logs and auxiliary files:
   - `C:\ProgramData\RDP-login-monitor\Logs\`

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

For domain deployment from a share you do not configure the scheduler on clients by hand — use `Deploy-LoginMonitor.ps1` (see `DEPLOY.md`).

## 4) Post-install checks

- Logs:
  - `C:\ProgramData\RDP-login-monitor\Logs\login_monitor.log`
  - `C:\ProgramData\RDP-login-monitor\Logs\watchdog.log`
- Heartbeat:
  - `C:\ProgramData\RDP-login-monitor\Logs\last_heartbeat.txt` updates on **`$HeartbeatInterval`** (hourly by default).
- Daily report: after the first daily window (default **09:00**, controlled by **`$DailyReportHour`** / **`$DailyReportMinute`** in `Login_Monitor.ps1`), Telegram receives a `quser` summary; last run marker: `Logs\last_daily_report.txt`.
- Startup Telegram message: with **RD Session Host** (or broader RDS session components, not gateway-only) you get the RDS/RDP session-host line; when the **RD Gateway** log is available you get a separate line about connections to **internal targets** through the gateway (302/303). A gateway-only node does not duplicate the “session host” wording.

## 5) Automatic restart on failure

`-Watchdog` inside `Login_Monitor.ps1`:

- looks for `powershell.exe` / `pwsh.exe` whose command line references `Login_Monitor.ps1`;
- if the main monitor is missing, starts it;
- if the monitor is already running, does not spawn a second instance.

## 6) Extra parameters and other repo files

- **`-SkipScheduledTaskMaintenance`**: during normal monitor startup, skip verification/recreation of scheduled tasks (if you manage tasks only via **`-InstallTasks`** or manually).
- **`Install-DeployScheduledTask.ps1`** — helper to run **`Deploy-LoginMonitor.ps1`** from a share on a schedule (see **[DEPLOY.md](DEPLOY.md)**).
- **`Watchdog_RDP_Monitor.ps1`** and **`Install-ScheduledTasks.ps1`** — **alternate** layout with a separate watchdog script and default paths under **`D:\Soft`**. For new installs, prefer the built-in **`-Watchdog`** in **`Login_Monitor.ps1`** and tasks **`RDP-Login-Monitor`** / **`RDP-Login-Monitor-Watchdog`**.

## Keywords (for discovery)

`rdp`, `rd-gateway`, `rdp-gateway`, `rds`, `remote-desktop`, `windows-security-log`, `eventlog`, `event-id-4624`, `event-id-4625`, `event-id-302`, `event-id-303`, `powershell`, `telegram-bot`, `watchdog`, `gpo`, `netlogon`, `domain-deployment`, `windows-server`, `monitoring`
