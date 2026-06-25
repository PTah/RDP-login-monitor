# RDP Login Monitor

PowerShell monitoring for Windows logon events (RDP, RDS, RD Gateway, WinRM) with Telegram and/or SMTP alerts. Optional integration with [Security Alert Center](https://github.com/PTah/security-alert-center).

**Repository:** https://github.com/PTah/RDP-login-monitor

# RDP Login Monitor

**Версия:** `2.1.5-SAC` (`$ScriptVersion` + `version.txt`)

PowerShell-мониторинг Windows: RDP/RDS, RD Gateway, WinRM, admin share, блокировки УЗ, heartbeat, отчёты.

## Установка (домен)

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "\\<DC>\NETLOGON\RDP-login-monitor\Deploy-LoginMonitor.ps1"
```

Каталог: `C:\ProgramData\RDP-login-monitor\` · настройки: `login_monitor.settings.ps1` (не перезаписываются при деплое).

## Обновление через SAC (WinRM)

С карточки хоста в SAC: **«Обновить через WinRM»** (SAC ≥ 0.20.15). Сервер тянет репозиторий с git, отдаёт zip по HTTPS; на ПК **не нужны** git и NETLOGON.

1. Staging: `C:\ProgramData\RDP-login-monitor\_sac_staging`
2. `Deploy-LoginMonitor.ps1 -SourceShareRoot` (тот же алгоритм, что при GPO)
3. Нужны: WinRM, domain admin в SAC, доступ ПК к `SAC_PUBLIC_URL`, `rdp_git_repo_url` в **Настройки → Обновления агентов**

Подробнее: [security-alert-center — agent-control-plane](https://github.com/PTah/security-alert-center/src/branch/main/docs/agent-control-plane.md) §4.3.

## События в SAC

| Источник | Тип SAC |
|----------|---------|
| Security 4624/4625 | `rdp.login.*` |
| Security 5140 | `smb.admin_share.access` |
| WinRM Operational 91 | `winrm.session.started` |
| RD Gateway 302/303 | `rdg.connection.*` → flap 302→303 в SAC |
| Security 4740 (КД) | `auth.account.locked` |
| Агент | `agent.heartbeat`, `report.daily.rdp`, `agent.inventory` |

**SAC:** `Sac-Client.ps1`, `$UseSAC` — [agent-integration.md](https://github.com/PTah/security-alert-center/src/branch/main/docs/agent-integration.md). Poll команд `qwinsta`/`logoff` (≥ 2.1.0-SAC).

## Ключевые файлы

| Файл | Назначение |
|------|------------|
| `Login_Monitor.ps1` | Основной цикл |
| `Sac-Client.ps1` | Отправка в SAC |
| `Deploy-LoginMonitor.ps1` | NETLOGON, задачи, WinRM self-heal |
| `login_monitor.settings.ps1` | Секреты и параметры (локально) |

## Быстрые проверки

```powershell
Get-Content "C:\ProgramData\RDP-login-monitor\Logs\login_monitor.log" -Tail 60
Login_Monitor.ps1 -CheckSac
```

## Документация

- [Docs/README.md](Docs/README.md) — развёртывание, Exchange
- [security-alert-center](https://github.com/PTah/security-alert-center) — сервер, RDG flap, qwinsta через SAC UI/Seaca

## English

See repository docs; agent contract is in SAC `docs/agent-integration.md`.

## Topics (GitHub)

`rdp`, `remote-desktop`, `windows-security`, `powershell`, `telegram-bot`, `smtp`, `gpo`, `netlogon`, `winrm`, `exchange`, `monitoring`, `security`

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 Andrey "PapaTramp" Lutsenko.

<details>
<summary><strong>English summary</strong></summary>

Monitors Windows Security event log (4624/4625, RD Gateway 302/303, account lockout 4740, WinRM Enter-PSSession, etc.), sends alerts, supports domain deploy via NETLOGON and SAC agent ingest.

</details>
