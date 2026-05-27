# Публикация пакета на NETLOGON

Скрипт **`update-rdp-monitor.ps1`** на сервере публикации (например DC3) выполняет `git pull` и копирует файлы в шару.

## Параметры по умолчанию

| Параметр | Значение |
|----------|----------|
| `$RepoPath` | `C:\Soft\Git\RDP-login-monitor` |
| `$NetlogonDest` | `\\b26\NETLOGON\RDP-login-monitor` |
| `$GitUrl` | `https://git.kalinamall.ru/PapaTramp/RDP-login-monitor.git` |
| `$GitBranch` | `main` |
| `$LogFile` | `C:\soft\Logs\update-rdp-monitor.log` |

## Копируемые файлы

- `Login_Monitor.ps1`
- `Sac-Client.ps1`
- `version.txt`
- `Deploy-LoginMonitor.ps1`
- `Restart-RdpLoginMonitor.ps1`
- `Exchange-MailSecurity.ps1`
- `Notify-Common.ps1`
- `Install-DomainMonitors.ps1`
- `Deploy-DomainMonitors.ps1`
- `exchange_monitor.settings.example.ps1`
- `login_monitor.settings.example.ps1`

## Запуск

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\soft\update-rdp-monitor.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\soft\update-rdp-monitor.ps1 -WhatIf
```

После pull обязательно проверьте **`version.txt`** на шаре — его номер определяет, подтянут ли обновления на клиентах и Exchange.

Файлы **`*.ps1`** при копировании пересохраняются как **UTF-8 с BOM** (иначе PowerShell 5.1 с NETLOGON может не разобрать кириллицу в скриптах). Скрипты **`Deploy-DomainMonitors.ps1`** и **`Install-DomainMonitors.ps1`** используют **ASCII** в рабочих строках — их можно запускать и без перепубликации.
