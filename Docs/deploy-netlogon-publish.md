# Публикация пакета на NETLOGON

Скрипт **`update-rdp-monitor.ps1`** на сервере публикации (например DC3) выполняет `git pull` и копирует файлы в шару.

## Путь на шаре (`-NetlogonDest`)

После `git pull` скрипт копирует дистрибутив в UNC-каталог NETLOGON:

```text
\\<имя-DC>\NETLOGON\RDP-login-monitor
```

`<имя-DC>` — NetBIOS-имя или FQDN **контроллера домена**, где лежит SYSVOL (тот же хост, с которого GPO запускает `Deploy-LoginMonitor.ps1`). Примеры:

- `\\DC01\NETLOGON\RDP-login-monitor`
- `\\dc01.corp.example.com\NETLOGON\RDP-login-monitor`

Значение по умолчанию в скрипте — **заглушка** `\\dc.contoso.local\NETLOGON\RDP-login-monitor`. В реальном домене её **нужно переопределить**, иначе после успешного `git pull` будет ошибка **«Не найден сетевой путь»** (скрипт не достучится до несуществующего хоста).

Проверка перед публикацией:

```powershell
Test-Path '\\DC01\NETLOGON\RDP-login-monitor'
# или хотя бы корень шары:
Test-Path '\\DC01\NETLOGON'
```

Должно вернуть `True` под учётной записью, с которой запускаете публикацию (на DC — обычно локальный админ; с рабочей станции — доменный админ с доступом к NETLOGON).

## Параметры по умолчанию

| Параметр | Значение |
|----------|----------|
| `$RepoPath` | `C:\Soft\Git\RDP-login-monitor` |
| `$NetlogonDest` | `\\dc.contoso.local\NETLOGON\RDP-login-monitor` *(заглушка — замените на свой DC)* |
| `$GitUrl` | `https://github.com/PTah/RDP-login-monitor.git` |
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

**На сервере публикации** (клон репозитория + доступ к NETLOGON):

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Soft\Git\RDP-login-monitor\update-rdp-monitor.ps1 `
  -NetlogonDest '\\DC01\NETLOGON\RDP-login-monitor'
```

Другой remote git (закрытое зеркало):

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Soft\Git\RDP-login-monitor\update-rdp-monitor.ps1 `
  -NetlogonDest '\\DC01\NETLOGON\RDP-login-monitor' `
  -GitUrl 'https://github.com/PTah/RDP-login-monitor.git'
```

Пробный прогон без копирования:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Soft\Git\RDP-login-monitor\update-rdp-monitor.ps1 `
  -NetlogonDest '\\DC01\NETLOGON\RDP-login-monitor' `
  -WhatIf
```

После pull обязательно проверьте **`version.txt`** на шаре — его номер определяет, подтянут ли обновления на клиентах. Метка может включать суффикс (например **`1.2.27-SAC`**); **`Deploy-LoginMonitor.ps1`** сравнивает её с **`deployed_version.txt`** по полной строке.

Файлы **`*.ps1`** при копировании пересохраняются как **UTF-8 с BOM** (иначе PowerShell 5.1 с NETLOGON может не разобрать кириллицу в скриптах). Скрипты **`Deploy-DomainMonitors.ps1`** и **`Install-DomainMonitors.ps1`** используют **ASCII** в рабочих строках — их можно запускать и без перепубликации.
