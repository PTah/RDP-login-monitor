# Развёртывание RDP Login Monitor в домене

Монитор ставится в **`C:\ProgramData\RDP-login-monitor\`**, задачи планировщика создаёт сам **`Login_Monitor.ps1`** (параметр `-InstallTasks`). Доставку по сети выполняет **`Deploy-LoginMonitor.ps1`**.

См. также: [exchange-mail-security.md](exchange-mail-security.md) (отдельно, только сервер Exchange).

## Файлы на файловой шаре

Создайте каталог, доступный **конечным компьютерам** на чтение (часто учётная запись компьютера домена), например:

`\\dc.contoso.local\NETLOGON\RDP-login-monitor\`

Минимум для RDP-монитора на всех ПК/серверах:

| Файл | Назначение |
|------|------------|
| `Login_Monitor.ps1` | Основной скрипт (логика мониторинга; без локальных секретов). |
| `login_monitor.settings.example.ps1` | Образец настроек на шаре (Telegram, SMTP, 4740). |
| `version.txt` | **Одна строка** — номер версии пакета на шаре (см. раздел «Версии» ниже). |
| `Deploy-LoginMonitor.ps1` | Установщик: сравнивает версию, копирует монитор, вызывает `-InstallTasks`, при необходимости запускает процесс монитора. |

Полный список файлов для публикации на шару — в [deploy-netlogon-publish.md](deploy-netlogon-publish.md).

## Как это работает

1. **`Deploy-LoginMonitor.ps1`** определяет корень дистрибутива:
   - параметр **`-SourceShareRoot`** `\\server\share\RDP-login-monitor`, **или**
   - если скрипт запущен по UNC, берётся **родительская папка** этого файла.

2. Читается **`version.txt`** на шаре и сравнивается с локальной меткой **`deployed_version.txt`**. Если метки нет — подтягивается **`$ScriptVersion`** из установленного **`Login_Monitor.ps1`**.

3. Версия на шаре **совпадает** с локальной — выход без копирования.

4. Версия на шаре **новее** — остановка процессов монитора → копирование **`Login_Monitor.ps1`** → **`Login_Monitor.ps1 -InstallTasks`** → **`deployed_version.txt`** → запуск монитора (если не **`-SkipStartMonitorAfterUpdate`**).

5. Версия на шаре **старее** — откат блокируется, пока не указан **`-AllowDowngrade`**.

Лог: **`C:\ProgramData\RDP-login-monitor\Logs\deploy.log`**.

## Локальные настройки: `login_monitor.settings.ps1`

На каждом компьютере: **`C:\ProgramData\RDP-login-monitor\login_monitor.settings.ps1`**.

- Секреты и параметры сайта (Telegram, SMTP, **4740**, `$IgnoreAdvapiNetworkLogonSourceIps`) — **только** в этом файле.
- Образец в репозитории и на шаре: **`login_monitor.settings.example.ps1`**.
- **`Deploy-LoginMonitor.ps1`** **не перезаписывает** `login_monitor.settings.ps1` при обновлении скрипта.
- Если файла нет, Deploy **один раз** копирует example → settings (дальше правки только локально).

```powershell
$root = 'C:\ProgramData\RDP-login-monitor'
Copy-Item '\\B26\NETLOGON\RDP-login-monitor\login_monitor.settings.example.ps1' `
    (Join-Path $root 'login_monitor.settings.ps1')
notepad (Join-Path $root 'login_monitor.settings.ps1')
```

DPAPI: **`Encrypt-DpapiForRdpMonitor.ps1`** — строки Base64 в settings.

## Опционально: `ignore.lst`

Файл **`C:\ProgramData\RDP-login-monitor\ignore.lst`** — подавление отдельных алертов **4624/4625/4740**. Синтаксис — в **[README.md](../README.md)** (раздел 7) и **`ignore.lst.example`**. Deploy с шары **`ignore.lst` не копирует**.

## Опционально на КД: блокировки AD (4740)

Включается только если монитор запущен на КД с именем **`$LockoutMonitorDomainController`**. Параметры задаются в **`login_monitor.settings.ps1`** на этом КД (`$NetBiosDomainName`, `$ExchangeIisLogPath`, …).

## Heartbeat и watchdog

- **`Logs\last_heartbeat.txt`** — обновление по **`$HeartbeatInterval`** (по умолчанию 1 ч).
- Нет обновления дольше **`$HeartbeatStaleAlertMultiplier × интервал`** — оповещение.
- Задача **`RDP-Login-Monitor-Watchdog`** — каждые 5 мин проверяет процесс и поднимает при падении.

## Задачи планировщика (`-InstallTasks`)

| Имя | Назначение |
|-----|------------|
| **`RDP-Login-Monitor`** | Запуск при старте ОС |
| **`RDP-Login-Monitor-Watchdog`** | Контроль процесса каждые 5 мин |

Проверка:

```powershell
Get-ScheduledTask -TaskName 'RDP-Login-Monitor','RDP-Login-Monitor-Watchdog' -ErrorAction SilentlyContinue
```

Логи: **`login_monitor.log`**, **`watchdog.log`**.

## GPO (автозагрузка): проверенная схема

1. Файлы на `\\B26\NETLOGON\RDP-login-monitor\`
2. GPO на OU **компьютеров** → **Сценарии PowerShell** автозагрузки → `Deploy-LoginMonitor.ps1`
3. Security Filtering: группа компьютеров (например `B26\RDP-Login`), права Read + Apply GPO
4. Доступ на шару для **SYSTEM** / Domain Computers
5. После смены membership — **перезагрузка** (не только `gpupdate`)

**Нюансы:** UNC в NETLOGON не копируется в SYSVOL GPO — это нормально. Deploy после `-InstallTasks` делает `schtasks /Run` для немедленного старта монитора.

### Периодический Deploy на серверах без перезагрузок

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\Install-DeployScheduledTask.ps1" `
  -TaskName "RDP-Login-Monitor-Deploy" `
  -DeployScriptPath "\\B26\NETLOGON\RDP-login-monitor\Deploy-LoginMonitor.ps1" `
  -RepeatMinutes 60 `
  -RunNow
```

### Ручной deploy

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "\\B26\NETLOGON\RDP-login-monitor\Deploy-LoginMonitor.ps1"
```

Параметры: **`-WhatIf`**, **`-SkipStartMonitorAfterUpdate`**, **`-AllowDowngrade`**.

### Диагностика

- Group Policy Operational log
- `Logs\deploy.log`, `login_monitor.log`, `watchdog.log`

## Версии: `version.txt` и `$ScriptVersion`

| Что | Роль |
|-----|------|
| **`version.txt` на шаре** | Триггер обновления для Deploy |
| **`$ScriptVersion` в скрипте** | Версия в логах и Telegram |

Поднимайте **`version.txt`** при каждой выкладке на NETLOGON.

## Безопасность

- Ограничьте ACL на шару (в example/settings могут быть секреты для домена B26).
- DPAPI: **`Encrypt-DpapiForRdpMonitor.ps1`** (значения в **`login_monitor.settings.ps1`**)
- Внутренний git (git.kalinamall.ru): доверенный; секреты допустимы в **`login_monitor.settings.example.ps1`**

## UNC и ExecutionPolicy

При ошибках подписи с FQDN-шары используйте короткое имя DC: `\\DC01\NETLOGON\...` и **`powershell.exe -ExecutionPolicy Bypass -File "..."`**.
