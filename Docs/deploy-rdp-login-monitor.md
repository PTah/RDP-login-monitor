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
| `Sac-Client.ps1` | Клиент Security Alert Center (обязателен для SAC, копируется рядом с монитором). |
| `login_monitor.settings.example.ps1` | Образец настроек на шаре (Telegram, SAC, SMTP, 4740). |
| `version.txt` | **Одна строка** — номер версии пакета на шаре (см. раздел «Версии» ниже). |
| `Deploy-LoginMonitor.ps1` | Установщик: сравнивает версию, копирует монитор и Sac-Client, вызывает `-InstallTasks`, при необходимости запускает процесс монитора. |

Полный список файлов для публикации на шару — в [deploy-netlogon-publish.md](deploy-netlogon-publish.md).

## Как это работает

1. **`Deploy-LoginMonitor.ps1`** определяет корень дистрибутива:
   - параметр **`-SourceShareRoot`** `\\server\share\RDP-login-monitor`, **или**
   - если скрипт запущен по UNC, берётся **родительская папка** этого файла.

2. Читается **`version.txt`** на шаре и сравнивается с локальной меткой **`deployed_version.txt`**. Если метки нет — подтягивается **`$ScriptVersion`** из установленного **`Login_Monitor.ps1`**.

3. Версия на шаре **совпадает** с локальной — выход **без копирования**, **кроме** случаев:
   - на ПК **нет** `Sac-Client.ps1` или его SHA256 **отличается** от шары;
   - в `login_monitor.settings.ps1` **нет** блока SAC (`$UseSAC`, `$SacUrl`, `$SacApiKey`) — тогда добавляется **`UseSAC = 'dual'`** из example (без перезаписи Telegram, если возможно).

4. Версия на шаре **новее** (или сработало условие выше) — остановка процессов → копирование **`Login_Monitor.ps1`** и **`Sac-Client.ps1`** → настройка SAC в settings при необходимости → **`Login_Monitor.ps1 -InstallTasks`** → **`deployed_version.txt`** → запуск монитора.

5. Версия на шаре **старее** — откат блокируется, пока не указан **`-AllowDowngrade`**.

Лог: **`C:\ProgramData\RDP-login-monitor\Logs\deploy.log`**.

## Локальные настройки: `login_monitor.settings.ps1`

На каждом компьютере: **`C:\ProgramData\RDP-login-monitor\login_monitor.settings.ps1`**.

- Секреты и параметры сайта (Telegram, SMTP, **4740**, `$IgnoreAdvapiNetworkLogonSourceIps`) — **только** в этом файле.
- Образец в репозитории и на шаре: **`login_monitor.settings.example.ps1`**.
- **`Deploy-LoginMonitor.ps1`** **не перезаписывает** существующий `login_monitor.settings.ps1`, если SAC уже настроен (`UseSAC` не `off`, заданы `$SacUrl` и `$SacApiKey`).
- Если файла нет — Deploy **один раз** копирует example → settings (**`UseSAC = 'dual'`**).
- Если файл есть, но **нет блока SAC** — Deploy **дописывает** блок из example (Telegram/SMTP не трогает).

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

## Обновление на любой Windows-машине (чеклист)

Цель: новые **`Login_Monitor.ps1`**, **`Sac-Client.ps1`**, при необходимости настройки SAC — без ручного копирования с рабочей станции.

### A. Один раз: публикация на шару (сервер, где есть git)

1. На DC3 (или другом хосте публикации):
   ```powershell
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\soft\update-rdp-monitor.ps1
   ```
   Скрипт делает `git pull` с **git.kalinamall.ru** и копирует файлы в `\\b26\NETLOGON\RDP-login-monitor\`.

2. Убедитесь, что на шаре есть **`Sac-Client.ps1`** и в **`version.txt`** — новая версия (например `1.2.0-SAC`).

### B. На каждой целевой машине (автоматически)

Если настроена GPO / задача с **`Deploy-LoginMonitor.ps1`** — достаточно дождаться запуска Deploy (при старте ОС, по расписанию или после `gpupdate /force` + перезагрузки).

Deploy **сам**:
- сравнит `version.txt` на шаре с `C:\ProgramData\RDP-login-monitor\deployed_version.txt`;
- скопирует **`Login_Monitor.ps1`** и **`Sac-Client.ps1`**;
- перерегистрирует задачи (`-InstallTasks`);
- **не трогает** `login_monitor.settings.ps1`.

### C. Ручное обновление одной машины (без GPO)

От **администратора** PowerShell:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File "\\b26\NETLOGON\RDP-login-monitor\Deploy-LoginMonitor.ps1"
```

Проверка:

```powershell
Select-String -Path 'C:\ProgramData\RDP-login-monitor\Login_Monitor.ps1' -Pattern 'ScriptVersion'
Test-Path 'C:\ProgramData\RDP-login-monitor\Sac-Client.ps1'
Get-ScheduledTask -TaskName 'RDP-Login-Monitor','RDP-Login-Monitor-Watchdog' -ErrorAction SilentlyContinue
Get-Content 'C:\ProgramData\RDP-login-monitor\Logs\deploy.log' -Tail 15
```

### Graceful restart (без убийства PowerShell)

После правки **`login_monitor.settings.ps1`** (SAC, Telegram):

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File "C:\ProgramData\RDP-login-monitor\Login_Monitor.ps1" -RequestRestart
```

Или скрипт из репозитория/шары: **`Restart-RdpLoginMonitor.ps1`**.

Чтобы подхватить **новый `Login_Monitor.ps1` с диска** (после Deploy), нужен **recycle** — новый скрытый процесс, старый завершается сам:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File "C:\ProgramData\RDP-login-monitor\Login_Monitor.ps1" -RequestRestart -Recycle
```

**`Deploy-LoginMonitor.ps1`** записывает **`restart.request`** напрямую (без дочернего PowerShell) и ждёт до **35 с**; **`Stop-Process -Force`** только если таймаут.

Сигнал: файл **`C:\ProgramData\RDP-login-monitor\restart.request`** (создаётся автоматически, не редактировать вручную).

### D. Первичная установка (ещё нет ProgramData)

1. Deploy (как в C) — создаст каталог и при отсутствии settings скопирует **`login_monitor.settings.ps1`** из example.
2. Отредактируйте **`C:\ProgramData\RDP-login-monitor\login_monitor.settings.ps1`** (SAC, при необходимости 4740).
3. Проверка SAC:
   ```powershell
   powershell.exe -NoProfile -ExecutionPolicy Bypass `
     -File 'C:\ProgramData\RDP-login-monitor\Login_Monitor.ps1' -CheckSac
   ```

## Security Alert Center (SAC)

В **`login_monitor.settings.ps1`** на машине (не перезаписывается Deploy):

```powershell
$UseSAC = 'dual'          # off | exclusive | dual | fallback
$SacUrl = 'https://sac.kalinamall.ru'
$SacApiKey = 'sac_...'     # ключ из SAC
```

Режимы:
- **`dual`** — SAC + Telegram (рекомендуется на переходе);
- **`exclusive`** — только SAC;
- **`fallback`** — SAC, при сбоях — Telegram.

После правок settings перезапуск не обязателен: watchdog поднимет процесс; для проверки:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File 'C:\ProgramData\RDP-login-monitor\Login_Monitor.ps1' -CheckSac
```

В SAC UI: **Отчёты** / **События** — события `rdp.login.*`, `report.daily.rdp`, `agent.heartbeat`.

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
