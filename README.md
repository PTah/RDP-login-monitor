# RDP Login Monitor

PowerShell-набор для мониторинга входов в Windows с отправкой уведомлений в Telegram.

## Актуальная схема (рекомендуется)

- **`Login_Monitor.ps1`** — единый монитор: журнал Security (`4624`/`4625`), при необходимости RD Gateway (`302`/`303`), рабочие станции и серверы, ротация логов, heartbeat, отчёты. Устанавливается в **`C:\ProgramData\RDP-login-monitor\`**, задачи **`RDP-Login-Monitor`** и **`RDP-Login-Monitor-Watchdog`** создаются параметром **`-InstallTasks`** (watchdog через **`schtasks`**, см. **DEPLOY.md**).
- **`Deploy-LoginMonitor.ps1`** + **`version.txt`** — доставка с файловой шары по версии (домен, GPO «автозагрузка» компьютера). Подробности, структура шары и правила версий: **[DEPLOY.md](DEPLOY.md)**.
- **`Encrypt-DpapiForRdpMonitor.ps1`** — опционально, для DPAPI-строк токена/chat id на конкретном ПК.

Разделы ниже про **`D:\Soft\`**, **`Watchdog_RDP_Monitor.ps1`** и **`Install-ScheduledTasks.ps1`** относятся к **старой схеме** и оставлены для совместимости; новые установки ориентируйте на **`ProgramData`** и **DEPLOY.md**.

## Что изменилось (важное)

- **Кодировка `.ps1`**: в репозитории добавлены `.editorconfig` и `.gitattributes`, чтобы `*.ps1` по умолчанию сохранялись как **UTF-8 with BOM** и с **CRLF** (это сильно снижает “кракозябры” и ошибки парсинга PowerShell).
- **Кодировка логов**: `login_monitor.log` / `watchdog.log` пишутся как **UTF-8 с BOM** (и при необходимости BOM добавляется к уже существующему файлу), чтобы в **FAR/старых просмотрщиках** не было ситуации “в консоли нормально, а в файле РЈРІРµ…” из‑за неверной авто-кодировки.
- **`auditpol` на русской Windows**: настройка/проверка аудита опирается на категорию **`Вход/выход`** и подкатегории **`Вход в систему` / `Выход из системы`** (ожидается строка **`Успех и сбой`**). Это устраняет ошибки вида `0x00000057` из‑за несуществующего на RU ОС имени `Logon`.
- **Стабильность**: `auditpol` запускается через `cmd.exe` с перехватом `stdout+stderr`, чтобы не ломать выполнение при `$ErrorActionPreference = "Stop"`.

## 1) Подготовка

1. Скопируйте в `D:\Soft\` как минимум `Login_Monitor.ps1` и `Watchdog_RDP_Monitor.ps1` (для установки из скрипта — ещё `Install-ScheduledTasks.ps1`), либо измените пути в параметрах установщика / в watchdog.
2. Откройте `Login_Monitor.ps1` и задайте:
   - `$TelegramBotToken`
   - `$TelegramChatID`
3. Убедитесь, что существует `D:\Soft\Logs\` (скрипт сам создаст при запуске).
4. Запускайте от имени администратора (нужен доступ к журналу `Security`).

## 2) Ручной запуск

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "D:\Soft\Login_Monitor.ps1"
```

## 3) Запуск через Планировщик заданий (Task Scheduler)

Задания можно завести **вручную в GUI** (ниже) или **одной командой из PowerShell** — см. `Install-ScheduledTasks.ps1` (в начале файла стоит `#Requires -RunAsAdministrator`). Скрипт регистрирует **`RDP Login Monitor`** (старт ОС, запуск `Login_Monitor.ps1`) и **`RDP Login Monitor Watchdog`** (старт ОС + повтор каждые 5 минут, запуск `Watchdog_RDP_Monitor.ps1` из того же каталога). Пути по умолчанию: `D:\Soft\`. Параметры: `-InstallRoot`, `-MainTaskName`, `-WatchdogTaskName`, `-WatchdogRepeatMinutes`, задержки случайного старта и т.д.

Пример после копирования файлов в `D:\Soft\`:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "D:\Soft\Install-ScheduledTasks.ps1"
```

Это не заменяет настройку токена Telegram в `Login_Monitor.ps1`, а только регистрирует задания.

### Задание №1: основной монитор (вручную)

Создайте задачу `RDP Login Monitor`:

- **General**
  - `Run whether user is logged on or not`
  - `Run with highest privileges`
  - `Configure for`: ваша версия Windows Server/Windows
- **Triggers**
  - `At startup` (при запуске системы)
- **Actions**
  - Program/script: `powershell.exe`
  - Add arguments:
    ```text
    -NoProfile -ExecutionPolicy Bypass -File "D:\Soft\Login_Monitor.ps1"
    ```
- **Settings**
  - `If the task is already running`: `Do not start a new instance`

### Задание №2: watchdog (вручную)

Создайте задачу `RDP Login Monitor Watchdog`:

- **General**
  - `Run whether user is logged on or not`
  - `Run with highest privileges`
- **Triggers**
  - `At startup`
  - Дополнительно: `Repeat task every 5 minutes` (или отдельный триггер по расписанию каждые 5 минут)
- **Actions**
  - Program/script: `powershell.exe`
  - Add arguments:
    ```text
    -NoProfile -ExecutionPolicy Bypass -File "D:\Soft\Watchdog_RDP_Monitor.ps1"
    ```
- **Settings**
  - `If the task is already running`: `Do not start a new instance`

> Если watchdog лежит не в `D:\Soft\`, поправьте путь в аргументах или параметр `-MainScriptPath`.

## 4) Что проверять после запуска

- Логи:
  - `D:\Soft\Logs\login_monitor.log`
  - `D:\Soft\Logs\watchdog.log`
- Heartbeat:
  - `D:\Soft\Logs\last_heartbeat.txt` обновляется примерно раз в час (по `$HeartbeatInterval`).
- Telegram при старте: при установленном **RD Session Host** (или аналогичных компонентах RDS, не только шлюз) — строка про входы по RDP/RDS на этом сервере; при доступном журнале **RD Gateway** — отдельная строка про подключения к **внутренним целевым ПК** через шлюз (302/303). Узел только с ролью RD Gateway не дублирует формулировку «хост сессий».

## 5) Автоматический перезапуск при падении

`Watchdog_RDP_Monitor.ps1` делает:

- проверяет, есть ли процесс `powershell.exe/pwsh.exe` с `Login_Monitor.ps1` в командной строке;
- если процесса нет — запускает монитор;
- если heartbeat старше `$HeartbeatStaleMinutes` (по умолчанию 90 минут) — перезапускает монитор.


