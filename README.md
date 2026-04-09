# RDP Login Monitor

PowerShell-набор для мониторинга входов в Windows с отправкой уведомлений в Telegram:

- `Login_Monitor.ps1` — основной монитор (Security `4624/4625`, RD Gateway `302/303`, ротация логов, heartbeat, ежедневный отчет).
- `Watchdog_RDP_Monitor.ps1` — watchdog: проверяет, жив ли основной скрипт, и перезапускает его при падении/зависании heartbeat.

## 1) Подготовка

1. Скопируйте `Login_Monitor.ps1` в `D:\Soft\Login_Monitor.ps1` (или измените путь в watchdog).
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

### Задание №1: основной монитор

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

### Задание №2: watchdog

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

## 5) Автоматический перезапуск при падении

`Watchdog_RDP_Monitor.ps1` делает:

- проверяет, есть ли процесс `powershell.exe/pwsh.exe` с `Login_Monitor.ps1` в командной строке;
- если процесса нет — запускает монитор;
- если heartbeat старше `$HeartbeatStaleMinutes` (по умолчанию 90 минут) — перезапускает монитор.

