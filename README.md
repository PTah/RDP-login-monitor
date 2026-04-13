# RDP Login Monitor

PowerShell-набор для мониторинга входов в Windows с отправкой уведомлений в Telegram:

- `Login_Monitor.ps1` — основной монитор (Security `4624/4625`, RD Gateway `302/303`, ротация логов, heartbeat, ежедневный отчет).
- `Watchdog_RDP_Monitor.ps1` — watchdog: проверяет, жив ли основной скрипт, и перезапускает его при падении/зависании heartbeat.

## Что изменилось (важное)

- **Кодировка `.ps1`**: в репозитории добавлены `.editorconfig` и `.gitattributes`, чтобы `*.ps1` по умолчанию сохранялись как **UTF-8 with BOM** и с **CRLF** (это сильно снижает “кракозябры” и ошибки парсинга PowerShell).
- **Кодировка логов**: `login_monitor.log` / `watchdog.log` пишутся как **UTF-8 с BOM** (и при необходимости BOM добавляется к уже существующему файлу), чтобы в **FAR/старых просмотрщиках** не было ситуации “в консоли нормально, а в файле РЈРІРµ…” из‑за неверной авто-кодировки.
- **Фильтрация шума PMG/LDAP**: добавлено узкое исключение для `4624` с `LogonType=3`, если `IpAddress=192.168.160.57` и `LogonProcessName` содержит `Advapi` (частые периодические сетевые логоны).
- **`auditpol` на русской Windows**: настройка/проверка аудита опирается на категорию **`Вход/выход`** и подкатегории **`Вход в систему` / `Выход из системы`** (ожидается строка **`Успех и сбой`**). Это устраняет ошибки вида `0x00000057` из‑за несуществующего на RU ОС имени `Logon`.
- **Стабильность**: `auditpol` запускается через `cmd.exe` с перехватом `stdout+stderr`, чтобы не ломать выполнение при `$ErrorActionPreference = "Stop"`.

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


