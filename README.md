# RDP Login Monitor

PowerShell-набор для мониторинга входов в Windows с отправкой уведомлений в Telegram.

## Актуальная схема (рекомендуется)

- Базовый путь установки: **`C:\ProgramData\RDP-login-monitor\`**.
- Основной скрипт: **`Login_Monitor.ps1`** (Security `4624/4625`, опционально RD Gateway `302/303`, heartbeat, ротация логов, уведомления).
- Установка задач: запуск **`Login_Monitor.ps1 -InstallTasks`** создаёт:
  - `RDP-Login-Monitor` (основной монитор),
  - `RDP-Login-Monitor-Watchdog` (контроль процесса каждые 5 минут).
- Доменная доставка и обновления: **`Deploy-LoginMonitor.ps1`** + **`version.txt`** с шары `NETLOGON`.
- Для полной инструкции по деплою/GPO используйте **[DEPLOY.md](DEPLOY.md)**.
- **`Encrypt-DpapiForRdpMonitor.ps1`** — опционально для подготовки DPAPI-строк токена/chat id.

## Что изменилось (важное)

- **Кодировка `.ps1`**: в репозитории добавлены `.editorconfig` и `.gitattributes`, чтобы `*.ps1` по умолчанию сохранялись как **UTF-8 with BOM** и с **CRLF** (это сильно снижает “кракозябры” и ошибки парсинга PowerShell).
- **Кодировка логов**: `login_monitor.log` / `watchdog.log` пишутся как **UTF-8 с BOM** (и при необходимости BOM добавляется к уже существующему файлу), чтобы в **FAR/старых просмотрщиках** не было ситуации “в консоли нормально, а в файле РЈРІРµ…” из‑за неверной авто-кодировки.
- **`auditpol` на русской Windows**: настройка/проверка аудита опирается на категорию **`Вход/выход`** и подкатегории **`Вход в систему` / `Выход из системы`** (ожидается строка **`Успех и сбой`**). Это устраняет ошибки вида `0x00000057` из‑за несуществующего на RU ОС имени `Logon`.
- **Стабильность**: `auditpol` запускается через `cmd.exe` с перехватом `stdout+stderr`, чтобы не ломать выполнение при `$ErrorActionPreference = "Stop"`.

## 1) Подготовка

1. Подготовьте папку установки:
   - `C:\ProgramData\RDP-login-monitor\`
2. Скопируйте в неё как минимум:
   - `Login_Monitor.ps1`
   - (для доменного развёртывания отдельно на шаре) `Deploy-LoginMonitor.ps1` и `version.txt`.
3. Откройте `Login_Monitor.ps1` и задайте токен/чат:
   - `$TelegramBotToken` или `...ProtectedB64`
   - `$TelegramChatID` или `...ProtectedB64`
4. Запускайте с правами администратора (чтение `Security` журнала и регистрация задач).
5. Логи и служебные файлы будут в:
   - `C:\ProgramData\RDP-login-monitor\Logs\`

## 2) Ручной запуск

Используйте этот вариант для быстрой проверки старта/логики без установки задач планировщика.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\ProgramData\RDP-login-monitor\Login_Monitor.ps1"
```

Примечание: при ручном запуске монитор работает в текущей сессии до остановки (например, `Ctrl+C`).

## 3) Запуск через Планировщик заданий (Task Scheduler)

Текущая схема: вручную задачи в GUI создавать не нужно.

Достаточно запустить:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\ProgramData\RDP-login-monitor\Login_Monitor.ps1" -InstallTasks
```

Скрипт сам зарегистрирует `RDP-Login-Monitor` и `RDP-Login-Monitor-Watchdog`, а также запросит немедленный первый запуск задач.

Для доменной установки/обновления с шары вручную ничего в планировщике на клиенте настраивать не требуется: используйте `Deploy-LoginMonitor.ps1` (подробно в `DEPLOY.md`).

## 4) Что проверять после запуска

- Логи:
  - `C:\ProgramData\RDP-login-monitor\Logs\login_monitor.log`
  - `C:\ProgramData\RDP-login-monitor\Logs\watchdog.log`
- Heartbeat:
  - `C:\ProgramData\RDP-login-monitor\Logs\last_heartbeat.txt` обновляется примерно раз в час (по `$HeartbeatInterval`).
- Telegram при старте: при установленном **RD Session Host** (или аналогичных компонентах RDS, не только шлюз) — строка про входы по RDP/RDS на этом сервере; при доступном журнале **RD Gateway** — отдельная строка про подключения к **внутренним целевым ПК** через шлюз (302/303). Узел только с ролью RD Gateway не дублирует формулировку «хост сессий».

## 5) Автоматический перезапуск при падении

Режим `-Watchdog` внутри `Login_Monitor.ps1` делает:

- проверяет, есть ли процесс `powershell.exe/pwsh.exe` с `Login_Monitor.ps1` в командной строке;
- если процесса нет — запускает монитор;
- если монитор уже есть — не дублирует экземпляр.

## Ключевые слова (для поиска репозитория)

`rdp`, `rd-gateway`, `rdp-gateway`, `rds`, `remote-desktop`, `windows-security-log`, `eventlog`, `event-id-4624`, `event-id-4625`, `event-id-302`, `event-id-303`, `powershell`, `telegram-bot`, `watchdog`, `gpo`, `netlogon`, `domain-deployment`, `windows-server`, `monitoring`


