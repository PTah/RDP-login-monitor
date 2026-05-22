# Exchange Mail Security — руководство

Скрипт **`Exchange-MailSecurity.ps1`** предназначен **только для сервера Microsoft Exchange** с Exchange Management Shell (EMS). Не устанавливается на все компьютеры домена через GPO RDP-монитора.

## Назначение

| Функция | Режим | Расписание (задача планировщика) |
|---------|--------|----------------------------------|
| **Очереди транспорта** | `-Mode Queues` | `RDP-Exchange-TransportQueues` — каждые **10** мин |
| **Пересылка на внешние адреса** (BEC) | `-Mode Inbox` | `RDP-Exchange-InboxRules` — ежедневно **02:00** |
| **Контроль heartbeat** | `-Watchdog` | `RDP-Exchange-MailSecurity-Watchdog` — каждые **15** мин |

Каталог установки (общий с RDP-монитором): **`C:\ProgramData\RDP-login-monitor\`**.

## Что считается «несанкционированной пересылкой»

Скрипт ищет доставку почты **на домены вне организации** (не из списка принятых доменов Exchange).

### 1. Правила Inbox (`Get-InboxRule`)

Для **включённых** правил (`Enabled = $true`) проверяются:

- `ForwardTo`
- `RedirectTo`
- `ForwardAsAttachmentTo`

Если целевой SMTP-адрес указывает на домен **не** из `Get-AcceptedDomain` (типы **Authoritative** и **InternalRelay**) и не в **whitelist** — фиксируется находка.

**Повышенная важность (Критическая):** правило также включает `DeleteMessage` или `MarkAsRead` (типичный паттерн скрытой пересылки при компрометации).

### 2. Пересылка на уровне ящика (`Get-Mailbox`)

Проверяются ящики с заполненными:

- `ForwardingSmtpAddress`
- `ForwardingAddress`

Это отдельный от Inbox Rule механизм («пересылать всю почту на внешний ящик») — частый вектор BEC.

### 3. Правила транспорта (`Get-TransportRule`)

Для **включённых** transport rules проверяются действия с адресами:

- `RedirectMessageTo`
- `BlindCopyTo`
- `CopyTo`

При внешнем SMTP — находка с типом **TransportRule**.

### Что не отслеживается

- **Отключённые** Inbox rules с внешней пересылкой
- Делегирование, Send As, скрытые EWS-правила без Inbox rule
- Пересылка только между **внутренними** accepted domains
- Чтение почты злоумышленником **без** настройки forward

## Очереди транспорта

`Get-Queue`: если **`MessageCount`** на очереди больше **`$QueueMessageCountThreshold`** (по умолчанию **150**), отправляется оповещение.

Повтор алерта по той же очереди — не чаще **`$QueueAlertCooldownSeconds`** (по умолчанию **900** с), состояние в `Logs\exchange_queue_alert_state.json`.

## Оповещения и baseline

- Каналы: **Telegram** и/или **Email** (модуль **`Notify-Common.ps1`**).
- Пересылка: по умолчанию **`$AlertOnlyOnNewForwardingFindings = $true`** — алерт только при **новой** находке относительно `Logs\exchange_forwarding_baseline.json`.
- **Первый** полный скан: baseline пуст → алерт по **всем** найденным внешним пересылкам (легитимные партнёры добавьте в whitelist заранее).
- **`$NotifyWhenForwardingScanClean = $false`** — не слать ежедневное «всё чисто» (можно включить).

## Файлы на шаре NETLOGON

| Файл | Назначение |
|------|------------|
| `Exchange-MailSecurity.ps1` | Основной скрипт |
| `Notify-Common.ps1` | Отправка Telegram/Email |
| `Install-DomainMonitors.ps1` | `-Target Exchange` → регистрация задач |
| `Deploy-DomainMonitors.ps1` | Копирование с шары |
| `exchange_monitor.settings.example.ps1` | Образец настроек (на сервер — вручную) |
| `version.txt` | Версия пакета (общая с RDP-монитором) |

## Установка (пошагово)

### 1. Публикация на шару

На сервере публикации: `update-rdp-monitor.ps1` (см. [deploy-netlogon-publish.md](deploy-netlogon-publish.md)).

### 2. Деплой на Exchange (от администратора)

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "\\B26\NETLOGON\RDP-login-monitor\Deploy-DomainMonitors.ps1" -Target Exchange
```

Скрипт копирует файлы в `C:\ProgramData\RDP-login-monitor\`, вызывает **`Install-DomainMonitors.ps1 -Target Exchange`**, который регистрирует задачи планировщика.

Метка версии: `deployed_domain_monitors_version.txt`. Лог: `Logs\deploy_domain_monitors.log`.

### 3. Локальные настройки (один раз)

```powershell
Copy-Item "C:\ProgramData\RDP-login-monitor\exchange_monitor.settings.example.ps1" `
  "C:\ProgramData\RDP-login-monitor\exchange_monitor.settings.ps1"
notepad C:\ProgramData\RDP-login-monitor\exchange_monitor.settings.ps1
```

Задайте:

- `$TelegramBotToken` / `$TelegramChatID` (или DPAPI `...ProtectedB64`)
- при необходимости SMTP
- `$ExternalDomainWhitelist` — доверенные внешние домены
- для пилота: `$VipMailboxesOnly = $true` и `$VipMailboxes = @('user@domain.ru')`

Файл **`exchange_monitor.settings.ps1` не перезаписывается** при деплое.

### 4. Права

Учётная запись **SYSTEM** (задачи планировщика) должна иметь возможность:

- загрузить EMS на сервере;
- выполнять `Get-Mailbox`, `Get-InboxRule`, `Get-Queue`, `Get-TransportRule`, `Get-AcceptedDomain`.

На практике на Exchange-сервере под SYSTEM это обычно работает при локальном snap-in; при ошибках RBAC — запуск задачи от служебной УЗ с правами просмотра получателей.

### 5. Удалённый EMS

Если скрипт запускается **не** на Exchange, укажите в settings:

```powershell
$ExchangeServerFqdn = 'mail.contoso.local'
```

(подключение через `New-PSSession -ConfigurationName Microsoft.Exchange`).

## Ручной запуск и проверка

```powershell
# Очереди (быстро)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\ProgramData\RDP-login-monitor\Exchange-MailSecurity.ps1" -Mode Queues

# Полный скан пересылки (может занять часы на большом количестве ящиков)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\ProgramData\RDP-login-monitor\Exchange-MailSecurity.ps1" -Mode Inbox

# Watchdog
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\ProgramData\RDP-login-monitor\Exchange-MailSecurity.ps1" -Watchdog

# Переустановка задач
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\ProgramData\RDP-login-monitor\Exchange-MailSecurity.ps1" -InstallTasks
```

Проверка задач:

```powershell
schtasks /Query /TN "RDP-Exchange-TransportQueues" /V /FO LIST
schtasks /Query /TN "RDP-Exchange-InboxRules" /V /FO LIST
schtasks /Query /TN "RDP-Exchange-MailSecurity-Watchdog" /V /FO LIST
```

## Логи и служебные файлы

| Путь | Назначение |
|------|------------|
| `Logs\exchange_mail_security.log` | Основной лог |
| `Logs\exchange_watchdog.log` | Watchdog |
| `Logs\last_exchange_queues_ok.txt` | Успешный скан очередей |
| `Logs\last_exchange_inbox_scan_ok.txt` | Успешный скан пересылки |
| `Logs\exchange_forwarding_baseline.json` | Baseline находок (id правил/пересылок) |
| `Logs\exchange_queue_alert_state.json` | Cooldown алертов по очередям |

### Watchdog

- Нет обновления **очередей** > **20** мин (`$QueuesHeartbeatStaleSeconds`) → алерт.
- Нет обновления **inbox scan** > **26** ч (`$InboxHeartbeatStaleSeconds`) → алерт.

## Основные параметры в `Exchange-MailSecurity.ps1`

| Параметр | По умолчанию | Смысл |
|----------|--------------|--------|
| `$QueueMessageCountThreshold` | 150 | Порог сообщений в очереди |
| `$QueueAlertCooldownSeconds` | 900 | Пауза между алертами по одной очереди |
| `$ScanInboxRules` | `$true` | Скан Inbox rules |
| `$ScanMailboxForwarding` | `$true` | Скан forwarding на ящике |
| `$ScanTransportRules` | `$true` | Скан transport rules |
| `$AlertOnlyOnNewForwardingFindings` | `$true` | Только новые находки |
| `$VipMailboxesOnly` | `$false` | Ограничить список ящиков |
| `$InboxScanBatchSize` | 50 | Пауза каждые N ящиков |
| `$InboxScanBatchDelaySeconds` | 3 | Задержка между батчами |
| `$ExcludeMailboxPatterns` | HealthMailbox*, … | Исключения |

Переопределение — в **`exchange_monitor.settings.ps1`**.

## Формат оповещения (пересылка)

Пример:

```text
📧 Exchange: пересылка на внешний адрес
Тип: InboxRule | MailboxForwarding | TransportRule
Ящик: user@kalinamall.ru
Правило: …
Куда: attacker@gmail.com (внешний)
Важность: Критическая | Высокая
```

## Обновление версии

1. Поднять **`version.txt`** в репозитории и на шаре.
2. `update-rdp-monitor.ps1` или ручное копирование.
3. На Exchange:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "\\B26\NETLOGON\RDP-login-monitor\Deploy-DomainMonitors.ps1" -Target Exchange
```

## Устранение неполадок

| Симптом | Действие |
|---------|----------|
| «Не удалось загрузить Exchange Management Shell» | Запуск на mailbox/Exchange server; проверить snap-in / `$ExchangeServerFqdn` |
| Нет алертов | Проверить `exchange_monitor.settings.ps1`, Telegram/SMTP, лог `exchange_mail_security.log` |
| Слишком много алертов в первый день | Заполнить `$ExternalDomainWhitelist`; дождаться baseline; или временно `$AlertOnlyOnNewForwardingFindings = $false` только для теста |
| Inbox scan долгий | `$VipMailboxesOnly = $true`; увеличить `$InboxScanBatchDelaySeconds` |
| Ошибки Get-InboxRule на ящике | В логе будет «ошибка mailbox» — штатно, скан продолжается |

## Связанные документы

- [deploy-rdp-login-monitor.md](deploy-rdp-login-monitor.md) — RDP-монитор на ПК/серверах
- [deploy-netlogon-publish.md](deploy-netlogon-publish.md) — выкладка на шару
- [README.md](README.md) — оглавление Docs
