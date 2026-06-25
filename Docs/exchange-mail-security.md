# Exchange Mail Security — руководство

Скрипт **`Exchange-MailSecurity.ps1`** предназначен **только для сервера Microsoft Exchange** с Exchange Management Shell (EMS). Не устанавливается на все компьютеры домена через GPO RDP-монитора.

На Exchange-сервере GPO **`Deploy-LoginMonitor.ps1`** по-прежнему ставит **`Login_Monitor.ps1`** (RDP/WinRM/4624) и при необходимости дописывает noise settings в **`login_monitor.settings.ps1`**. Пакет **`Exchange-MailSecurity.ps1`** доставляется отдельно — см. раздел «Деплой на Exchange» ниже и [deploy-rdp-login-monitor.md](deploy-rdp-login-monitor.md).

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

Для **включённых** правил проверяются:

- `ForwardTo`
- `RedirectTo`
- `ForwardAsAttachmentTo`

Если целевой SMTP-адрес указывает на домен **не** из `Get-AcceptedDomain` (типы **Authoritative** и **InternalRelay**) и не в **whitelist** — фиксируется находка.

**Повышенная важность (Критическая):** включённое правило с `DeleteMessage` или `MarkAsRead`.

**Отключённые правила** (`$ScanDisabledInboxRulesWithExternalForward = $true`): внешняя пересылка фиксируется с важностью **«Средняя (правило отключено)»**.

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

- Делегирование, Send As, скрытые EWS-правила без Inbox rule
- Пересылка только между **внутренними** accepted domains
- Чтение почты злоумышленником **без** настройки forward

## Очереди транспорта

`Get-Queue`: если **`MessageCount`** на очереди больше **`$QueueMessageCountThreshold`** (по умолчанию **150**), отправляется оповещение.

Повтор алерта по той же очереди — не чаще **`$QueueAlertCooldownSeconds`** (по умолчанию **900** с), состояние в `Logs\exchange_queue_alert_state.json`.

## Оповещения и baseline

- Каналы: **Telegram** и/или **Email** (модуль **`Notify-Common.ps1`**).
- Пересылка: **`$AlertOnlyOnNewForwardingFindings = $true`** — алерт при **новой** находке (`Logs\exchange_forwarding_baseline.json`).
- **Первый скан:** **`$SuppressAlertsOnFirstBaselineRun = $true`** (по умолчанию) — существующие пересылки **только в baseline**, без всплеска алертов; одна **сводка** (`$SendInboxScanSummary`).
- Далее — алерт только при **новых** или **изменённых** пересылках (в т.ч. включили ранее отключённое правило).
- **`$NotifyWhenForwardingScanClean = $false`** — не слать «всё чисто» при нуле находок.

## Режим VIP (пилот)

В **`exchange_monitor.settings.ps1`**:

```powershell
$VipMailboxesOnly = $true
$VipMailboxes = @('director@domain.ru', 'cfo@domain.ru')
$VipMailboxPatterns = @('*@domain.ru')   # опционально
```

- **Список** — точные SMTP.
- **Шаблоны** — дополнительно обход `Get-Mailbox` и отбор по `-like`.
- Mailbox forwarding и Inbox rules — только в рамках VIP.
- Для полного домена: **`$VipMailboxesOnly = $false`**.

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
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "\\dc.contoso.local\NETLOGON\RDP-login-monitor\Deploy-DomainMonitors.ps1" -Target Exchange
```

Скрипт копирует файлы в `C:\ProgramData\RDP-login-monitor\`, вызывает **`Install-DomainMonitors.ps1 -Target Exchange`**, который регистрирует задачи планировщика.

Метка версии: `deployed_domain_monitors_version.txt`. Лог: `Logs\deploy_domain_monitors.log`.

### 3. Локальные настройки (один раз)

```powershell
# После Deploy v1.6.4+ образец лежит в ProgramData; иначе — с NETLOGON:
$ex = 'C:\ProgramData\RDP-login-monitor'
$src = Join-Path $ex 'exchange_monitor.settings.example.ps1'
if (-not (Test-Path -LiteralPath $src)) {
    $src = '\\dc.contoso.local\NETLOGON\RDP-login-monitor\exchange_monitor.settings.example.ps1'
}
Copy-Item -LiteralPath $src -Destination (Join-Path $ex 'exchange_monitor.settings.ps1')
notepad (Join-Path $ex 'exchange_monitor.settings.ps1')
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
| `$VipMailboxesOnly` | `$false` | Только VIP-ящики |
| `$VipMailboxPatterns` | `@()` | Wildcard для VIP |
| `$SuppressAlertsOnFirstBaselineRun` | `$true` | Первый скан без N алертов |
| `$ScanDisabledInboxRulesWithExternalForward` | `$true` | Отключённые правила с внешним forward |
| `$SendInboxScanSummary` | `$true` | Сводка после скана |
| `$InboxScanBatchSize` | 50 | Пауза каждые N ящиков |
| `$InboxScanBatchDelaySeconds` | 3 | Задержка между батчами |
| `$ExcludeMailboxPatterns` | HealthMailbox*, … | Исключения |
| `$SkipInboxScanMailboxes` | `user@example.com` | Не вызывать `Get-InboxRule` (битый rule store) |

Переопределение — в **`exchange_monitor.settings.ps1`**.

После починки ящика удалите его из `$SkipInboxScanMailboxes`.

## Формат оповещения (пересылка)

Пример:

```text
📧 Exchange: пересылка на внешний адрес
Тип: InboxRule | MailboxForwarding | TransportRule
Ящик: user@example.com
Правило: …
Куда: attacker@gmail.com (внешний)
Важность: Критическая | Высокая
```

## Обновление версии

1. Поднять **`version.txt`** в репозитории и на шаре.
2. `update-rdp-monitor.ps1` или ручное копирование.
3. На Exchange:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "\\dc.contoso.local\NETLOGON\RDP-login-monitor\Deploy-DomainMonitors.ps1" -Target Exchange
```

## Устранение неполадок

| Симптом | Действие |
|---------|----------|
| «Не удалось загрузить Exchange Management Shell» | Запуск на mailbox/Exchange server; проверить snap-in / `$ExchangeServerFqdn` |
| Нет алертов | Проверить `exchange_monitor.settings.ps1`, Telegram/SMTP, лог `exchange_mail_security.log` |
| Слишком много алертов в первый день | По умолчанию подавлены (`$SuppressAlertsOnFirstBaselineRun`); иначе whitelist + baseline |
| Inbox scan долгий | `$VipMailboxesOnly = $true`; увеличить `$InboxScanBatchDelaySeconds` |
| Ошибки Get-InboxRule на ящике | В логе будет «ошибка mailbox» — штатно, скан продолжается |

## Связанные документы

- [deploy-rdp-login-monitor.md](deploy-rdp-login-monitor.md) — RDP-монитор на ПК/серверах
- [deploy-netlogon-publish.md](deploy-netlogon-publish.md) — выкладка на шару
- [README.md](README.md) — оглавление Docs
