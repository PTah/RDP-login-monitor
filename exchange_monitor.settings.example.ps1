<#
.SYNOPSIS
    Пример локальных настроек Exchange-MailSecurity.ps1
.DESCRIPTION
    Скопируйте в C:\ProgramData\RDP-login-monitor\exchange_monitor.settings.ps1
    и задайте секреты / whitelist. Файл не деплоится с шары автоматически.
#>

# Telegram (или DPAPI Base64 с Encrypt-DpapiForRdpMonitor.ps1)
$TelegramBotToken = ''
$TelegramChatID = ''
# $TelegramBotTokenProtectedB64 = ''
# $TelegramChatIDProtectedB64 = ''

# SMTP (опционально)
# $MailSmtpHost = 'smtp.example.com'
# $MailFrom = 'monitor@example.com'
# $MailTo = 'admin@example.com'
# $NotifyOrder = 'telegram,email'

# Внешние домены-партнёры (не считать угрозой)
$ExternalDomainWhitelist = @(
    # 'partner-bank.ru'
)

# Очереди
$QueueMessageCountThreshold = 150

# --- Пилот VIP (рекомендуется для первого запуска) ---
# $VipMailboxesOnly = $true
# $VipMailboxes = @(
#     'director@example.com',
#     'cfo@example.com'
# )
# $VipMailboxPatterns = @(
#     '*@example.com'   # опционально: все ящики домена из Get-Mailbox
# )

# Первый ночной скан: не слать сотни алертов по уже существующим пересылкам
# $SuppressAlertsOnFirstBaselineRun = $true   # по умолчанию в скрипте уже $true

# Отключённые Inbox rules с внешней пересылкой (важность «Средняя»)
# $ScanDisabledInboxRulesWithExternalForward = $true

# Сводка в TG/Email после каждого скана
# $SendInboxScanSummary = $true

# Удалённый EMS (если скрипт не на Exchange)
# $ExchangeServerFqdn = 'mail.example.com'

# Не сканировать Inbox rules (битое хранилище правил / Watson на Get-InboxRule)
# $SkipInboxScanMailboxes = @(
#     'user@example.com'
# )
