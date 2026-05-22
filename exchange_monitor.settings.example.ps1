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

# Скан ящиков: только VIP (для первого пилота)
# $VipMailboxesOnly = $true
# $VipMailboxes = @('ceo@kalinamall.ru', 'cfo@kalinamall.ru')

# Удалённый EMS (если скрипт не на Exchange)
# $ExchangeServerFqdn = 'fifth.kalinamall.ru'
