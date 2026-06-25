# Telegram bot token (use BotFather; never commit real values)
$TelegramBotToken = 'YOUR_TELEGRAM_BOT_TOKEN'
$TelegramChatID = 'YOUR_TELEGRAM_CHAT_ID'
# $TelegramBotTokenProtectedB64 = ''
# $TelegramChatIDProtectedB64 = ''

# --- Email (optional) ---
# $MailSmtpHost = 'smtp.example.com'
# $MailSmtpPort = 587
# $MailSmtpUser = ''
# $MailSmtpPassword = ''
# $MailFrom = 'monitor@example.com'
# $MailTo = 'admin@example.com'
# $MailSmtpStartTls = $true
# $MailSmtpSsl = $false
# $MailSmtpPasswordProtectedB64 = ''

# --- Security Alert Center (optional) ---
# UseSAC: off | exclusive | dual | fallback
$UseSAC = 'off'
$SacUrl = 'https://sac.example.com'
# $SacApiKey = 'your-ingest-api-key'

# --- Domain / lockout (adjust for your AD) ---
# $LockoutMonitorDomainController = 'DC01'
# $NetBiosDomainName = 'CONTOSO'

# --- Local IP exclusions (examples) ---
# $IgnoreSourceIpList = @('127.0.0.1', '::1')

# --- Log rotation and backup retention (Logs\Backup\LoginLog_*.bak) ---
# $LogRotationHour = 0
# $LogRotationMinute = 0
$MaxBackupDays = 31

# Copy this file to C:\ProgramData\RDP-login-monitor\login_monitor.settings.ps1
# Deploy-LoginMonitor.ps1 does not overwrite existing settings.
