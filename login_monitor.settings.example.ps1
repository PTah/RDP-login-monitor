<#
.SYNOPSIS
    Локальные настройки Login_Monitor.ps1
.DESCRIPTION
    Скопируйте в C:\ProgramData\RDP-login-monitor\login_monitor.settings.ps1
    и при необходимости отредактируйте. Файл login_monitor.settings.ps1 не перезаписывается
    при автообновлении Login_Monitor.ps1 с шары (Deploy-LoginMonitor.ps1).
    При первой установке Deploy может создать login_monitor.settings.ps1 из этого example автоматически.
#>

# --- Telegram (или DPAPI Base64 через Encrypt-DpapiForRdpMonitor.ps1) ---
$TelegramBotToken = ''
$TelegramChatID = ''
# $TelegramBotTokenProtectedB64 = ''
# $TelegramChatIDProtectedB64 = ''

# --- Email (опционально) ---
$NotifyOrder = 'tg'
# $MailSmtpHost = 'smtp.example.com'
# $MailSmtpPort = 587
# $MailSmtpUser = ''
# $MailSmtpPassword = ''
# $MailFrom = 'monitor@example.com'
# $MailTo = 'admin@example.com'
# $MailSmtpStartTls = $true
# $MailSmtpSsl = $false
# $MailSmtpPasswordProtectedB64 = ''

# --- Security Alert Center (SAC) ---
# off | exclusive | dual | fallback — см. security-alert-center/docs/agent-integration.md
# $UseSAC = 'exclusive'
# $SacUrl = 'https://sac.kalinamall.ru'
# $SacApiKey = 'sac_xxxxxxxx'
# $SacSpoolDir = 'C:\ProgramData\RDP-login-monitor\sac-spool'
# $SacTimeoutSec = 12
# $SacTlsSkipVerify = $false
# $SacFallbackFailures = 5
# Проверка: powershell -File Login_Monitor.ps1 -CheckSac

# --- Узкое исключение шумовых сетевых логонов (LogonType=3, Advapi) ---
$IgnoreAdvapiNetworkLogonSourceIps = @(
    '192.168.160.57'
)

# --- Блокировка учётной записи AD (4740) + IP из IIS ActiveSync ---
# Мониторинг включается только на КД с именем $LockoutMonitorDomainController.
$LockoutMonitorDomainController = 'K6A-DC3'
$NetBiosDomainName = 'B26'
$ExchangeIisLogPath = '\\fifth.kalinamall.ru\c$\inetpub\logs\LogFiles\W3SVC1'
$ExchangeServerHostForIisExclude = ''
$ExchangeIisLogTailLines = 5000
$ExchangeIisLogMinutesBeforeLockout = 30
