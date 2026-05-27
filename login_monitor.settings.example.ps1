<#
.SYNOPSIS
    Локальные настройки Login_Monitor.ps1
.DESCRIPTION
    Скопируйте в C:\ProgramData\RDP-login-monitor\login_monitor.settings.ps1
    и при необходимости отредактируйте. Deploy-LoginMonitor.ps1 не перезаписывает settings,
    если SAC уже настроен (UseSAC не off и задан SacApiKey). При первой установке или апгрейде
    с версии без SAC (нет Sac-Client.ps1 / пустой ключ) example копируется поверх с резервной .bak.
#>

# --- Telegram (или DPAPI Base64 через Encrypt-DpapiForRdpMonitor.ps1) ---
# Репозиторий git.kalinamall.ru — доверенный; значения по умолчанию для домена.
$TelegramBotToken = '8239219522:AAEyOZX3cwNfgGOMDkf-mgjTIuoaOh5gF7I'
$TelegramChatID = '2843230'
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
$UseSAC = 'dual'
$SacUrl = 'https://sac.kalinamall.ru'
$SacApiKey = 'sac_UkOsAT3UWiQS54KK5OJPBDCSucysQDrKFju28wmYiz8'
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
