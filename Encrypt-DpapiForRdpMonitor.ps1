# Запуск: от администратора на ТОМ ЖЕ компьютере, где будет Login_Monitor.ps1.
# Результат (Base64) вставьте в $TelegramBotTokenProtectedB64 / $TelegramChatIDProtectedB64.
param(
    [Parameter(Mandatory = $true)][string]$PlainText
)
Add-Type -AssemblyName System.Security
$bytes = [Text.Encoding]::UTF8.GetBytes($PlainText)
$protected = [System.Security.Cryptography.ProtectedData]::Protect(
    $bytes, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine
)
[Convert]::ToBase64String($protected)
