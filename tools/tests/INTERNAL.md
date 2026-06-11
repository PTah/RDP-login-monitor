# Autotests (kalinamall only)

Каталог `tools/tests/` и `tools/Run-RdpMonitorTests.ps1` — **внутренние** smoke-тесты.

## Запуск

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\Run-RdpMonitorTests.ps1
```

Перед push правок `Deploy-LoginMonitor.ps1` / `Login_Monitor.ps1` / `RdpMonitor-TaskQuery.ps1`.

## Git remotes

- **kalinamall** — публиковать можно (`git push kalinamall main`)
- **GitHub (origin)** — **не пушить** коммиты с этими тестами на публичный remote

После работы с тестами:

```powershell
git push kalinamall main
```

На `origin` (GitHub) не выполнять push, если в коммите есть `tools/tests/` или `tools/Run-RdpMonitorTests.ps1`.
