# RDP Login Monitor

PowerShell-набор для мониторинга входов в Windows с уведомлениями в Telegram и/или Email (SMTP).

## Актуальная схема (рекомендуется)

- Базовый путь установки: **`C:\ProgramData\RDP-login-monitor\`**.
- Основной скрипт: **`Login_Monitor.ps1`** — журнал Security **`4624`/`4625`** (логика зависит от типа ОС: рабочая станция или сервер/КД), при всплеске **`4625`** — **агрегированные оповещения** (два порога: IP+пользователь и только IP), при наличии журнала — **Remote Connection Manager `1149`** (часто актуально для РС с RDP), **RDS Shadow Control** (`20506`/`20507`/`20510`, severity warning), **WinRM inbound / Enter-PSSession** (Operational `91`, severity warning), при роли **RD Gateway** — **`302`/`303`**, на **КД, где запущен монитор** (имя совпадает с **`$LockoutMonitorDomainController`**) — **`4740`** (блокировка УЗ + IP из IIS ActiveSync), **ежедневный отчёт** (активные сессии через `quser`), **heartbeat**, **ротация логов**, уведомления в Telegram и/или Email.
- Установка задач: запуск **`Login_Monitor.ps1 -InstallTasks`** создаёт:
  - `RDP-Login-Monitor` (основной монитор),
  - `RDP-Login-Monitor-Watchdog` (контроль процесса каждые 5 минут).
- Доменная доставка и обновления: **`Deploy-LoginMonitor.ps1`** + **`version.txt`** с шары `NETLOGON`. После успешного деплоя в приветственном сообщении (Telegram/Email) может появиться отметка об обновлении (файл **`deploy_last_update.txt`** рядом с логами).
- Документация по развёртыванию: **[Docs/README.md](Docs/README.md)** (RDP-монитор, Exchange, NETLOGON).
- **`Encrypt-DpapiForRdpMonitor.ps1`** — опционально для подготовки DPAPI-строк токена/chat id и пароля SMTP (`$MailSmtpPasswordProtectedB64` в файле настроек).
- **Локальные настройки RDP-монитора:** **`login_monitor.settings.ps1`** в каталоге установки (образец **`login_monitor.settings.example.ps1`**). При автообновлении **`Login_Monitor.ps1`** с шары файл настроек **не перезаписывается** (как **`exchange_monitor.settings.ps1`** для Exchange).
- **Security Alert Center (SAC):** модуль **`Sac-Client.ps1`** (копируется вместе с `Login_Monitor.ps1`). Режимы **`$UseSAC`**: `off` | `exclusive` | `dual` | `fallback` — контракт в репозитории **security-alert-center** (`docs/agent-integration.md`). Версия релиза: **`$ScriptVersion`** и **`version.txt`** (сейчас **2.0.0-SAC**); **`Sac-Client.ps1`** передаёт ту же версию в SAC (`product_version`).

## Что изменилось (важное)

- **Локальные настройки RDP-монитора** вынесены в **`login_monitor.settings.ps1`** (образец **`login_monitor.settings.example.ps1`**). При автообновлении **`Login_Monitor.ps1`** с шары секреты и параметры КД **не слетают**. Deploy при отсутствии settings создаёт файл один раз из example на шаре.
- **Кодировка `.ps1`**: в репозитории добавлены `.editorconfig` и `.gitattributes`, чтобы `*.ps1` по умолчанию сохранялись как **UTF-8 with BOM** и с **CRLF** (это сильно снижает “кракозябры” и ошибки парсинга PowerShell).
- **Кодировка логов**: `login_monitor.log` / `watchdog.log` пишутся как **UTF-8 с BOM** (и при необходимости BOM добавляется к уже существующему файлу), чтобы в **FAR/старых просмотрщиках** не было ситуации “в консоли нормально, а в файле РЈРІРµ…” из‑за неверной авто-кодировки.
- **`auditpol` на русской Windows**: настройка/проверка аудита опирается на категорию **`Вход/выход`** и подкатегории **`Вход в систему` / `Выход из системы`** (ожидается строка **`Успех и сбой`**). Это устраняет ошибки вида `0x00000057` из‑за несуществующего на RU ОС имени `Logon`.
- **Стабильность**: `auditpol` вызывается по полному пути `%SystemRoot%\System32\auditpol.exe` (без зависимости от PATH), stdout+stderr объединяются через `ProcessStartInfo`.
- **Агрегация 4625 (брутфорс)**: при включённом `$FailedLogonRateLimitEnabled` — уровень 1: **5** неудачных попыток за **60** с с одного источника для **одной** учётной записи (IP+user); уровень 2: **12** попыток за **60** с с одного IP (несколько логинов). Пока порог не достигнут — поштучные 4625; при всплеске — сводные алерты, одиночные подавляются. Параметры в начале `Login_Monitor.ps1`. Автоблокировка IP не выполняется.
- **Exchange Mail Security** (`Exchange-MailSecurity.ps1`): на **сервере Exchange** — очереди, пересылка на внешние адреса, watchdog. Руководство: **[Docs/exchange-mail-security.md](Docs/exchange-mail-security.md)**. GPO **`Deploy-LoginMonitor.ps1`** на MailServer ставит тот же RDP-монитор и дописывает WinRM/4624 noise в **`login_monitor.settings.ps1`**; **`Deploy-DomainMonitors.ps1 -Target Exchange`** — отдельно.

## 1) Подготовка

1. Подготовьте папку установки:
   - `C:\ProgramData\RDP-login-monitor\`
2. Скопируйте в неё как минимум:
   - `Login_Monitor.ps1`
   - `Sac-Client.ps1`
   - `login_monitor.settings.example.ps1` → переименуйте в **`login_monitor.settings.ps1`** и задайте параметры (см. п. 3)
   - (для доменного развёртывания отдельно на шаре) `Deploy-LoginMonitor.ps1`, `version.txt` и `login_monitor.settings.example.ps1`
3. Настройте **`C:\ProgramData\RDP-login-monitor\login_monitor.settings.ps1`** (не редактируйте секреты в `Login_Monitor.ps1` — они перезапишутся при деплое):
   - **Telegram:** `$TelegramBotToken` / `$TelegramChatID` или `...ProtectedB64`
   - **Email (SMTP):** `$MailSmtpHost`, `$MailFrom`, `$MailTo`, `$MailSmtpPort` (по умолчанию 587), при необходимости `$MailSmtpUser` / `$MailSmtpPassword` (или `$MailSmtpPasswordProtectedB64` через DPAPI), `$MailSmtpStartTls` / `$MailSmtpSsl`
   - **Порядок:** `$NotifyOrder` — пусто = авто (Telegram → Email, только настроенные); иначе `telegram,email` или `email` и т.п. (допускаются `tg`, `mail`)
   - **SAC (опционально):** `$UseSAC`, `$SacUrl`, `$SacApiKey` — см. блок в **`login_monitor.settings.example.ps1`**. Проверка: `Login_Monitor.ps1 -CheckSac`
   - **IP хоста для SAC (опционально):** `$ServerIPv4` — явный IPv4 для `host.ipv4`; если не задан, берётся автоопределение
   - **Exchange-шум 4624 (опционально):** `${Ignore4624-LT3-EmptyIP-Event} = $true` — подавляет `4624` c `LogonType=3` и `IP='-'` (часто Outlook/SMTP-клиенты на почтовом сервере)
   - Пошаговое обновление по домену: **[Docs/deploy-rdp-login-monitor.md](Docs/deploy-rdp-login-monitor.md)** (раздел «Обновление на любой Windows-машине»)
4. Запускайте с правами администратора (чтение `Security` журнала и регистрация задач).
5. Логи и служебные файлы будут в:
   - `C:\ProgramData\RDP-login-monitor\Logs\`
6. (Опционально) Подавление части алертов по списку — см. раздел **«7) ignore.lst»** ниже.
7. (Опционально) Мониторинг блокировок AD на КД — в **`login_monitor.settings.ps1`**: **`$LockoutMonitorDomainController`** (короткое имя узла, на котором **установлен и запущен** монитор), **`$NetBiosDomainName`**, **`$ExchangeIisLogPath`**, **`$ExchangeIisLogMinutesBeforeLockout`** (по умолчанию 30), **`$ExchangeIisLogTailLines`** (по умолчанию 5000), **`$ExchangeServerHostForIisExclude`**. В оповещении: пользователь из 4740 и IP из IIS за окно до блокировки. В **`ignore.lst`** префикс **`4740:`** или **`all:`** — см. **`ignore.lst.example`**.
8. Heartbeat: при отсутствии обновления **`Logs\last_heartbeat.txt`** дольше **`$HeartbeatStaleAlertMultiplier` × `$HeartbeatInterval`** (по умолчанию 2×1 ч) — оповещение в Telegram/Email.

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

Для доменной установки/обновления с шары вручную ничего в планировщике на клиенте настраивать не требуется: используйте `Deploy-LoginMonitor.ps1` (подробно в [Docs/deploy-rdp-login-monitor.md](Docs/deploy-rdp-login-monitor.md)).

## 4) Что проверять после запуска

- Логи:
  - `C:\ProgramData\RDP-login-monitor\Logs\login_monitor.log`
  - `C:\ProgramData\RDP-login-monitor\Logs\watchdog.log`
- Heartbeat:
  - `C:\ProgramData\RDP-login-monitor\Logs\last_heartbeat.txt` обновляется по интервалу **`$HeartbeatInterval`** (по умолчанию раз в час).
- Ежедневный отчёт: после первого прохождения дневного слота (по умолчанию **09:00**, задаётся **`$DailyReportHour`** / **`$DailyReportMinute`** в `Login_Monitor.ps1`) уходит сводка по **`quser`** (Telegram/Email); метка последнего отчёта — `Logs\last_daily_report.txt`.
- Stale heartbeat: если **`last_heartbeat.txt`** не обновлялся дольше **`$HeartbeatStaleAlertMultiplier` × `$HeartbeatInterval`** — оповещение в Telegram/Email (см. п. 8 подготовки).
- При старте в Telegram/Email: строка **«Каналы уведомлений»** (фактический порядок доставки), плюс режим RDS/4740 по конфигурации.
- Telegram при старте: при установленном **RD Session Host** (или аналогичных компонентах RDS, не только шлюз) — строка про входы по RDP/RDS на этом сервере; при доступном журнале **RD Gateway** — отдельная строка про подключения к **внутренним целевым ПК** через шлюз (302/303). Узел только с ролью RD Gateway не дублирует формулировку «хост сессий».
- **Дубли Telegram на один RDP-вход:** Windows часто пишет **несколько 4624** с одним временем; с версии **1.2.18-SAC** второе уведомление за **`$LoginSuccessNotifyDedupSeconds`** (90 с) подавляется (`Notify dedup 4624` в логе).
- **В логе нет `Notify`, но 4624 в Security есть:** монитор обрабатывает только события **после** своего `StartTime` (окно опроса ~10 с при старте). Ищите строки **`Skip 4624:`** (фильтр LogonType / ignore.lst). Диагностика: **`tools\Show-Rdp4624Recent.ps1`**.

## 5) Автоматический перезапуск при падении

Режим `-Watchdog` внутри `Login_Monitor.ps1` делает:

- проверяет, есть ли процесс `powershell.exe/pwsh.exe` с `Login_Monitor.ps1` в командной строке;
- если процесса нет — запускает монитор;
- если монитор уже есть — не дублирует экземпляр.

## 6) Дополнительные параметры и прочие файлы

- **`-SkipScheduledTaskMaintenance`**: при обычном запуске монитора не выполнять проверку/пересоздание задач планировщика (если регистрацию задач ведёте только через **`-InstallTasks`** или вручную).
- **`Install-DeployScheduledTask.ps1`** — helper для периодического запуска **`Deploy-LoginMonitor.ps1`** с шары (см. **[DEPLOY.md](DEPLOY.md)**).
- **`Watchdog_RDP_Monitor.ps1`** и **`Install-ScheduledTasks.ps1`** — **альтернативная** схема с отдельным watchdog-файлом и путями по умолчанию **`D:\Soft`**. Для новых установок рекомендуется встроенный режим **`-Watchdog`** в **`Login_Monitor.ps1`** и задачи **`RDP-Login-Monitor`** / **`RDP-Login-Monitor-Watchdog`**.
- **`ignore.lst.example`** в репозитории — образец файла **`ignore.lst`** для подавления отдельных уведомлений Security (см. раздел 7).
- **`Diagnose-RdpLoginMonitor.ps1`** — сбор диагностики после RDP-входа (Security 4624/4778, хвост `login_monitor.log`, симуляция фильтров монитора). Отчёт в **`Logs\diagnose_*.txt`**. Запуск:
  ```powershell
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\ProgramData\RDP-login-monitor\Diagnose-RdpLoginMonitor.ps1" -MinutesBack 15 -ExpectedUser "ваш_логин"
  ```
- **`login_monitor.settings.example.ps1`** — образец **`login_monitor.settings.ps1`** (Telegram, SMTP, 4740, локальные IP-исключения). Deploy при первой установке может создать `login_monitor.settings.ps1` из example автоматически.

## 7) Подавление уведомлений Security: `ignore.lst`

В каталоге установки можно положить файл **`C:\ProgramData\RDP-login-monitor\ignore.lst`** (рядом с **`Login_Monitor.ps1`**). По умолчанию правила относятся к **`4624`/`4625`**; префикс **`4740:`** (или **`lockout:`**, **`блокир:`**) — только к блокировкам учётной записи; **`all:`** — и входы, и **4740**. Для **4740** тип **`ip:`** сравнивается с IP из IIS ActiveSync. Жёсткие исключения в скрипте по-прежнему для всех типов событий, кроме **4740** (там только `ignore.lst` и встроенные проверки пользователя).

События **RD Gateway (`302`/`303`)**, **RCM `1149`**, ежедневный отчёт и heartbeat **этим файлом не настраиваются**.

### Как читается файл

- Чтение выполняется по мере обработки событий; содержимое **кэшируется в памяти**. Если **`LastWriteTimeUtc`** файла изменился (редактирование и сохранение), список **перечитывается автоматически** — перезапуск монитора не обязателен.
- Кодировка: **UTF-8** (`Get-Content -Encoding UTF8`). Строка может начинаться с BOM — он отбрасывается при разборе.
- Пустые строки пропускаются. Строки, начинающиеся с **`#`** или **`;`**, считаются комментариями.
- Строка с **`:`**: берётся **первая** двоеточие — всё слева (после обрезки пробелов) определяет тип правила, всё справа — значение. Если справа пусто, строка игнорируется.
- Строка **без** **`:`**: целиком трактуется как правило типа «любое совпадение» (см. ниже).

### Префикс области (в самом начале строки, до типа правила)

| Префикс | События |
| --- | --- |
| *(нет)* | **4624**, **4625** |
| `4740:`, `lockout:`, `блокир:` | **4740** |
| `all:`, `*:` | **4624**, **4625**, **4740** |

Пример: `4740:user:svc_sync` — не слать оповещение о блокировке этой УЗ.

### Типы правил (левая часть до первого `:` после префикса области)

| Левая часть (фрагменты совпадают как regex, без учёта регистра) | Поле события |
| --- | --- |
| `рабоч`, `workstation`, `wks` | имя рабочей станции (**WorkstationName** и аналоги в XML события) |
| `польз`, `username`, `subject`, `account`, `target user`, целое слово `user` | имя пользователя (**TargetUserName** и др.) |
| `ip`, `ip адрес`, `ipaddress`, `адрес ip` | IP источника (**IpAddress** и др.), только если в событии есть непустой IP |

Если левая часть **не** подошла ни к одному типу, но двоеточие есть — используется режим как в разборе строк Telegram: тип **«любое»**, значение — **только правая часть** (метка слева отбрасывается).

### Совпадение для типа «любое» (строка без `:` или «неизвестная» метка слева от `:`)

Проверка по очереди:

1. Если значение похоже на **IPv4** — сравнивается с IP источника в событии (точное совпадение, без учёта регистра для текста не применимо).
2. Если значение содержит **`\`** — сравнивается с **учётной записью**: полное совпадение с `DOMAIN\user` **или** совпадение с **SAM** после последнего `\` (как `DOMAIN\IVANOV` при правиле `IVANOV`).
3. Иначе сначала полное совпадение с **именем рабочей станции**, затем с **учётной записью** по тем же правилам, что в п.2.

Для явных типов **User** / **Workstation** / **Ip** используется только соответствующее поле (для пользователя — те же правила полного имени и SAM, что в п.2).

### Примеры и поставка

- Расширенные примеры строк — в **`ignore.lst.example`** в корне репозитория (скопируйте на сервер как **`ignore.lst`** и отредактируйте).
- **`Deploy-LoginMonitor.ps1`** **`ignore.lst`** и **`login_monitor.settings.ps1`** **не копирует и не перезаписывает** — правила и секреты локальны; при отсутствии settings Deploy создаёт его один раз из **`login_monitor.settings.example.ps1`** на шаре.

## Ключевые слова (для поиска репозитория)

`rdp`, `rd-gateway`, `rdp-gateway`, `rds`, `remote-desktop`, `windows-security-log`, `eventlog`, `event-id-4624`, `event-id-4625`, `event-id-4740`, `event-id-302`, `event-id-303`, `account-lockout`, `active-sync`, `exchange`, `iis`, `smtp`, `email`, `powershell`, `telegram-bot`, `watchdog`, `gpo`, `netlogon`, `domain-deployment`, `windows-server`, `monitoring`


