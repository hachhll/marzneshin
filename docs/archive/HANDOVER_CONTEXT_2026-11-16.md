# Handover Context и зафиксированные договорённости (2026-11-16)

Этот файл фиксирует текущую боевую архитектуру, причины всех внесённых исправлений, принятые эксплуатационные договорённости и безопасный регламент диагностики при возможном возврате с проблемами.

> **Примечание о безопасности репозитория:** живые IP-адреса, домены и секреты (UUID/ключи) намеренно не хранятся в Git. Фактические параметры каждого узла находятся локально в `/var/lib/marzneshin/state.json` и `/root/vpn-credentials/` (команда `sudo ./script.sh status` на сервере) и в локальном `~/.ssh/config`.

Связанные документы:
- [RISK_TRACKING_AND_MITIGATION.md](./RISK_TRACKING_AND_MITIGATION.md) — реестр рисков ТСПУ и чеклист мер.
- [RCA_SERVER_FAM_2026-11-15.md](./RCA_SERVER_FAM_2026-11-15.md) — разбор прошлой блокировки `<LEGACY_BLOCKED_IP>`.
- [HANDOVER_CONTEXT_2026-11-15.md](./HANDOVER_CONTEXT_2026-11-15.md) — исходный контекст миграции на стек `marzneshin`.

---

## 1. Текущая боевая инфраструктура (актуально на 2026-11-16)

| Роль | IP / Интерфейс | Домен / SNI | TLS / Порты снаружи | Ресурсы | SSH |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Входной мост (РФ, Москва, `REG.RU`)** | `<MOSCOW_BRIDGE_IP>` (за NAT, внутренний интерфейс `192.168.x.x`) | `<BRIDGE_DOMAIN>` (поддомен `<ROOT_DOMAIN>`, Cloudflare **DNS Only**, серое облако) | Let's Encrypt EC-256 (`--bridge-acme`), наружу открыты **только `443/tcp` и `22222/tcp`** (`80/tcp` закрыт после выпуска сертификата) | `955 MB` RAM, `0` swap | `ssh -p 22222 stealth@<MOSCOW_BRIDGE_IP>` |
| **Выходной узел (Германия, Франкфурт, `server-ai`)** | `<FRANKFURT_AI_EXIT_IP>` | `<EXIT_DOMAIN>` (Cloudflare **DNS Only**) | Let's Encrypt EC-256, наружу `443/tcp`, `80/tcp` (ACME), `22222/tcp` | `907 MB` RAM (свободно ~`461 MB`), `511 MB` swap | `ssh -p 22222 stealth@<FRANKFURT_AI_EXIT_IP>` |

**Маршрут трафика:**  
`Клиент (v2rayNG / Throne)` $\rightarrow$ `<MOSCOW_BRIDGE_IP>:443 (SNI=<BRIDGE_DOMAIN>, fp=firefox)` $\rightarrow$ `<FRANKFURT_AI_EXIT_IP>:443 (SNI=<EXIT_DOMAIN>, fp=firefox, flow=xtls-rprx-vision)` $\rightarrow$ `Интернет`.

**Текущая пользовательская нагрузка:**
- К `<FRANKFURT_AI_EXIT_IP>` напрямую никто не подключается.
- Через московский мост `<MOSCOW_BRIDGE_IP>` сейчас подключены только владелец (планшет с `v2rayNG`) и 1 дополнительный пользователь (`v2rayNG`, импорт текущей ссылки из `/root/vpn-credentials/links.txt`).

---

## 2. Критические технические настройки (не откатывать при обновлениях!)

1. **Закреплена версия `Xray v26.6.27` ([Dockerfile](./Dockerfile)):**
   - Начиная с `Xray v26.9.8+` (проверено и на `v26.11.9`), Reality на сервере принудительно требует постквантовый `X25519MLKEM768` до `X25519`, из-за чего клиенты на `sing-box 1.13/1.14` (`Throne`) падают при рукопожатии (`SagerNet/sing-box#4520`).
   - Обновлять `XRAY_VERSION` только после успешного прохождения [tests/test_cascade_e2e.py](./tests/test_cascade_e2e.py) с целевой версией `sing-box`.
2. **Защита от `CVE-2026-98432` (MPTCP) для `Xray v26.6.27`:**
   - На обоих серверах отключён MPTCP в ядре (`net.mptcp.enabled = 0` в `/etc/sysctl.d/99-vpn-hardening.conf`) и явно запрещён в Xray (`"tcpMptcp": false` в [config_builder.py](./app/xray/config_builder.py)).
3. **Отпечаток `uTLS=firefox` по умолчанию ([config_builder.py](./app/xray/config_builder.py), [profile_generator.py](./app/client/profile_generator.py)):**
   - Эмпирически доказано на сети пользователя в РФ: `fp=chrome` блокируется/режется оператором (даже при выключенном `Hev TUN`), тогда как **`fp=firefox` при включённом `Hev TUN` проходит стабильно**.
   - Не возвращать дефолт на `chrome`.
4. **Инварианты моста (`mode=bridge`):**
   - `mux.enabled = false` + `flow: "xtls-rprx-vision"` на исходящем плече к выходному узлу;
   - `routing.domainStrategy = "AsIs"` (ноль DNS-запросов на российском сервере);
   - `dest: "127.0.0.1:8443"` (Zero-Loop) + нейтральный `CN=localhost` и `444` на любые запросы без SNI или с чужим SNI (включая `<EXIT_DOMAIN>` при обращении к мосту);
   - при повторной раскатке за NAT (где на сетевом интерфейсе внутренний `192.168.x.x`) обязательно передавать `--bridge-ip <ПУБЛИЧНЫЙ_IP>`.
5. **Антишторм и стабильность TCP (`script.sh`, `config_builder.py`, `profile_generator.py`):**
   - Двусторонний `TCPMSS = 1360` в `/etc/ufw/before.rules` (`ufw-mangle-tcpmss`);
   - В ядре: `net.ipv4.tcp_retries2 = 5`, `tcp_fin_timeout = 15`, `tcp_syn_retries = 2`, `tcp_synack_retries = 2`, `tcp_max_syn_backlog = 4096`, `tcp_syncookies = 1`, `bbr + fq`, `disable_ipv6 = 1`;
   - `sockopt` (`tcpKeepAliveIdle=120`, `tcpKeepAliveInterval=30`, `tcpNoDelay=true`, `tcpMptcp=false`) прописан на инбаундах, на outbound моста, на `direct` outbound выходного узла и в `xray-client.json`;
   - В `sing-box` профилях (`throne-windows11.json`, `android-singbox.json`): актуальный DNS-формат `sing-box 1.12+` (`type: "udp"`, `detour: "proxy"`), `connect_timeout: "5s"`, `tcp_keep_alive: "2m"`, `tcp_keep_alive_interval: "30s"`, `override_android_vpn` — только для Android (убран из Windows-профиля);
   - В [manager.py](./app/nginx/manager.py) при атомарной записи decoy/Nginx-файлов выставляются права `0644` (иначе unprivileged-воркеры nginx отдают `403`).
6. **Zero-Surface / отсутствие URL подписок:**
   - Веб-панель и `/sub/...` отсутствуют намеренно. В **Throne** нельзя жать «Обновить подписки» — профили импортируются вручную из `/root/vpn-credentials/` (`links.txt` или `throne-windows11.json`). Актуальную ссылку всегда можно вывести на сервере командой `sudo ./script.sh status`.

---

## 3. Договорённости по пользователям и дальнейшему развитию

1. **Принцип работы каскада:**
   - Вход пользователей внутрь РФ (`<MOSCOW_BRIDGE_IP>`) $\rightarrow$ выход через Германию считается рабочей и более устойчивой к ТСПУ моделью, чем прямой коннект пользователей из РФ на зарубежный IP.
2. **Онбординг пользователя в `v2rayNG`:**
   - На **свежем актуальном `v2rayNG`** достаточно импортировать готовую ссылку (`sni=<BRIDGE_DOMAIN>`, `fp=firefox`) из буфера обмена и включить VPN — дополнительных настроек не требуется (при условии автосинхронизации времени телефона <= 60s, выключенных `Mux`/`Fragment` и отсутствия конфликтующего системного `Private DNS`).
   - При любом обрыве связи клиент не должен часами висеть в цикле автопереподключений (чтобы не генерировать всплеск `TCPTimeouts`).
   - Примечание по тесту задержки: `www.gstatic.com/generate_204` разрешён, а `connectivitycheck.gstatic.com` и `connectivitycheck.android.com` намеренно блокируются правилами сервера.
3. **Условия перед масштабированием на 5–10+ пользователей:**
   - **Разделение ключей (отдельные UUID):** сейчас CLI ([app/cli.py](./app/cli.py)) управляет только одним общим ключом (`owner`). При расширении группы до 5–10 человек нужно добавить SSH-команды `add-user` / `remove-user` (базовый `LocalXrayConfigBuilder` уже принимает список `clients`), чтобы отключать отдельного пользователя без `rotate` для всех.
   - **Изоляция `<FRANKFURT_AI_EXIT_IP>` (`server-ai`) и корневого домена `<ROOT_DOMAIN>`:**
     - Пока подключены только владелец и 1 пользователь — риск смешения низкий.
     - Перед массовым/семейным подключением вынести общих пользователей на отдельный 2-й зарубежный VPS (см. [HANDOVER_CONTEXT_2026-11-15.md](./HANDOVER_CONTEXT_2026-11-15.md), кандидат `<FAMILY_EXIT_IP>` или новый сервер от `2 GB RAM`) и **отдельный корневой домен** (не `*.<ROOT_DOMAIN>`), а также при необходимости поднять RAM до `2+ GB` на обоих плечах (сейчас по ~`900–955 MB`).

---

## 4. Протокол безопасной диагностики при возврате с проблемами

1. **Строгий запрет компрометации IP и аккаунтов:**
   - На российском мосту (`<MOSCOW_BRIDGE_IP>`) соблюдается **Zero-Emission**: не выполнять исходящих проверок к сторонним сервисам (`api.ipify.org`, `youtube.com`, Telegram и т.п.) и не запускать `speedtest-cli` до РФ.
   - Не включать логи доступа (`access_log off`, `loglevel: none`) и не выводить/не сохранять клиентские IP (например, не снимать сырые `ss -tnp`).
2. **Безопасные команды для быстрой проверки при инциденте:**
   - На каждом сервере:
     ```bash
     cd /opt/marzneshin && sudo ./script.sh self-test
     sudo ufw status
     nstat -az TcpExtEmbryonicRsts TcpExtTCPTimeouts TcpExtTCPSynRetrans
     ss -s
     free -m
     ```
   - Проверка TLS и заглушки снаружи (только к своим доменам `<BRIDGE_DOMAIN>` / `<EXIT_DOMAIN>`):
     ```bash
     echo | openssl s_client -connect <MOSCOW_BRIDGE_IP>:443 -servername <BRIDGE_DOMAIN> 2>&1 | grep -E "subject=|issuer=|Verify"
     echo | openssl s_client -connect <MOSCOW_BRIDGE_IP>:443 -noservername 2>&1 | grep -E "subject=|issuer=|Verify"
     ```
   - Проверка прохождения туннеля с рабочей станции — строго к `https://<EXIT_DOMAIN>/` (и опционально анонимно `https://1.1.1.1/cdn-cgi/trace`).
   - Проверка кодовой базы перед правками и деплоем:
     ```bash
     .venv/bin/python -m pytest tests/ -v
     ```
