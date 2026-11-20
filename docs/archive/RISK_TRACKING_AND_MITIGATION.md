# Реестр рисков блокировки (Anti-TSPU) и план устранения

**Дата создания:** 2026-11-16  
**База анализа:** [RCA_SERVER_FAM_2026-11-15.md](./RCA_SERVER_FAM_2026-11-15.md), [HANDOVER_CONTEXT_2026-11-15.md](./HANDOVER_CONTEXT_2026-11-15.md), живой аудит узлов `<MOSCOW_BRIDGE_IP>` (Москва) и `<FRANKFURT_AI_EXIT_IP>` (Франкфурт).  
**Главная цель:** не допустить повторения сценария блокировки `<LEGACY_BLOCKED_IP>` (`server-fam`) и защитить рабочий AI-сервер во Франкфурте (`<FRANKFURT_AI_EXIT_IP>`).

> **Примечание о безопасности репозитория:** живые IP-адреса, домены, UUID, `PublicKey` и `shortId` здесь намеренно заменены на плейсхолдеры. Фактические параметры хранятся локально на каждом сервере в `/var/lib/marzneshin/state.json` и `/root/vpn-credentials/` (команда `sudo ./script.sh status`).

---

## 1. Базовый срез состояния серверов (2026-11-16)

- **Франкфурт (`<FRANKFURT_AI_EXIT_IP>`, `<EXIT_DOMAIN>`)**:
  - Активная проверка TLS без SNI / с чужим SNI: отдаётся нейтральный `CN=localhost` и соединение закрывается с кодом `444` (`TLS alert 80` отсутствует).
  - Активная проверка TLS с `SNI = <EXIT_DOMAIN>`: валидный сертификат Let's Encrypt (`Verify return code: 0 (ok)`), HTTP `:80` по голому IP сбрасывает пустым ответом (`444`).
  - `iptables -t mangle`: `TCPMSS set 1360` активен.
  - Счётчики ядра: `estab 2`, `TcpExtTCPSynRetrans = 59`, `TcpExtTCPTimeouts = 98` (признаков ТСПУ-блокировки нет).
- **Москва (`<MOSCOW_BRIDGE_IP>`, мост `--bridge`, `<BRIDGE_DOMAIN>`)**:
  - Порт `:80` закрыт, открыты только `:443/tcp` и `:22222/tcp`.
  - Вход моста переведён на отдельный `SNI = <BRIDGE_DOMAIN>` с настоящим сертификатом Let's Encrypt (`Verify return code: 0 (ok)`) и отдачей статического decoy (`HTTP/2 200`); без SNI или с чужим SNI (`<EXIT_DOMAIN>`) отдаётся `CN=localhost` + `444`.
  - `self-test`: `5/5 [PASS]` без предупреждений `WARN`.
  - `iptables -t mangle`: `TCPMSS set 1360` активен.
  - Счётчики ядра на раннем срезе (`18:08`): `estab 2`, `TcpExtTCPSynRetrans = 142` (`TcpExtTCPTimeouts = 16172` были накоплены при ранней отладке до `tcp_retries2 = 5` и `fp=firefox`).

---

## 2. Что уже закрыто в коде и на серверах

- [x] **Отпечаток `uTLS=firefox` по умолчанию** ([config_builder.py](./app/xray/config_builder.py), [profile_generator.py](./app/client/profile_generator.py)): устранена блокировка `uTLS=chrome` со стороны российских операторов/ТСПУ (подтверждено перекрёстным тестом: с `chrome` без `Hev TUN` не работало, с `firefox` и включённым `Hev TUN` тесты проходят).
- [x] **Фиксация совместимой версии `Xray v26.6.27`** ([Dockerfile](./Dockerfile)) и отключение MPTCP (`net.mptcp.enabled = 0`, `tcpMptcp: false`, [tests/test_cascade_e2e.py](./tests/test_cascade_e2e.py)).
- [x] **Устранение `TLS alert 80`, второго порта `:8443` и `/sub/`-эндпоинтов** ([manager.py](./app/nginx/manager.py)): на входе оставлен только `:443`, заглушка `CN=localhost + 444` на посторонние SNI, убран фоновый `urltest` в `sing-box`.
- [x] **Защита от зависания сокетов и таймаут-штормов** ([script.sh](./script.sh), [config_builder.py](./app/xray/config_builder.py), [profile_generator.py](./app/client/profile_generator.py)):
  - `sockopt` (`tcpKeepAliveIdle=120`, `tcpKeepAliveInterval=30`, `tcpNoDelay=true`, `tcpMptcp=false`) добавлен на инбаундах, плече моста, `direct` outbound во Франкфурте и в `xray-client.json`;
  - в профилях `sing-box` добавлены `connect_timeout: "5s"`, `tcp_keep_alive: "2m"`, `tcp_keep_alive_interval: "30s"`;
  - в `/etc/sysctl.d/99-vpn-hardening.conf` добавлены `net.ipv4.tcp_retries2 = 5`, `net.ipv4.tcp_max_syn_backlog = 4096`, `net.ipv4.tcp_syncookies = 1` (обрыв мёртвых TCP-потоков за ~15–25 секунд вместо 15 минут).
- [x] **Добавлена техническая поддержка независимого TLS-сертификата на мосту (`--bridge-sni <domain> --bridge-acme`)** ([script.sh](./script.sh), [cli.py](./app/cli.py), [self_test.py](./app/utils/self_test.py)):
  - запрещено переиспользование `--upstream-domain` при `--bridge-acme`, добавлен контроль TLD и предупреждение в `self-test` при совпадении `bridge_sni == upstream_domain` или наличии `CN=localhost`;
  - во время `--bridge-acme` порт `:80` открывается только на момент выпуска сертификата Let's Encrypt и сразу закрывается обратно (порт `:443` остаётся единственным VPN-портом, Zero-Loop сохраняется).

---

## 3. Оставшиеся риски и чек-лист сопровождения

### Риск №1 `[MITIGATED -> LOW-MEDIUM]`: Общий SNI и `CN=localhost` на `<MOSCOW_BRIDGE_IP>:443`

**Что уже устранено (`<BRIDGE_DOMAIN>`):**  
На `<MOSCOW_BRIDGE_IP>` настроен выделенный поддомен (`DNS Only`), выпущен настоящий сертификат Let's Encrypt (`--bridge-acme`), порт `:80` закрыт обратно, `CN=localhost` при целевом зонде устранён.

**Остаточный нюанс (RCA №7):** `<BRIDGE_DOMAIN>` и `<EXIT_DOMAIN>` делят общий корневой домен `<ROOT_DOMAIN>` (для одного пользователя без массового трафика риск умеренный, но при расширении стоит уйти на отдельный корневой домен).

- [x] **Шаг 1.1:** A-запись (`DNS Only`) указывает на `<MOSCOW_BRIDGE_IP>`. *(На будущее для полной отвязки от `<ROOT_DOMAIN>`: выделить отдельный независимый домен второго уровня.)*
- [x] **Шаг 1.2:** Московский мост переведён на `--bridge-sni <BRIDGE_DOMAIN> --bridge-acme` с выпуском сертификата Let's Encrypt и сохранением Zero-Loop.
- [ ] **Шаг 1.3:** Переимпортировать обновлённую ссылку из `/root/vpn-credentials/links.txt` на планшете (`v2rayNG`) и при настройке в `Throne`.
- [x] **Шаг 1.4:** Подтверждено `openssl s_client` и `curl`: с целевым SNI — `Verify return code: 0 (ok)` (`Let's Encrypt`) и `HTTP/2 200`; без SNI / с чужим SNI — `CN=localhost`; `sudo ./script.sh self-test` проходит `5/5 [PASS]` без `WARN`.

---

### Риск №2 `[HIGH -> CONTROLLED]`: Повторный шторм неудачных реконнектов со стороны клиентов

**Почему опасно (RCA №6):**  
Даже при корректной настройке сервера автореконнекты сломанного клиента накапливают тысячи `TCPTimeouts` на одном IP и провоцируют активное зондирование ТСПУ.

- [x] Серверная и клиентская часть усилена (`tcp_retries2=5`, `sockopt` keepalive, `sing-box` `connect_timeout: 5s`, `uTLS=firefox`).
- [ ] **Шаг 2.1:** Удалить старые/нерабочие подписки и профили из **Throne (ПК)** и проверить подключение по свежему профилю `fp=firefox`.
- [ ] **Шаг 2.2 (постоянное правило):** При любой потере связи на клиенте **не оставлять VPN в цикле автопереподключения** в фоне — сразу отключать туннель и проверять причину одной точечной попыткой.
- [ ] **Шаг 2.3:** Контролировать рост `TCPSynRetrans` / `TCPTimeouts` на обоих серверах пассивным локальным осмотром (без сторонних зондов):
  ```bash
  nstat -az TcpExtEmbryonicRsts TcpExtTCPTimeouts TcpExtTCPSynRetrans
  ss -s
  ```

---

### Риск №3 `[LOW while single-owner -> HIGH if shared]`: Смешение рабочего AI-контура (`<FRANKFURT_AI_EXIT_IP>`) с семейным и массовым трафиком

**Текущий статус (`2026-11-16`):** К каскаду подключены только владелец и 1 пользователь, на Германию напрямую никто не ходит. Пункты ниже обязательны **до** добавления группы пользователей (`5–10+` человек) или семейных устройств:

- [ ] **Шаг 3.1:** Выделить отдельный зарубежный выходной сервер под общих/семейных пользователей (`<FAMILY_EXIT_IP>`, от `2 GB RAM`) с **отдельным независимым доменом** (не `<ROOT_DOMAIN>`).
- [ ] **Шаг 3.2:** На новом зарубежном сервере развернуть чистый exit-узел:
  ```bash
  sudo ./script.sh --domain <ДОМЕН_СЕМЕЙНОГО_ВЫХОДА>
  ```
- [ ] **Шаг 3.3:** Переключить пользовательский мост (или поднять второй RU-мост >= `2 GB RAM` + отдельные UUID каждому пользователю) на новый зарубежный exit-сервер, а `<FRANKFURT_AI_EXIT_IP>` (`<EXIT_DOMAIN>`) оставить **исключительно** для рабочего AI-контура.
- [ ] **Шаг 3.4:** На Android в рабочем AI-профиле исключать фоновые системные сервисы (`Google Play Services`, локационные сервисы) или отключать геолокацию по Wi-Fi/сотовым вышкам.

---

## 4. Журнал проверок

| Дата (UTC) | Сервер / Узел | Что проверено | Результат |
| :--- | :--- | :--- | :--- |
| 2026-11-16 18:05 | `<FRANKFURT_AI_EXIT_IP>`, `<MOSCOW_BRIDGE_IP>` | Деплой `uTLS=firefox` по умолчанию + `self-test` + `sing-box`/`xray` E2E | `5/5 [PASS]` на обоих, E2E `HTTP 200` |
| 2026-11-16 18:08 | `<FRANKFURT_AI_EXIT_IP>` | `openssl s_client` без SNI / чужой SNI / валидный SNI, `iptables mangle`, `nstat` | `CN=localhost + 444` без SNI, `Verify ok` по SNI, `TCPMSS 1360`, `estab 2` |
| 2026-11-16 18:08 | `<MOSCOW_BRIDGE_IP>` | `iptables mangle`, `nstat`, `ss -s` | `TCPMSS 1360`, `estab 2`, выявлены Риски №1–№3 |
| 2026-11-16 18:30 | Оба сервера + код | Anti-storm `tcp_retries2=5`, outbound `sockopt`, `--bridge-acme`, чеклист рисков | Выполнено (`pytest`: 34 passed, `self-test` `5/5 [PASS]`, E2E `HTTP 200`) |
| 2026-11-16 18:49 | `<MOSCOW_BRIDGE_IP>` | Перевод на `<BRIDGE_DOMAIN>` + Let's Encrypt `--bridge-acme`, `openssl`, `ufw`, `sing-box`/`xray` каскад | `Let's Encrypt Verify ok`, `HTTP/2 200`, `444` без SNI, `80/tcp` закрыт, `self-test` `5/5 [PASS]` без `WARN`, каскад `HTTP 200` |
