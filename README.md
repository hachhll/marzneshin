# Zero-Surface VLESS Self-Reality Appliance & Cascade Bridge

Автономный однопользовательский комплекс **VLESS (XTLS-RPRX-Vision + Reality)** с локальным **Nginx Self-Reality / Zero-Loop Gateway**, поддержкой каскадного моста **Москва (`REG.RU`) $\rightarrow$ Франкфурт (`server-ai`)** и пассивной самодиагностикой **Zero-Emission** против детектирования ТСПУ.

> Актуальный контекст инфраструктуры и договорённостей: [HANDOVER_CONTEXT_2026-11-16.md](./HANDOVER_CONTEXT_2026-11-16.md).  
> Чеклист рисков ТСПУ и план их устранения: [RISK_TRACKING_AND_MITIGATION.md](./RISK_TRACKING_AND_MITIGATION.md).

---

## Архитектура безопасности (Anti-TSPU)

1. **Zero-Surface (нулевая веб-поверхность)**:
   - Полностью отсутствуют веб-панель управления, FastAPI, SQLite, `/api/*`, `/sub/*`, `/dashboard/*`.
   - Всё управление выполняется исключительно по SSH через `./script.sh`.
2. **Zero-Loop защита от активного зондирования на мосту в РФ (`--bridge`)**:
   - На московском сервере `dest` в Xray Reality направлен строго на локальный loopback `127.0.0.1:8443` (`marzneshin-nginx` с нейтральным `CN=localhost` и закрытием `444`), а **не** на внешний сайт.
   - Любое активное зондирование `<IP_МОСКВЫ>:443` со стороны ТСПУ замыкается внутри `127.0.0.1` и **не порождает ни одного исходящего пакета** с сетевого интерфейса российского сервера.
3. **Fail-Closed маршрутизация и защита от тайминг-корреляции**:
   - На московском сервере в `outbounds` присутствуют только `proxy` (`vless` Reality к числовому IPv4 `<IP_ФРАНКФУРТА>:443`, `uTLS=firefox`, `flow: "xtls-rprx-vision"`) и `block` (`blackhole`).
   - Выход `direct` (`freedom`) на мосту полностью отсутствует — утечка клиентского трафика или DNS в РФ физически невозможна.
4. **Zero-Emission установка и самодиагностика**:
   - В режиме `--bridge` установщик и `./script.sh self-test` **не отправляют ни одного пакета во внешнюю сеть** (ни `curl` к `ipify`/`youtube`, ни `dig`, ни пробных подключений к Франкфурту). Свой публичный IPv4 мост определяет локально из таблицы маршрутизации ядра (`ip -4 route get 1.1.1.1`).

---

## Пошаговая инструкция развёртывания с нуля (Ubuntu 26)

### Этап 1. Настройка DNS (выполняется первым делом)

Домен нужен **обязательно для выходного сервера за рубежом (`<IP_ФРАНКФУРТА>`)**, а для долгоживущего моста в РФ рекомендуется выделить отдельный независимый домен (`--bridge-sni <ДОМЕН_МОСТА> --bridge-acme`, см. [RISK_TRACKING_AND_MITIGATION.md](./RISK_TRACKING_AND_MITIGATION.md)).

1. Откройте панель управления DNS вашего домена (например, `example.com`).
2. Создайте (или обновите) **прямую `A`-запись**:
   - **Имя (Host)**: выделенный поддомен (например, `edge.example.com`)
   - **Тип**: `A`
   - **Значение (IPv4)**: `<IP_ФРАНКФУРТА>`
   - **TTL**: `300` (5 минут) или `Auto`
   - **Проксирование CDN (Cloudflare Orange Cloud)**: **ОБЯЗАТЕЛЬНО ВЫКЛЮЧЕНО (`DNS Only` / серое облако)**
3. **Записи `AAAA` (IPv6)**: если для этого имени есть `AAAA`-запись — **удалите её**, чтобы выпуск сертификата и маршрутизация шли строго по IPv4.
4. Проверьте со своего рабочего компьютера, что DNS обновился:
   ```bash
   dig +short A edge.example.com
   # Должно вернуть строго: <IP_ФРАНКФУРТА>
   ```

---

### Этап 2. Доставка кода и SSH-ключа на серверы (без `git clone` на сервере в РФ)

Чтобы не генерировать обращения к репозиториям с российского сервера под ТСПУ, код передаётся **напрямую с вашего рабочего компьютера по SSH** (`scp`).

Выполните на своём рабочем компьютере:

```bash
# 1. Упаковываем чистый архив проекта (без .git, .venv и кэшей)
cd /path/to/marzneshin
tar --exclude='.git' --exclude='.venv' --exclude='__pycache__' --exclude='.pytest_cache' \
    -czf /tmp/appliance.tar.gz .

# 2. ОБЯЗАТЕЛЬНО: убедитесь, что ваш публичный SSH-ключ установлен на оба сервера ДО запуска script.sh
# (script.sh перенесёт ключ пользователю stealth и отключит вход под root и по паролю)
ssh-copy-id -i ~/.ssh/id_ed25519.pub root@<IP_ФРАНКФУРТА>
ssh-copy-id -i ~/.ssh/id_ed25519.pub root@<IP_МОСКВЫ>

# 3. Копируем архив во Франкфурт и в Москву
scp /tmp/appliance.tar.gz root@<IP_ФРАНКФУРТА>:/root/appliance.tar.gz
scp /tmp/appliance.tar.gz root@<IP_МОСКВЫ>:/root/appliance.tar.gz
```
*(Если вход по SSH настроен под обычным пользователем с `sudo`, копируйте в `/tmp/appliance.tar.gz`).*

---

### Этап 3. Настройка Выходного узла за рубежом (`<IP_ФРАНКФУРТА>`)

Выходной узел настраивается **первым**, так как он генерирует ключи Reality, которые понадобятся для привязки московского моста.

1. **Подключитесь по SSH к выходному серверу** и перейдите в `root`:
   ```bash
   ssh root@<IP_ФРАНКФУРТА>
   # (если вошли под обычным пользователем: sudo -i)
   ```
2. **Распакуйте код в `/opt/marzneshin`**:
   ```bash
   mkdir -p /opt/marzneshin
   tar -xzf /root/appliance.tar.gz -C /opt/marzneshin
   rm -f /root/appliance.tar.gz
   cd /opt/marzneshin
   chmod +x script.sh scripts/self_test.sh
   ```
3. **Проверьте синхронизацию времени (NTP)** (Reality требует точности системных часов в пределах $\le 30$ с):
   ```bash
   timedatectl set-ntp true
   timedatectl status
   ```
4. **Запустите установщик от `root`**:
   ```bash
   ./script.sh --domain edge.example.com --decoy corporate
   ```
   **Что автоматически сделает `script.sh`:**
   - Проверит репутацию доменной зоны (`.com`), свободные порты `80`/`443` и прямое совпадение `A`-записи `edge.example.com` с `<IP_ФРАНКФУРТА>`.
   - Проверит чистоту IP для Google Antigravity (`GL != RU`), OpenAI (`loc != RU`, `warp=off`) и Anthropic API.
   - Установит Docker и Docker Compose (если они ещё не установлены).
   - Настроит ядро (`BBR`, защиту от SYN-штормов, отключит IPv6, пропишет `TCPMSS = 1360` в `iptables` и `/etc/ufw/before.rules`).
   - Сгенерирует ключи в `/var/lib/marzneshin/state.json`, поднимет контейнеры `marzneshin-xray` и `marzneshin-nginx`, выпустит TLS 1.3 сертификат Let's Encrypt для `edge.example.com` и применит его в Nginx.
5. **Скопируйте готовую команду для настройки московского моста**:
   В самом низу вывода в терминале появится строка:
   ```text
   Moscow Cascade Bridge Setup Command (Run on clean Ubuntu 26 RU server):
     sudo ./script.sh --bridge \
       --upstream-ip <IP_ФРАНКФУРТА> \
       --upstream-domain edge.example.com \
       --upstream-uuid <UUID> \
       --upstream-pbk <PUBKEY> \
       --upstream-sid <SHORT_ID> \
       --upstream-transport xhttp \
       --upstream-xhttp-path <64_HEX_PATH> \
       --bridge-sni <DEDICATED_BRIDGE_DOMAIN> --bridge-acme
   ```
   Скопируйте её целиком.

---

### Этап 4. Настройка Каскадного Моста в Москве (`REG.RU`)

1. **Подключитесь по SSH к московскому серверу** и перейдите в `root`:
   ```bash
   ssh root@<IP_МОСКВЫ>
   # (если вошли под обычным пользователем: sudo -i)
   ```
2. **Распакуйте код в `/opt/marzneshin`**:
   ```bash
   mkdir -p /opt/marzneshin
   tar -xzf /root/appliance.tar.gz -C /opt/marzneshin
   rm -f /root/appliance.tar.gz
   cd /opt/marzneshin
   chmod +x script.sh scripts/self_test.sh
   timedatectl set-ntp true
   ```
3. **Запустите скопированную на Этапе 3 команду `--bridge`**:
   ```bash
   ./script.sh --bridge \
     --upstream-ip <IP_ФРАНКФУРТА> \
     --upstream-domain <ДОМЕН_ФРАНКФУРТА> \
     --upstream-uuid <UUID_ИЗ_ФРАНКФУРТА> \
     --upstream-pbk <PUBKEY_ИЗ_ФРАНКФУРТА> \
     --upstream-sid <SHORT_ID_ИЗ_ФРАНКФУРТА> \
     --bridge-sni <ДОМЕН_ФРАНКФУРТА> \
     --bridge-ip <ПУБЛИЧНЫЙ_IP_МОСКВЫ>
   ```
   > [!IMPORTANT]
   > На облачных серверах за NAT (например, REG.RU, где сетевой интерфейс имеет внутренний серый IP вида `192.168.x.x`) **обязательно указывайте `--bridge-ip <ПУБЛИЧНЫЙ_IP_МОСКВЫ>`**, иначе `script.sh` специально остановит установку и попросит передать публичный IP явно.

   **Что автоматически сделает `script.sh` в режиме `--bridge`:**
   - **Zero-Emission**: не выполнит ни одного исходящего HTTP/DNS/TLS-запроса.
   - Сгенерирует **отдельную собственную пару ключей Reality и UUID** для плеча `Ваш клиент -> Москва`.
   - Настроит `marzneshin-xray` в режиме каскадного моста (`dest: "127.0.0.1:8443"`, `outbounds: ["proxy", "block"]`, по умолчанию через `XHTTP + Reality + xmux` при передаче `--upstream-xhttp-path` либо `Vision`, без `direct`), а `marzneshin-nginx` — только на `127.0.0.1:8443` (порт `80` не слушается).
   - Перенесёт SSH на порт **`22222/tcp`**, создаст пользователя **`stealth`** с `sudo` и вашими SSH-ключами, отключит `root`, пароли и `ssh.socket`, а затем закроет порт `22/tcp`.
   - Откроет в `UFW` **только `22222/tcp` (SSH) и `443/tcp` (VLESS Reality)**.
   - Выведет в терминал QR-код и ссылку `vless://...@<IP_МОСКВЫ>:443?...` и сохранит клиентские конфиги в `/root/vpn-credentials/`.

4. **Подключайтесь к серверу далее под `stealth` на порт `22222` и скачайте профили**:
   На своём рабочем компьютере выполните:
   ```bash
   ssh -p 22222 stealth@<IP_МОСКВЫ> "cd /opt/marzneshin && sudo ./script.sh self-test"
   ssh -p 22222 stealth@<IP_МОСКВЫ> "sudo cp -r /root/vpn-credentials /tmp/vpn-creds && sudo chown -R stealth:stealth /tmp/vpn-creds"
   scp -P 22222 stealth@<IP_МОСКВЫ>:/tmp/vpn-creds/* ~/Downloads/
   ssh -p 22222 stealth@<IP_МОСКВЫ> "rm -rf /tmp/vpn-creds"
   ```
   - `throne-windows11.json` / `throne-windows11-selective.json` — профили для **Throne / Sing-box на Windows 11** (`Full Tunnel` и `Selective` со списками `podkop` / процессов; требования см. в [SINGBOX_CLIENT_REQUIREMENTS.md](./SINGBOX_CLIENT_REQUIREMENTS.md)).
   - `android-singbox.json` / `android-singbox-selective.json` — профили для **официального Sing-box на Android** (`1.14+`/`1.15+`: `Full Tunnel` и `Selective` со списками `podkop` и прямым обходом для РФ-сервисов/SMS/FCM; либо отсканируйте QR-код в `v2rayNG`).
   - `xray-client.json` — клиентский конфиг для Xray.
   - `links.txt` — текстовый файл со ссылкой `vless://`.

---

## Что происходит с доступом к серверам (SSH и UFW)

После успешной установки оба сервера автоматически переводятся в максимально защищённый SSH-режим:

1. **Пользователь и права (`stealth`)**:
   - Создаётся администратор `stealth` в группе `sudo` с беспарольным `sudo` (`/etc/sudoers.d/90-stealth`), куда переносятся публичные ключи из `/root/.ssh/authorized_keys`.
   - Вход по SSH для `root` (`PermitRootLogin no`) и аутентификация по паролю (`PasswordAuthentication no`, `KbdInteractiveAuthentication no`) отключаются.
   - Разрешён вход только пользователю `stealth` (`AllowUsers stealth`).
2. **Порты SSH и защита Ubuntu 24/26 (`ssh.socket`)**:
   - Юнит `ssh.socket` (который в Ubuntu 24/26 по умолчанию биндится на IPv6 и конфликтует с `disable_ipv6`) отключается, SSH переводится на `ssh.service` строго по IPv4 (`AddressFamily inet`) на порту **`22222/tcp`**.
   - Старый порт **`22/tcp`** удаляется из правил UFW только после подтверждения `ss -4 -tln`, что порт `22222` реально слушается.
3. **Открытые внешние порты**:
   - **Москва (`--bridge`)**: только `22222/tcp` (`LIMIT`) и `443/tcp` (`ALLOW`). Порт `80/tcp` полностью закрыт (и UFW, и внутри Nginx).
   - **Франкфурт (`--domain`)**: `22222/tcp` (`LIMIT`), `80/tcp` (`ALLOW`, для ACME Let's Encrypt) и `443/tcp` (`ALLOW`).
   - Все служебные порты (`127.0.0.1:8443` Nginx fallback, `127.0.0.1:10085` Xray API, `127.0.0.1:10086` XHTTP) привязаны строго к `127.0.0.1`.

---

## Команды повседневного управления (по SSH в `/opt/marzneshin`)

| Команда | Описание |
| :--- | :--- |
| `sudo ./script.sh status` | Показать текущую ссылку `vless://`, QR-код, топологию и пути к профилям в `/root/vpn-credentials/` (без перезаписи конфигов и без перезапуска сервисов). |
| `sudo ./script.sh self-test` | **100% пассивная Zero-Emission самодиагностика**: проверяет локальные конфиги Xray/Nginx, отсутствие лишних открытых портов в `/proc/net/tcp*` и отсутствие запрещённых процессов (`wg`, `warp`, `tor`) **без отправки пакетов в сеть**. |
| `sudo ./script.sh self-test --active-probe` | Активная проверка TLS 1.3 и репутации IP для Google/OpenAI/Anthropic *(выполняется только на выходном узле во Франкфурте; на мосту автоматически игнорируется)*. |
| `sudo ./script.sh rotate` | Сгенерировать новый `UUID`, ключи Reality и `shortId`, обновить файлы в `/root/vpn-credentials/` и перезапустить `marzneshin-xray`. |
| `sudo ./script.sh decoy <preset\|url>` | Сменить сайт-прикрытие на выходном узле (`corporate`, `blog`, `coming_soon` или `https://...`). |
| `sudo ./script.sh xhttp <on\|off>` | Включить или выключить резервный транспорт `VLESS + XHTTP + TLS` через Nginx на выходном узле. |
| `sudo ./script.sh bridge-transport <vision\|xhttp> [--path <64-hex>] ...` | Переключить магистраль московского моста между `XHTTP + Reality + xmux` и `Vision` (и при необходимости обновить IP/ключи Exit-узла). |

---

## Совместимость Xray / sing-box и регламент безопасных обновлений

### Почему закреплена версия `Xray v26.6.27` в `Dockerfile` и `uTLS=firefox` по умолчанию
Начиная с `Xray-core v26.9.8+`, протокол `REALITY` на сервере стал принудительно требовать постквантовый гибридный обмен ключами `X25519MLKEM768` в `ClientHello` перед `X25519` (а `v26.7.11+` ужесточил проверку `minClientVer`). Актуальные клиенты на ядре `sing-box` (включая `Throne`, `NekoBox`, `sing-box 1.13.x / 1.14.x` — issue `SagerNet/sing-box#4520`) ещё не формируют этот `KeyShare` по стандарту Xray `v26.9.8+`, поэтому более новые сборки `Xray` отбрасывают их `ClientHello` на fallback.

Дополнительно для обхода фильтрации ТСПУ на российских мобильных и домашних провайдерах (где сигнатура `uTLS=chrome` блокируется/обрывается на входе, тогда как `firefox` проходит с включённым `Hev TUN`) профили клиентов и плечо моста по умолчанию используют `uTLS=firefox`.

### Защита от уязвимости MPTCP (`CVE-2026-98432`)
В более свежем `Xray v26.10.31` был отключён приём MPTCP-сокетов по умолчанию (в Go 1.24+ MPTCP включён по умолчанию, а уязвимость затрагивает MPTCP-листенеры ядра Linux). На `Xray v26.6.27` та же защита обеспечивается на уровне **как ядра ОС, так и Xray**:
1. В `/etc/sysctl.d/99-vpn-hardening.conf` принудительно задано `net.mptcp.enabled = 0`.
2. В `DEFAULT_VLESS_SOCKOPT` (`app/xray/config_builder.py`) явно прописано `"tcpMptcp": false`.
3. Регулярно устанавливайте системные обновления ядра Ubuntu (`apt update && apt upgrade`) на обоих серверах.

### Как безопасно проверять совместимость перед обновлением версий
Перед сменой `XRAY_VERSION` в [Dockerfile](./Dockerfile) или зависимостей в [requirements.txt](./requirements.txt) прогоните полный локальный набор автотестов на **`127.0.0.1`** (он не отправляет пакеты к рабочим серверам):

```bash
.venv/bin/python -m pytest tests/ -v
```

Ключевые зафиксированные проверки:
- [test_cascade_e2e.py](./tests/test_cascade_e2e.py) — пересобирает образ из `Dockerfile` и в изолированной локальной цепочке (`sing-box -> Bridge -> Exit + Nginx`) проверяет реальный Reality-хендшейк (`hs.c.isHandshakeComplete.Load(): true`). Если новая версия `Xray` несовместима с `sing-box`, тест упадёт до выкладки на серверы.
- [test_client_profiles.py](./tests/test_client_profiles.py) — проверяет инварианты генерации всех клиентских JSON (`Full Tunnel` и `Selective` для Windows 11 Throne `1.13+` и Android `sing-box 1.14+/1.15+`), правила `podkop`, блокировку телеметрии/IPv6/QUIC/STUN и отсутствие устаревших полей (`stack`, `store_rdrc`).
- [test_xray_config.py](./tests/test_xray_config.py) — проверяет инварианты моста (`AsIs` без утечки DNS в РФ, `Zero-Loop`, `tcpMptcp: false`, отсутствие `freedom`).
