# Требования к клиентским настройкам `sing-box` (Android SFA и Windows 11 Throne)

Этот документ фиксирует обязательные технические и анти-цензурные требования к JSON-профилям `sing-box`, генерируемым модулем [`app/client/profile_generator.py`](app/client/profile_generator.py).

---

## 1. Поддерживаемые клиенты и версии ядра

| Платформа | Клиент | Целевая версия ядра | Файлы в `/root/vpn-credentials/` |
| :--- | :--- | :--- | :--- |
| **Android** | Официальный **`sing-box`** (`io.nekohasekai.sfa`) | `1.14+` / `1.15+` | `android-singbox.json` (Full)<br>`android-singbox-selective.json` (Selective) |
| **Windows 11** | **`Throne`** (`throneproj/Throne`) | `1.13+` | `throne-windows11.json` (Full)<br>`throne-windows11-selective.json` (Selective) |

---

## 2. Обязательные требования безопасности (TSPU, утечки, антибан AI/Google)

1. **Единый узел входа (Cascade Bridge) и отпечаток uTLS:**
   - В режиме каскада клиент подключается к российскому мосту (`VLESS + Reality + Vision`, `flow: "xtls-rprx-vision"`, `packet_encoding: "xudp"`), а мост мультиплексирует соединения к зарубежному Exit-узлу через `XHTTP + Reality + xmux`.
   - Обязательный `tls.utls.fingerprint`: **`"firefox"`** (устойчивый отпечаток на ТСПУ).
   - `connect_timeout: "5s"`, `tcp_keep_alive: "2m"`, `tcp_keep_alive_interval: "30s"`.

2. **Запрет фонового автопинга (`urltest`):**
   - В `outbounds` допускается только ручной **`selector`** (`interrupt_exist_connections: true`).
   - Тип `urltest` **строго запрещён**, чтобы клиент не генерировал фоновые периодические пробы/рукопожатия.

3. **Блокировка утечек и телеметрии (`action: "reject"` выше правил `proxy`):**
   - **IPv6:** `{"ip_cidr": ["::/0"], "action": "reject"}` (при отключённом IPv6 egress), `dns.strategy: "ipv4_only"`.
   - **QUIC и WebRTC/STUN для проксируемого трафика:** `network: "udp"`, `port: [443, 3478, 19302]` $\rightarrow$ `reject` (отключает QUIC в пользу TCP/H2 и блокирует WebRTC IP leak; при этом высокие UDP-порты голосовых звонков Discord/Telegram остаются доступными через `xudp`).
   - **Телеметрия Android и Firebase:**
     - `location.googleapis.com` (критично против привязки RU Wi-Fi BSSID к DE-аккаунтам Google/AI)
     - `connectivitycheck.android.com`, `connectivitycheck.gstatic.com`
     - `firebaselogging.googleapis.com`, `firebaselogging-pa.googleapis.com`
     - `app-measurement.com`, `firebase-settings.crashlytics.com`
   - **Обязательное исключение из блокировки:** `gvt1.com` и `gvt2.com` **нельзя** блокировать (нужны для обновлений Google/IDE).

4. **Чистота DNS (никакого `223.5.5.5`):**
   - Удалённый DNS только через прокси: `1.1.1.1` и `8.8.8.8` (`type: "udp"`, `detour: "proxy"`).
   - Блокировка `query_type: "HTTPS"` (SVCB/HTTP3 hints) в `dns.rules`, чтобы браузеры не уходили в QUIC.
   - В режиме **Full Tunnel**: все DNS-запросы идут только в `dns-remote`, `dns-local` отсутствует.
   - В режиме **Selective (раздельное туннелирование)**:
     - Для проксируемых приложений, сервисов и доменов — `dns-remote` (`detour: "proxy"`).
     - Для `.ru`, `.su`, `.xn--p1ai` (`.рф`), локальных сетей и прямого трафика — `{"type": "local", "tag": "dns-local"}` (`dns.final: "dns-local"`, `route.default_domain_resolver: "dns-local"`).

---

## 3. Матрица маршрутизации: что идёт через VPN (`proxy`), что напрямую (`direct`) и что блокируется (`reject`)

В режиме **`Selective`** правило по умолчанию — **`route.final: "direct"`** и **`dns.final: "dns-local"`** (весь трафик идёт напрямую мимо VPN, кроме явно перечисленных ниже приложений, сервисов и списков).

### 3.1. Идёт строго ЧЕРЕЗ VPN (`proxy` + `dns-remote`)

1. **Android — приложения (`package_name`, полный трафик приложения идёт в VPN):**
   - **Рабочие браузеры (изолированные):** `org.mozilla.firefox` (Firefox), `com.brave.browser` (Brave)
   - **AI-клиенты:** `com.openai.chatgpt` (ChatGPT), `com.anthropic.claude` (Claude), `com.google.android.apps.bard` (Google Gemini)
   - **YouTube:** `com.google.android.youtube` (YouTube), `com.google.android.apps.youtube.music` (YouTube Music)
   - **Мессенджеры:** `com.discord` (Discord), `org.telegram.messenger` (Telegram), `org.telegram.messenger.web` (Telegram Web/APK), `org.thunderdog.challegram` (Telegram X)
   - **Соцсети:** `com.instagram.android` (Instagram), `com.facebook.katana` (Facebook), `com.twitter.android` (X / Twitter), `com.linkedin.android` (LinkedIn)

2. **Windows 11 — процессы (`process_name`, полный трафик процесса идёт в VPN):**
   - **AI IDE и клиенты:** `Antigravity.exe`, `Antigravity IDE.exe`, `language_server_windows_x64.exe`, `agy.exe`, `Cursor.exe`, `Windsurf.exe`, `Claude.exe`, `ChatGPT.exe`
   - **Мессенджеры:** `Discord.exe`, `Telegram.exe`
   - **Рабочие браузеры (изолированные):** `firefox.exe` (Firefox), `brave.exe` (Brave)
   - **Явный локальный прокси:** весь трафик через входящий `mixed-in` (`127.0.0.1:2080`)

3. **Списки `podkop` (`itdoginfo/allow-domains`, `.srs`, обновление `1d`):**
   - В `route.rule_set` подключены все 7 списков: `discord`, `google_ai`, `google_play`, `telegram`, `meta`, `twitter`, `russia_inside`.
   - В `dns.rules` подключены только чисто доменные наборы (`google_ai`, `google_play`, `russia_inside`), а наборы с `ip_cidr`/`port_range` (`discord`, `telegram`, `meta`, `twitter`) применяются только в `route.rules`, тогда как их домены продублированы в `SELECTIVE_VPN_DOMAIN_SUFFIXES`.

4. **Доменные группы (`SELECTIVE_VPN_DOMAIN_SUFFIXES`) и подсети:**
   - **Google / Antigravity / NotebookLM / YouTube:** `google.com`, `google.ru`, `googleapis.com`, `googleusercontent.com`, `googlevideo.com`, `gstatic.com`, `gvt1.com`, `gvt2.com`, `ggpht.com`, `ytimg.com`, `youtube.com`, `youtu.be`, `withgoogle.com`, `deepmind.google`, `antigravity.google`, `antigravityide.net`, `notebooklm.google`, `notebooklm-enterprise.google`, `gemini.google`, `labs.google`, `google.dev`, `google.ai`, `ai.google`, `ai.dev`, `g.co`, `goo.gl`, `firebaseapp.com`, `gmail.com`, `recaptcha.net`
   - **OpenAI / Anthropic / AI IDE:** `openai.com`, `chatgpt.com`, `oaistatic.com`, `oaiusercontent.com`, `sora.com`, `anthropic.com`, `claude.ai`, `claude.com`, `claude.usercontent.com`, `claudeusercontent.com`, `claudemcpclient.com`, `cursor.com`, `cursor.sh`, `cursor-cdn.com`, `windsurf.com`, `codeium.com`, `perplexity.ai`, `huggingface.co`
   - **Databricks / Okta / Auth0:** `databricks.com`, `databricks.com.cn`, `databricks.cfg`, `databricks-labs.com`, `databricks-prod-cloudfront.com`, `azuredatabricks.net`, `databricksusercontent.com`, `evently.com`, `databriks.com`, `databriks.net`, `okta.com`, `oktacdn.com`, `oktapreview.com`, `okta-emea.com`, `auth0.com`, `auth0.net`
   - **Netflix / Streaming:** `netflix.com`, `netflix.net`, `nflximg.net`, `nflxvideo.net`, `nflxso.net`, `nflxext.com`, `fast.com`
   - **Discord / Telegram / Соцсети (дополнительно к `.srs`):** домены `discord*`, `telegram*`, `t.me`, `tdesktop.com`, `telesco.pe`, `telegra.ph`, `tg.dev`, `instagram.com`, `cdninstagram.com`, `facebook.com`, `fbcdn.net`, `fbsbx.com`, `fb.com`, `meta.com`, `threads.net`, `x.com`, `twitter.com`, `twimg.com`, `t.co`, `linkedin.com`, `licdn.com`
   - **Официальные DC-подсети Telegram (`TELEGRAM_DC_CIDRS`):** `149.154.160.0/20`, `91.105.192.0/23`, `91.108.4.0/22`, `91.108.8.0/22`, `91.108.12.0/22`, `91.108.16.0/22`, `91.108.20.0/22`, `91.108.56.0/22`, `185.76.151.0/24`

### 3.2. Идёт строго НАПРЯМУЮ МИМО VPN (`direct` + `dns-local`)

1. **Российские банки, сервисы и повседневные браузеры (`route.final: "direct"`):**
   - Банки (`ru.sberbank.*`, Т-Банк, Альфа и др.), Госуслуги, маркетплейсы, Todoist и прочие не указанные в п. 3.1 приложения.
   - Повседневные браузеры (**Chrome**, **Edge**, **Яндекс Браузер**, встроенные браузеры) для российских сайтов (`.ru`, `.su`, `.рф` / `.xn--p1ai` резолвятся через `dns-local`).
2. **Принудительные прямые исключения Android (выше общих правил `googleapis.com` / `podkop`):**
   - Пакеты: `com.google.android.apps.messaging` (SMS/RCS), `com.google.android.dialer` (Звонки).
   - Фоновые сервисные домены: `mobileconfiguration-pa.googleapis.com`, `reminders-pa.googleapis.com`, `mtalk.google.com`, `alt1..8-mtalk.google.com` (Android FCM Push).
   - *Важно:* сам пакет `com.google.android.gms` целиком в `direct` **не** выводится, чтобы не ломать OAuth-авторизацию Google / Play Store / Gemini.
3. **Локальные сети (`ip_is_private: true`):** `127.0.0.0/8`, `192.168.0.0/16`, `10.0.0.0/8`, `172.16.0.0/12` (LAN, роутер, локальный IPC в IDE).

### 3.3. Блокируется (`action: "reject"`, выше правил `proxy`)

- **Телеметрия и геолокация:** `location.googleapis.com`, `connectivitycheck.android.com`, `connectivitycheck.gstatic.com`, `firebaselogging.googleapis.com`, `firebaselogging-pa.googleapis.com`, `app-measurement.com`, `firebase-settings.crashlytics.com`.
- **Утечки IPv6:** `::/0`.
- **QUIC / WebRTC / STUN на проксируемом трафике:** `UDP 443, 3478, 19302` + `query_type: "HTTPS"` в `dns.rules`.

---

## 4. Совместимость со схемой `sing-box` `1.13` / `1.14` / `1.15` (без предупреждений `migration/`)

1. Не использовать устаревший параметр `tun.stack` (deprecated in `1.15.0`).
2. Не использовать `experimental.cache_file.store_rdrc` (deprecated in `1.14.0`): на Android `1.14+` используется `{"enabled": true, "store_dns": true}`, на Windows `Throne 1.13` — `{"enabled": true}`.
3. Загрузка удалённых `.srs` rule-set:
   - На **Android (`1.14+` / `1.15+`)**: использовать top-level `http_clients: [{"tag": "proxy-http", "detour": "proxy"}]`, `route.default_http_client: "proxy-http"` и `"http_client": "proxy-http"` (без устаревшего `download_detour`).
   - На **Windows (`Throne 1.13`)**: использовать `"download_detour": "proxy"` до обновления встроенного ядра Throne на `1.14+`.
4. На **Android** в `route` указывать `"override_android_vpn": true` (не добавлять его в Windows-конфиг).
5. Во всех правилах `dns.rules` и `route.rules` явно задавать `"action"` (`"route"`, `"reject"`, `"sniff"`, `"hijack-dns"`).
