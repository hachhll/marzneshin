import hashlib
import secrets
from enum import Enum
from typing import Final


class DecoyMode(str, Enum):
    preset = "preset"
    custom_html = "custom_html"
    reverse_proxy = "reverse_proxy"


DECOY_STYLE_CSS: Final[str] = """/* ArmenyTravel Static Portal Stylesheet */
:root {
  --bg: #faf8f5;
  --surface: #ffffff;
  --text: #1c1917;
  --muted: #57534e;
  --accent: #9a3412;
  --accent-light: #ffedd5;
  --border: #e7e5e4;
}
* { box-sizing: border-box; }
body {
  font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  margin: 0;
  color: var(--text);
  background: var(--bg);
  line-height: 1.65;
}
header {
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  position: sticky;
  top: 0;
  z-index: 10;
}
.nav-wrap {
  max-width: 1120px;
  margin: 0 auto;
  padding: 1rem 1.5rem;
  display: flex;
  flex-wrap: wrap;
  justify-content: space-between;
  align-items: center;
  gap: 1rem;
}
.brand {
  font-weight: 800;
  font-size: 1.25rem;
  color: var(--accent);
  text-decoration: none;
  letter-spacing: -0.02em;
}
nav a {
  margin-left: 1.25rem;
  color: var(--muted);
  text-decoration: none;
  font-size: 0.95rem;
  font-weight: 500;
}
nav a:hover { color: var(--accent); }
.lang-switch a {
  display: inline-block;
  padding: 0.2rem 0.55rem;
  border: 1px solid var(--border);
  border-radius: 0.375rem;
  font-size: 0.8rem;
  margin-left: 0.35rem;
  color: var(--text);
  text-decoration: none;
}
main { max-width: 1120px; margin: 0 auto; padding: 3rem 1.5rem; }
.hero {
  background: linear-gradient(135deg, #fff7ed 0%, #ffffff 100%);
  border: 1px solid var(--border);
  border-radius: 1rem;
  padding: 3rem 2rem;
  margin-bottom: 2.5rem;
}
.badge {
  display: inline-block;
  background: var(--accent-light);
  color: var(--accent);
  font-size: 0.8rem;
  font-weight: 600;
  padding: 0.25rem 0.75rem;
  border-radius: 999px;
  margin-bottom: 1rem;
}
.hero h1 {
  font-size: 2.35rem;
  line-height: 1.2;
  margin: 0 0 1rem;
  color: var(--text);
}
.hero p { font-size: 1.1rem; color: var(--muted); max-width: 760px; margin: 0 0 1.25rem; }
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(290px, 1fr));
  gap: 1.5rem;
  margin: 2rem 0;
}
.tile {
  border: 1px solid var(--border);
  border-radius: 0.85rem;
  padding: 1.5rem;
  background: var(--surface);
  box-shadow: 0 1px 2px rgba(0,0,0,0.03);
}
.tile img {
  width: 100%;
  height: 160px;
  object-fit: cover;
  border-radius: 0.5rem;
  margin-bottom: 1rem;
  background: #f5f5f4;
}
.tile h3 { margin: 0 0 0.5rem; font-size: 1.15rem; color: var(--text); }
.tile p { margin: 0 0 0.75rem; color: var(--muted); font-size: 0.95rem; }
.meta { font-size: 0.82rem; color: var(--accent); font-weight: 600; }
.lang-block {
  border-top: 1px solid var(--border);
  padding-top: 2rem;
  margin-top: 2.5rem;
}
.table-wrap { overflow-x: auto; margin-top: 1.5rem; }
table { width: 100%; border-collapse: collapse; background: var(--surface); border-radius: 0.5rem; }
th, td { text-align: left; padding: 0.85rem 1rem; border-bottom: 1px solid var(--border); font-size: 0.92rem; }
th { background: #f5f5f4; font-weight: 600; }
footer {
  border-top: 1px solid var(--border);
  background: var(--surface);
  text-align: center;
  padding: 2.5rem 1.5rem;
  color: var(--muted);
  font-size: 0.85rem;
  margin-top: 3rem;
}
"""

DECOY_APP_JS: Final[str] = """/* ArmenyTravel Interactive Language & Season Filter */
(function () {
  document.addEventListener("DOMContentLoaded", function () {
    var buttons = document.querySelectorAll("[data-lang-btn]");
    buttons.forEach(function (btn) {
      btn.addEventListener("click", function (e) {
        var target = btn.getAttribute("data-lang-btn");
        var el = document.getElementById("section-" + target);
        if (el) {
          e.preventDefault();
          el.scrollIntoView({ behavior: "smooth" });
        }
      });
    });
  });
})();
"""

SVG_ARARAT: Final[str] = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 600 320">
  <rect width="600" height="320" fill="#ffedd5"/>
  <circle cx="480" cy="70" r="38" fill="#fb923c" opacity="0.45"/>
  <polygon points="40,320 230,90 410,320" fill="#78716c"/>
  <polygon points="185,148 230,90 275,148 250,156 230,138 210,156" fill="#fafaf9"/>
  <polygon points="270,320 410,145 555,320" fill="#57534e"/>
  <polygon points="382,180 410,145 438,180" fill="#f5f5f4"/>
  <rect y="275" width="600" height="45" fill="#9a3412" opacity="0.85"/>
</svg>
"""

SVG_SEVAN: Final[str] = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 600 320">
  <rect width="600" height="320" fill="#e0f2fe"/>
  <polygon points="0,210 150,110 320,210" fill="#64748b"/>
  <polygon points="240,210 430,95 600,210" fill="#475569"/>
  <rect y="205" width="600" height="115" fill="#0284c7"/>
  <path d="M80 245 Q180 235 280 245 T480 245" stroke="#bae6fd" stroke-width="3" fill="none"/>
</svg>
"""

SVG_TATEV: Final[str] = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 600 320">
  <rect width="600" height="320" fill="#fef3c7"/>
  <polygon points="0,320 190,80 390,320" fill="#78350f" opacity="0.75"/>
  <polygon points="230,320 440,65 600,320" fill="#92400e" opacity="0.85"/>
  <rect x="415" y="40" width="50" height="35" fill="#d97706"/>
  <polygon points="410,40 440,12 470,40" fill="#78350f"/>
</svg>
"""

DECOY_404_HTML: Final[str] = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>404 Not Found — ArmenyTravel</title>
  <link rel="stylesheet" href="/assets/style.css">
</head>
<body>
  <main style="text-align:center;padding:5rem 1.5rem;">
    <h1>404</h1>
    <p>The requested page or itinerary could not be found. / Страница не найдена. / Seite nicht gefunden.</p>
    <p><a href="/">Return to Home / На главную / Zur Startseite</a></p>
  </main>
</body>
</html>
"""

DECOY_PRESETS: Final[dict[str, str]] = {
    "corporate": """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ArmenyTravel — Curated Expeditions &amp; Cultural Tours in Armenia (EN / RU / DE)</title>
  <meta name="description" content="Guided cultural, culinary, and alpine tours across Armenia: Yerevan, Lake Sevan, Dilijan, Garni, Geghard, and Tatev. Авторские туры в Армению. Kultur- und Bergreisen in Armenien.">
  <link rel="icon" href="/favicon.ico">
  <link rel="stylesheet" href="/assets/style.css">
  <script type="application/ld+json">
  {
    "@context": "https://schema.org",
    "@type": "TravelAgency",
    "name": "ArmenyTravel",
    "description": "Curated Cultural, Culinary & Mountain Expeditions across Armenia (EN/RU/DE)",
    "areaServed": ["AM", "DE", "RU", "EU"],
    "availableLanguage": ["English", "Russian", "German"]
  }
  </script>
</head>
<body>
  <header>
    <div class="nav-wrap">
      <a class="brand" href="/">ArmenyTravel</a>
      <nav>
        <a href="/tours.html">Itineraries / Маршруты</a>
        <a href="/guide.html">Travel Guide / Путеводитель</a>
        <a href="#section-ru" data-lang-btn="ru">Русский</a>
        <a href="#section-de" data-lang-btn="de">Deutsch</a>
      </nav>
      <div class="lang-switch">
        <a href="/">EN</a>
        <a href="/ru/">RU</a>
        <a href="/de/">DE</a>
      </div>
    </div>
  </header>
  <main>
    <section class="hero" id="section-en">
      <span class="badge">2026 Season Open &bull; Yerevan &bull; Sevan &bull; Syunik</span>
      <h1>Discover the Highlands &amp; Ancient Monasteries of Armenia</h1>
      <p>Small-group cultural journeys, alpine hikes, and vineyard routes through the Caucasus. Tailor-made itineraries with local historians and mountain guides in English, Russian, and German.</p>
      <p><a href="/tours.html">Explore 2026 Departure Dates &rarr;</a> &nbsp;|&nbsp; <a href="/guide.html">Read Practical Travel Guide &rarr;</a></p>
    </section>

    <section class="grid">
      <article class="tile">
        <img src="/assets/ararat.svg" alt="Mount Ararat and Khor Virap Panorama">
        <div class="meta">7 DAYS &bull; CLASSIC HERITAGE</div>
        <h3>Yerevan, Khor Virap &amp; Geghard</h3>
        <p>Explore pink-tuff architecture in Yerevan, pagan temple of Garni, UNESCO cliff-carved chambers of Geghard, and Areni wine caves.</p>
      </article>
      <article class="tile">
        <img src="/assets/sevan.svg" alt="Lake Sevan and Dilijan Alpine Forests">
        <div class="meta">5 DAYS &bull; ALPINE &amp; NATURE</div>
        <h3>Lake Sevan &amp; Dilijan National Park</h3>
        <p>High-altitude emerald waters of Lake Sevan (1,900m), Sevanavank peninsula, and forested trails around Haghartsin and Goshavank.</p>
      </article>
      <article class="tile">
        <img src="/assets/tatev.svg" alt="Tatev Monastery and Vorotan Canyon">
        <div class="meta">6 DAYS &bull; SOUTHERN EXPEDITION</div>
        <h3>Syunik Gorge &amp; Wings of Tatev</h3>
        <p>Cross the Vardenyats Pass (Selim Caravanserai) to Noravank red cliffs, Khndzoresk cave village, and the 9th-century Tatev fortress.</p>
      </article>
    </section>

    <section class="lang-block" id="section-ru">
      <span class="badge">РУССКАЯ ВЕРСИЯ &bull; АВТОРСКИЕ ТУРЫ В АРМЕНИЮ</span>
      <h2>Путешествия по Армении: от древнего Еревана до ущелий Сюника</h2>
      <p>Мы организуем индивидуальные и камерные групповые экспедиции по всей территории Армении: гастрономические маршруты по винодельням Вайоц-Дзора, треккинг в Дилижанском национальном парке, поездки на озеро Севан и канатную дорогу «Крылья Татева».</p>
      <div class="grid">
        <div class="tile">
          <h3>Безвизовый въезд и прямой перелёт</h3>
          <p>Комфортный трансфер из аэропорта Звартноц (EVN), проверенные бутик-отели в центре Еревана и горные эко-лоджи в Дилижане и Горисе.</p>
          <p><a href="/ru/">Перейти в раздел на русском языке &rarr;</a></p>
        </div>
        <div class="tile">
          <h3>Гастрономия и виноделие Арени</h3>
          <p>Дегустации автохтонных сортов Воскеат и Арени Черный, мастер-классы по выпечке традиционного лаваша в тонире и обеды в семейных усадьбах.</p>
          <p><a href="/tours.html">Смотреть расписание групп &rarr;</a></p>
        </div>
      </div>
    </section>

    <section class="lang-block" id="section-de">
      <span class="badge">DEUTSCHE AUSGABE &bull; KULTUR- UND BERGREISEN</span>
      <h2>Armenien Entdecken: Klöster, Hochgebirge &amp; Weinkultur im Südkaukasus</h2>
      <p>Erleben Sie eines der ältesten christlichen Kulturländer der Welt in kleinen Reisegruppen oder auf individuellen Privatreisen ab Frankfurt, München, Berlin und Wien. Deutschsprachige Studienreiseleitung auf allen Routen.</p>
      <div class="grid">
        <div class="tile">
          <h3>UNESCO-Welterbe &amp; Felsenklöster</h3>
          <p>Besuch der Kathedrale von Etschmiadsin, des Höhlenklosters Geghard, des hellenistischen Tempels von Garni sowie der Klöster Haghpat und Sanahin.</p>
          <p><a href="/de/">Zur deutschen Übersichtsseite &rarr;</a></p>
        </div>
        <div class="tile">
          <h3>Wandern am Sewansee &amp; Aragaz</h3>
          <p>Panorama-Wanderungen durch die alpine Flora des Kaukasus, Übernachtungen in ausgewählten Gasthäusern und Begegnungen mit lokalen Winzern.</p>
          <p><a href="/guide.html">Reiseinformationen &amp; Beste Reisezeit &rarr;</a></p>
        </div>
      </div>
    </section>
  </main>
  <footer>
    &copy; 2026 ArmenyTravel Cultural Expeditions &bull; Yerevan / Frankfurt / Moscow &bull; Edge Delivery by Nordic Systems GmbH
  </footer>
  <script src="/assets/app.js" defer></script>
</body>
</html>
""",
    "blog": """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ArmenyTravel Journal — Highland Notes &amp; Routes</title>
  <link rel="stylesheet" href="/assets/style.css">
</head>
<body>
  <main>
    <h1>ArmenyTravel Field Notes</h1>
    <p>Essays on Caucasian mountain passes, ancient monasteries, and regional travel across Armenia.</p>
    <p><a href="/">Back to main portal</a></p>
  </main>
</body>
</html>
""",
    "coming_soon": """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Scheduled Seasonal Update — ArmenyTravel</title>
  <link rel="stylesheet" href="/assets/style.css">
</head>
<body>
  <main>
    <h1>Seasonal Booking Portal Update</h1>
    <p>Our 2026 Armenia expedition schedules are being updated. Please check back shortly.</p>
  </main>
</body>
</html>
""",
}

DECOY_RU_HTML: Final[str] = """<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ArmenyTravel — Авторские туры и путешествия по Армении 2026</title>
  <meta name="description" content="Экскурсионные, гастрономические и горные туры по Армении: Ереван, Севан, Дилижан, Гарни, Гегард, Хор Вирап и Татев.">
  <link rel="stylesheet" href="/assets/style.css">
</head>
<body>
  <header>
    <div class="nav-wrap">
      <a class="brand" href="/">ArmenyTravel</a>
      <nav>
        <a href="/">Главная (EN/RU/DE)</a>
        <a href="/tours.html">Маршруты</a>
        <a href="/guide.html">Путеводитель</a>
        <a href="/de/">Deutsch</a>
      </nav>
    </div>
  </header>
  <main>
    <section class="hero">
      <span class="badge">СЕЗОН 2026 &bull; ПРЯМЫЕ ВЫЛЕТЫ ИЗ МОСКВЫ И РЕГИОНОВ</span>
      <h1>Авторские путешествия по Армении в мини-группах</h1>
      <p>Откройте для себя розовые туфовые кварталы Еревана, высокогорное озеро Севан, древние монастыри Татев и Нораванк, а также винодельни долины Арени.</p>
    </section>
    <div class="grid">
      <div class="tile">
        <img src="/assets/ararat.svg" alt="Арарат и Хор Вирап">
        <h3>Классическая Армения за 7 дней</h3>
        <p>Ереван, Матенадаран, Гарни, монастырь Гегард, Хор Вирап с видом на Арарат, Эчмиадзин и дегустации в Арени.</p>
      </div>
      <div class="tile">
        <img src="/assets/sevan.svg" alt="Озеро Севан и Дилижан">
        <h3>Севан, Дилижан и северные монастыри</h3>
        <p>Полуостров Севанаванк, тропы Дилижанского заповедника, монастыри Агарцин, Гошаванк, Ахпат и Санаин.</p>
      </div>
      <div class="tile">
        <img src="/assets/tatev.svg" alt="Татев и Сюник">
        <h3>Экспедиция в Сюник и Татев</h3>
        <p>Селимский перевал, караван-сарай Орбелянов, Караундж, пещерный город Хндзореск и канатная дорога «Крылья Татева».</p>
      </div>
    </div>
  </main>
  <footer>&copy; 2026 ArmenyTravel &bull; Москва / Ереван / Франкфурт</footer>
</body>
</html>
"""

DECOY_DE_HTML: Final[str] = """<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ArmenyTravel — Kultur-, Wein- und Bergreisen in Armenien 2026</title>
  <meta name="description" content="Geführte Rundreisen und Wanderungen in Armenien: Jerewan, Sewansee, Dilidschan, Garni, Geghard und Kloster Tatew.">
  <link rel="stylesheet" href="/assets/style.css">
</head>
<body>
  <header>
    <div class="nav-wrap">
      <a class="brand" href="/">ArmenyTravel</a>
      <nav>
        <a href="/">Startseite (EN/RU/DE)</a>
        <a href="/tours.html">Reiserouten</a>
        <a href="/guide.html">Reiseführer</a>
        <a href="/ru/">Русский</a>
      </nav>
    </div>
  </header>
  <main>
    <section class="hero">
      <span class="badge">REISESAISON 2026 &bull; KLEINGRUPPEN &amp; PRIVATREISEN</span>
      <h1>Kultur- und Naturreisen durch das armenische Hochland</h1>
      <p>Individuell geplante Rundreisen zwischen dem biblischen Berg Ararat, dem tiefblauen Sewansee und den Schluchten von Sjunik mit erfahrenen deutschsprachigen Reiseleitern.</p>
    </section>
    <div class="grid">
      <div class="tile">
        <img src="/assets/ararat.svg" alt="Ararat und Chor Wirap">
        <h3>Höhepunkte Armeniens (8 Tage)</h3>
        <p>Jerewan, Handschrifteninstitut Matenadaran, Tempel von Garni, Felsenkloster Geghard, Chor Wirap und Weinkellereien in Areni.</p>
      </div>
      <div class="tile">
        <img src="/assets/sevan.svg" alt="Sewansee und Dilidschan">
        <h3>Sewansee &amp; Grüne Wälder von Dilidschan</h3>
        <p>Kloster Sewanawank, Wanderungen im Nationalpark Dilidschan und UNESCO-Welterbeklöster Haghpat und Sanahin im Debed-Canyon.</p>
      </div>
      <div class="tile">
        <img src="/assets/tatev.svg" alt="Kloster Tatew">
        <h3>Der Wilde Süden &amp; Flügel von Tatew</h3>
        <p>Fahrt über den Wardenjaz-Pass zur Orbelian-Karawanserei, Schlucht von Norawank, Goris und Seilbahn zum Kloster Tatew.</p>
      </div>
    </div>
  </main>
  <footer>&copy; 2026 ArmenyTravel &bull; Frankfurt am Main / Jerewan</footer>
</body>
</html>
"""

DECOY_TOURS_HTML: Final[str] = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>2026 Itineraries &amp; Departures — ArmenyTravel (EN / RU / DE)</title>
  <link rel="stylesheet" href="/assets/style.css">
</head>
<body>
  <header>
    <div class="nav-wrap">
      <a class="brand" href="/">ArmenyTravel</a>
      <nav>
        <a href="/">Home</a>
        <a href="/guide.html">Travel Guide</a>
        <a href="/ru/">RU</a>
        <a href="/de/">DE</a>
      </nav>
    </div>
  </header>
  <main>
    <h1>2026 Armenia Tour Calendar &amp; Route Specifications</h1>
    <p>All departures include airport transfers (EVN), boutique accommodation, mountain transport, and trilingual guiding (English / Russian / German).</p>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Route Code</th>
            <th>Itinerary / Маршрут / Reiseroute</th>
            <th>Duration</th>
            <th>Season</th>
            <th>Languages</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>AM-101</td>
            <td>Classic Heritage: Yerevan, Garni, Geghard, Khor Virap &amp; Noravank</td>
            <td>7 Days / 6 Nights</td>
            <td>April – November</td>
            <td>EN / RU / DE</td>
          </tr>
          <tr>
            <td>AM-204</td>
            <td>Alpine Trails: Lake Sevan, Dilijan National Park &amp; Lori Canyon</td>
            <td>5 Days / 4 Nights</td>
            <td>May – October</td>
            <td>EN / RU / DE</td>
          </tr>
          <tr>
            <td>AM-309</td>
            <td>Southern Syunik Expedition: Vardenyats Pass, Goris &amp; Tatev</td>
            <td>6 Days / 5 Nights</td>
            <td>April – November</td>
            <td>EN / RU / DE</td>
          </tr>
        </tbody>
      </table>
    </div>
  </main>
  <footer>&copy; 2026 ArmenyTravel</footer>
</body>
</html>
"""

DECOY_GUIDE_HTML: Final[str] = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Armenia Travel Guide — Seasons, Entry &amp; Highlands | ArmenyTravel</title>
  <link rel="stylesheet" href="/assets/style.css">
</head>
<body>
  <header>
    <div class="nav-wrap">
      <a class="brand" href="/">ArmenyTravel</a>
      <nav>
        <a href="/">Home</a>
        <a href="/tours.html">Itineraries</a>
        <a href="/ru/">RU</a>
        <a href="/de/">DE</a>
      </nav>
    </div>
  </header>
  <main>
    <h1>Practical Guide to Traveling in Armenia (EN / RU / DE)</h1>
    <div class="grid">
      <div class="tile">
        <h3>Best Time to Visit</h3>
        <p>Spring (April–June) brings blooming mountain valleys, while Autumn (September–November) offers warm golden weather and grape harvests in Areni.</p>
      </div>
      <div class="tile">
        <h3>Памятка путешественнику (RU)</h3>
        <p>Для граждан РФ и стран ЕС действует безвизовый въезд. В Ереване и регионах развита инфраструктура гостевых домов, виноделен и горных маршрутов.</p>
      </div>
      <div class="tile">
        <h3>Reisehinweise (DE)</h3>
        <p>Visumfreie Einreise für EU-Bürger bis zu 180 Tage. Direkt- und Umsteigeverbindungen zum Flughafen Jerewan-Swartnoz (EVN) über europäische Drehkreuze.</p>
      </div>
    </div>
  </main>
  <footer>&copy; 2026 ArmenyTravel</footer>
</body>
</html>
"""


def _inject_polymorphic_entropy(html: str, seed: str | None = None) -> str:
    token = seed or secrets.token_hex(24)
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    pad_repeats = (int(digest[:4], 16) % 19) + 3
    css_vars = " ".join(
        f"--token-{i}: #{digest[(i * 6) % 56 : ((i * 6) % 56) + 6]};"
        for i in range(pad_repeats)
    )
    meta_block = (
        f'  <meta name="build-revision" content="{digest[:16]}">\n'
        f"  <!-- rev:{token}:{css_vars} -->\n"
    )
    if "</head>" in html:
        return html.replace("</head>", f"{meta_block}</head>", 1)
    return html + f"\n<!-- {token} -->\n"


def get_decoy_html(
    preset_name: str,
    custom_html: str | None = None,
    entropy_seed: str | None = None,
) -> str:
    if custom_html and custom_html.strip():
        base = custom_html
    else:
        base = DECOY_PRESETS.get(preset_name, DECOY_PRESETS["corporate"])
    return _inject_polymorphic_entropy(base, seed=entropy_seed)


def get_decoy_404_html(entropy_seed: str | None = None) -> str:
    return _inject_polymorphic_entropy(DECOY_404_HTML, seed=entropy_seed)


def get_decoy_Auxiliary_pages(entropy_seed: str | None = None) -> dict[str, str]:
    """Return multi-page trilingual Armenia travel pages and static assets."""
    return {
        "ru/index.html": _inject_polymorphic_entropy(DECOY_RU_HTML, seed=entropy_seed),
        "de/index.html": _inject_polymorphic_entropy(DECOY_DE_HTML, seed=entropy_seed),
        "tours.html": _inject_polymorphic_entropy(DECOY_TOURS_HTML, seed=entropy_seed),
        "guide.html": _inject_polymorphic_entropy(DECOY_GUIDE_HTML, seed=entropy_seed),
        "assets/style.css": DECOY_STYLE_CSS,
        "assets/app.js": DECOY_APP_JS,
        "assets/ararat.svg": SVG_ARARAT,
        "assets/sevan.svg": SVG_SEVAN,
        "assets/tatev.svg": SVG_TATEV,
    }


def get_decoy_robots_txt(domain: str) -> str:
    return f"User-agent: *\nAllow: /\nSitemap: https://{domain}/sitemap.xml\n"


def get_decoy_sitemap_xml(domain: str) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        f"  <url><loc>https://{domain}/</loc><changefreq>weekly</changefreq><priority>1.0</priority></url>\n"
        f"  <url><loc>https://{domain}/ru/</loc><changefreq>weekly</changefreq><priority>0.9</priority></url>\n"
        f"  <url><loc>https://{domain}/de/</loc><changefreq>weekly</changefreq><priority>0.9</priority></url>\n"
        f"  <url><loc>https://{domain}/tours.html</loc><changefreq>weekly</changefreq><priority>0.8</priority></url>\n"
        f"  <url><loc>https://{domain}/guide.html</loc><changefreq>monthly</changefreq><priority>0.8</priority></url>\n"
        "</urlset>\n"
    )


# Valid 1x1 32-bit ICO binary payload (70 bytes)
DECOY_FAVICON_ICO: Final[bytes] = bytes.fromhex(
    "00000100010001010000010020003000000016000000"
    "28000000010000000200000001002000000000000400"
    "0000000000000000000000000000000000002a170f00"
    "00000000"
)
