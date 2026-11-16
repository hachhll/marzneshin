import hashlib
import secrets
from enum import Enum
from typing import Final


class DecoyMode(str, Enum):
    preset = "preset"
    custom_html = "custom_html"
    reverse_proxy = "reverse_proxy"


DECOY_404_HTML: Final[str] = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>404 Not Found</title>
  <style>
    body { font-family: system-ui, -apple-system, sans-serif; background: #f8fafc; color: #1e293b; margin: 0; display: grid; place-items: center; min-height: 100vh; }
    .card { text-align: center; padding: 2.5rem; max-width: 420px; }
    h1 { font-size: 3rem; margin: 0 0 0.5rem; color: #0f172a; }
    p { color: #64748b; line-height: 1.6; }
    a { color: #2563eb; text-decoration: none; font-weight: 500; }
  </style>
</head>
<body>
  <div class="card">
    <h1>404</h1>
    <p>The page you requested could not be found.</p>
    <a href="/">Return Home</a>
  </div>
</body>
</html>
"""

DECOY_PRESETS: Final[dict[str, str]] = {
    "corporate": """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Nordic Systems &amp; Edge Engineering</title>
  <style>
    * { box-sizing: border-box; }
    body { font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 0; color: #1e293b; background: #ffffff; line-height: 1.6; }
    header { border-bottom: 1px solid #e2e8f0; padding: 1.25rem 2rem; display: flex; justify-content: space-between; align-items: center; max-width: 1080px; margin: 0 auto; }
    .brand { font-weight: 700; font-size: 1.125rem; color: #0f172a; letter-spacing: -0.02em; }
    nav a { margin-left: 1.5rem; color: #475569; text-decoration: none; font-size: 0.95rem; }
    main { max-width: 1080px; margin: 0 auto; padding: 4.5rem 2rem; }
    .hero h1 { font-size: 2.5rem; line-height: 1.15; color: #0f172a; max-width: 720px; margin: 0 0 1.25rem; }
    .hero p { font-size: 1.125rem; color: #475569; max-width: 640px; margin-bottom: 2.5rem; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 1.5rem; margin-top: 3rem; }
    .tile { border: 1px solid #e2e8f0; border-radius: 0.75rem; padding: 1.5rem; background: #f8fafc; }
    .tile h3 { margin-top: 0; color: #0f172a; font-size: 1.05rem; }
    .tile p { margin-bottom: 0; color: #475569; font-size: 0.95rem; }
    footer { border-top: 1px solid #e2e8f0; text-align: center; padding: 2rem; color: #94a3b8; font-size: 0.875rem; }
  </style>
</head>
<body>
  <header>
    <div class="brand">Nordic Systems</div>
    <nav>
      <a href="#services">Capabilities</a>
      <a href="#architecture">Architecture</a>
      <a href="#contact">Contact</a>
    </nav>
  </header>
  <main>
    <section class="hero">
      <h1>Deterministic Distributed Systems &amp; Platform Engineering</h1>
      <p>We partner with European engineering teams to design low-latency workloads, observability pipelines, and fault-tolerant infrastructure.</p>
    </section>
    <section id="services" class="grid">
      <div class="tile">
        <h3>Edge Reliability</h3>
        <p>Automated lifecycle management, zero-downtime ingress failover, and strict capacity planning.</p>
      </div>
      <div class="tile">
        <h3>Capacity Modeling</h3>
        <p>Latency-budget verification and synthetic workload validation across regional PoPs.</p>
      </div>
      <div class="tile">
        <h3>Compliance Audits</h3>
        <p>Minimal-retention operational postures and deterministic configuration verification.</p>
      </div>
    </section>
  </main>
  <footer id="contact">
    &copy; Nordic Cloud Advisory GmbH
  </footer>
</body>
</html>
""",
    "blog": """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Field Notes &mdash; Systems &amp; Travel</title>
  <style>
    body { font-family: Georgia, Cambria, "Times New Roman", serif; max-width: 680px; margin: 4rem auto; padding: 0 1.5rem; color: #1c1917; background: #fafaf9; line-height: 1.75; }
    h1 { font-size: 2rem; margin-bottom: 0.25rem; }
    .subtitle { color: #78716c; font-style: italic; margin-bottom: 3rem; }
    article { margin-bottom: 2.5rem; padding-bottom: 2rem; border-bottom: 1px solid #e7e5e4; }
    article h2 { font-size: 1.35rem; margin-bottom: 0.35rem; }
    .meta { font-family: system-ui, sans-serif; font-size: 0.85rem; color: #78716c; margin-bottom: 0.75rem; }
  </style>
</head>
<body>
  <h1>Field Notes</h1>
  <p class="subtitle">Essays on alpine trails, rail timetables, and calm software.</p>
  <article>
    <h2>Crossing the Rhine Valley by Regional Rail</h2>
    <div class="meta">October 18 &middot; 5 min read</div>
    <p>Taking the slower regional line between Mainz and Koblenz leaves time to watch barges navigate the bends below terraced vineyards.</p>
  </article>
  <article>
    <h2>Why Boring Infrastructure Lasts</h2>
    <div class="meta">September 04 &middot; 4 min read</div>
    <p>Systems built with small state machines, static assets, and predictable reload paths rarely wake anyone up at three in the morning.</p>
  </article>
</body>
</html>
""",
    "coming_soon": """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Scheduled Maintenance</title>
  <style>
    body { font-family: system-ui, -apple-system, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; display: grid; place-items: center; min-height: 100vh; }
    .box { max-width: 480px; padding: 2.5rem; border: 1px solid #1e293b; border-radius: 1rem; background: #111827; text-align: center; }
    h1 { font-size: 1.5rem; margin-top: 0; color: #f8fafc; }
    p { color: #94a3b8; line-height: 1.6; }
  </style>
</head>
<body>
  <div class="box">
    <h1>Portal Under Scheduled Maintenance</h1>
    <p>Static documentation and client portals are undergoing planned upgrades. Please check back shortly.</p>
  </div>
</body>
</html>
""",
}


def _inject_polymorphic_entropy(html: str, seed: str | None = None) -> str:
    token = seed or secrets.token_hex(24)
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    pad_repeats = (int(digest[:4], 16) % 19) + 3
    css_vars = " ".join(
        f"-- token-{i}: #{digest[(i * 6) % 56 : ((i * 6) % 56) + 6]};"
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
