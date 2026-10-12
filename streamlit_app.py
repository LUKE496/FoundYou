"""found you - accounts, credits, ETC/BTC payments.

Modules: ip, username (existence only), email infrastructure, domain/dns.
No people-finding and no leaked-data lookups.

    uv add streamlit requests dnspython pandas
    uv run streamlit run streamlit_app.py
"""
import hashlib
import hmac
import ipaddress
import os
import re
import secrets
import socket
import sqlite3
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from decimal import Decimal

import dns.resolver
import pandas as pd
import requests
import streamlit as st

st.set_page_config(page_title="found you", layout="wide", initial_sidebar_state="expanded")

# ------------------------------------------------------------------ config
DB_PATH = os.environ.get("FOUNDYOU_DB", "foundyou.db")
ETC_ADDRESS = "0x31bd80c1f7Fc0571C8C4320EeEc27390FcF18d1F"


def secret(name, default=""):
    if os.environ.get(name):
        return os.environ[name]
    try:
        return st.secrets.get(name, default)
    except Exception:
        return default


# Put your own Bitcoin address in .streamlit/secrets.toml as BTC_ADDRESS = "bc1..."
# (an 0x ETC address cannot receive BTC - coins sent there are lost).
BTC_ADDRESS = secret("BTC_ADDRESS", "bc1qlkta2yfkgzyfdmvcq3tjyf2paw27nxcjzzxgc3")

FREE_CREDITS = 0
INVOICE_TTL = 3600  # seconds
PACKS = {"50 credits": (5, 50), "200 credits": (15, 200), "600 credits": (40, 600)}  # (USD, credits)
HEADERS = {"User-Agent": "Mozilla/5.0 (found-you; security research tool)"}
TIMEOUT = 8

# ------------------------------------------------------------------ style
st.markdown(
    """
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@400;500;600&display=swap');
html, body, [class*="css"], .stMarkdown, input, textarea, button { font-family: 'IBM Plex Sans', system-ui, sans-serif !important; }
code, pre, [data-testid="stCode"] * { font-family: 'IBM Plex Mono', ui-monospace, monospace !important; }
#MainMenu, footer, [data-testid="stToolbar"], [data-testid="stDecoration"] { display: none !important; }
header[data-testid="stHeader"] { background: transparent; }
.block-container { padding-top: 2.2rem; max-width: 980px; }
h1, h2, h3 { font-weight: 500 !important; letter-spacing: -0.01em; }
h1 { font-size: 1.5rem !important; }
.stButton > button, .stDownloadButton > button {
    border-radius: 2px; background: transparent; border: 1px solid #3a3f47; color: #d6d9de; font-weight: 500;
}
.stButton > button:hover { border-color: #d08c3c; color: #d08c3c; background: transparent; }
div[data-baseweb="input"], div[data-baseweb="select"] > div { border-radius: 2px !important; }
.stTabs [data-baseweb="tab-list"] { gap: 1.2rem; border-bottom: 1px solid #262a30; }
.stTabs [data-baseweb="tab"] { padding: 0.4rem 0; background: transparent; }
[data-testid="stMetric"] { border: 1px solid #262a30; padding: 0.7rem 0.9rem; border-radius: 2px; }
[data-testid="stSidebar"] { border-right: 1px solid #262a30; }
.muted { color: #7d838c; font-size: 0.85rem; }
</style>
""",
    unsafe_allow_html=True,
)

# ------------------------------------------------------------------ database
def db():
    c = sqlite3.connect(DB_PATH, timeout=10)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    with closing(db()) as c:
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, salt BLOB NOT NULL,
                pw BLOB NOT NULL, credits INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS invoices(
                id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, coin TEXT NOT NULL, address TEXT NOT NULL,
                amount TEXT NOT NULL, usd REAL NOT NULL, credits INTEGER NOT NULL, created INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending', txid TEXT UNIQUE);
            CREATE TABLE IF NOT EXISTS usage(
                id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, module TEXT, query TEXT, ts INTEGER);
            """
        )
        c.commit()


init_db()

# ------------------------------------------------------------------ accounts
def hash_pw(pw: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 200_000)


def create_user(username: str, password: str):
    username = username.strip().lower()
    if not re.fullmatch(r"[a-z0-9_]{3,24}", username):
        return "Username: 3-24 characters, letters, numbers, underscore."
    if len(password) < 10:
        return "Password must be at least 10 characters."
    salt = secrets.token_bytes(16)
    try:
        with closing(db()) as c:
            c.execute(
                "INSERT INTO users(username, salt, pw, credits, created) VALUES(?,?,?,?,?)",
                (username, salt, hash_pw(password, salt), FREE_CREDITS, int(time.time())),
            )
            c.commit()
    except sqlite3.IntegrityError:
        return "That username is taken."
    return None


def check_login(username: str, password: str):
    with closing(db()) as c:
        row = c.execute("SELECT * FROM users WHERE username=?", (username.strip().lower(),)).fetchone()
    if row and hmac.compare_digest(row["pw"], hash_pw(password, row["salt"])):
        return row["id"]
    return None


def get_user(uid):
    with closing(db()) as c:
        return c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()


def spend(uid, cost, module, query):
    with closing(db()) as c:
        cur = c.execute("UPDATE users SET credits = credits - ? WHERE id=? AND credits >= ?", (cost, uid, cost))
        if cur.rowcount:
            c.execute("INSERT INTO usage(user_id, module, query, ts) VALUES(?,?,?,?)", (uid, module, query, int(time.time())))
        c.commit()
        return bool(cur.rowcount)


def refund(uid, cost):
    with closing(db()) as c:
        c.execute("UPDATE users SET credits = credits + ? WHERE id=?", (cost, uid))
        c.commit()

# ------------------------------------------------------------------ payments
@st.cache_data(ttl=120)
def prices():
    r = requests.get(
        "https://api.coingecko.com/api/v3/simple/price",
        params={"ids": "ethereum-classic,bitcoin", "vs_currencies": "usd"},
        timeout=10,
    ).json()
    return {"ETC": r["ethereum-classic"]["usd"], "BTC": r["bitcoin"]["usd"]}


def fmt_amount(coin, amount):
    div = Decimal(10**18) if coin == "ETC" else Decimal(10**8)
    return f"{Decimal(amount) / div:.10f}".rstrip("0").rstrip(".") + f" {coin}"


def create_invoice(uid, coin, usd, credits):
    price = prices()[coin]
    address = ETC_ADDRESS if coin == "ETC" else BTC_ADDRESS
    with closing(db()) as c:
        taken = {r["amount"] for r in c.execute("SELECT amount FROM invoices WHERE coin=? AND status='pending'", (coin,))}
        while True:
            if coin == "ETC":
                amount = int(usd / price * 1e6) * 10**12 + (1 + secrets.randbelow(9999)) * 10**8
            else:
                amount = int(usd / price * 1e8) + 1 + secrets.randbelow(999)
            if str(amount) not in taken:
                break
        inv_id = uuid.uuid4().hex[:12]
        c.execute(
            "INSERT INTO invoices(id,user_id,coin,address,amount,usd,credits,created) VALUES(?,?,?,?,?,?,?,?)",
            (inv_id, uid, coin, address, str(amount), usd, credits, int(time.time())),
        )
        c.commit()
    return inv_id


def check_etc(inv):
    r = requests.get(
        "https://etc.blockscout.com/api",
        params={"module": "account", "action": "txlist", "address": inv["address"], "sort": "desc"},
        headers=HEADERS, timeout=15,
    ).json()
    for tx in r.get("result") or []:
        if not isinstance(tx, dict):
            continue
        if (
            tx.get("to", "").lower() == inv["address"].lower()
            and tx.get("value") == inv["amount"]
            and tx.get("isError", "0") == "0"
            and int(tx.get("timeStamp", 0)) >= inv["created"] - 60
            and int(tx.get("confirmations", 10)) >= 10
        ):
            return tx["hash"]
    return None


def check_btc(inv):
    txs = requests.get(f"https://mempool.space/api/address/{inv['address']}/txs", headers=HEADERS, timeout=15).json()
    for tx in txs:
        st_ = tx.get("status", {})
        if not st_.get("confirmed") or st_.get("block_time", 0) < inv["created"] - 60:
            continue
        for out in tx.get("vout", []):
            if out.get("scriptpubkey_address") == inv["address"] and str(out.get("value")) == inv["amount"]:
                return tx["txid"]
    return None


def settle(inv, txid):
    try:
        with closing(db()) as c:
            cur = c.execute("UPDATE invoices SET status='paid', txid=? WHERE id=? AND status='pending'", (txid, inv["id"]))
            if cur.rowcount:
                c.execute("UPDATE users SET credits = credits + ? WHERE id=?", (inv["credits"], inv["user_id"]))
            c.commit()
            return bool(cur.rowcount)
    except sqlite3.IntegrityError:
        return False  # this transaction already paid another invoice

# ------------------------------------------------------------------ modules
def resolver():
    r = dns.resolver.Resolver()
    r.lifetime = TIMEOUT
    return r


def txt_records(name):
    try:
        return [b"".join(r.strings).decode() for r in resolver().resolve(name, "TXT")]
    except Exception:
        return []


def v_ip(x):
    try:
        a = ipaddress.ip_address(x.strip())
    except ValueError:
        raise ValueError("Not a valid IP address.")
    if a.is_private or a.is_loopback or a.is_reserved or a.is_link_local:
        raise ValueError("Private or reserved address, nothing public to look up.")
    return str(a)


def m_ip(ip):
    data = requests.get(f"https://ipwho.is/{ip}", headers=HEADERS, timeout=TIMEOUT).json()
    if not data.get("success", False):
        st.error(data.get("message", "Lookup failed."))
        return False
    try:
        rdns = socket.gethostbyaddr(ip)[0]
    except Exception:
        rdns = "n/a"
    conn = data.get("connection", {})
    c1, c2, c3 = st.columns(3)
    c1.metric("Country", data.get("country", "?"))
    c2.metric("Region / city", f"{data.get('region', '?')} / {data.get('city', '?')}")
    c3.metric("ASN", conn.get("asn", "?"))
    st.table(pd.Series({"ISP": conn.get("isp"), "Org": conn.get("org"), "Reverse DNS": rdns,
                        "Timezone": data.get("timezone", {}).get("id"), "Type": data.get("type")}, name="value"))
    if data.get("latitude"):
        st.map(pd.DataFrame({"lat": [data["latitude"]], "lon": [data["longitude"]]}))
    st.caption("Geolocation is approximate, city level at best.")
    return True


SITES = {
    "GitHub": "https://github.com/{u}", "GitLab": "https://gitlab.com/{u}",
    "Reddit": "https://www.reddit.com/user/{u}", "Dev.to": "https://dev.to/{u}",
    "Keybase": "https://keybase.io/{u}", "Medium": "https://medium.com/@{u}",
    "HackerNews": "https://news.ycombinator.com/user?id={u}", "Pastebin": "https://pastebin.com/u/{u}",
    "npm": "https://www.npmjs.com/~{u}", "PyPI": "https://pypi.org/user/{u}/",
    "Docker Hub": "https://hub.docker.com/u/{u}", "Steam": "https://steamcommunity.com/id/{u}",
    "Twitch": "https://www.twitch.tv/{u}", "Replit": "https://replit.com/@{u}",
}


def v_user(x):
    x = x.strip()
    if not re.fullmatch(r"[A-Za-z0-9_.\-]{2,32}", x):
        raise ValueError("2-32 characters: letters, numbers, underscore, dot, hyphen.")
    return x


def _site(item):
    name, tpl, user = item
    url = tpl.format(u=user)
    try:
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        status = "found" if r.status_code == 200 else "not found" if r.status_code == 404 else f"unclear ({r.status_code})"
    except Exception:
        status = "error"
    return {"site": name, "status": status, "url": url}


def m_user(u):
    with st.spinner("Checking sites"):
        with ThreadPoolExecutor(8) as ex:
            rows = list(ex.map(_site, [(n, t, u) for n, t in SITES.items()]))
    df = pd.DataFrame(rows)
    st.dataframe(df, use_container_width=True, hide_index=True, column_config={"url": st.column_config.LinkColumn()})
    st.download_button("Export CSV", df.to_csv(index=False), "username_check.csv")
    st.caption("Existence checks only. Some sites answer 200 to everything or block bots, so verify by hand.")
    return True


DISPOSABLE = {"mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
              "yopmail.com", "trashmail.com", "sharklasers.com", "getnada.com"}


def v_email(x):
    x = x.strip().lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", x):
        raise ValueError("Invalid email format.")
    return x


def m_email(email):
    domain = email.split("@")[1]
    st.write(f"domain: `{domain}`")
    st.write(f"disposable provider: {'yes' if domain in DISPOSABLE else 'no (basic list)'}")
    try:
        mx = sorted((r.preference, str(r.exchange)) for r in resolver().resolve(domain, "MX"))
        st.dataframe(pd.DataFrame(mx, columns=["priority", "mail server"]), hide_index=True)
    except Exception:
        st.error("No MX records, the domain probably can't receive mail.")
    spf = [t for t in txt_records(domain) if t.startswith("v=spf1")]
    dmarc = [t for t in txt_records(f"_dmarc.{domain}") if t.startswith("v=DMARC1")]
    st.write("SPF:", f"`{spf[0]}`" if spf else "not found")
    st.write("DMARC:", f"`{dmarc[0]}`" if dmarc else "not found")
    st.caption("Mail infrastructure only. This does not reveal who owns an address.")
    return True


def v_domain(x):
    x = x.strip().lower().removeprefix("http://").removeprefix("https://").split("/")[0]
    if not re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", x):
        raise ValueError("Invalid domain.")
    return x


def m_domain(domain):
    rows = []
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
        try:
            rows += [{"type": rtype, "value": r.to_text()} for r in resolver().resolve(domain, rtype)]
        except Exception:
            pass
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
    with st.spinner("Reading certificate transparency logs"):
        try:
            r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", headers=HEADERS, timeout=20)
            subs = sorted({n for e in r.json() for n in e["name_value"].split("\n") if "*" not in n})
            st.write(f"subdomains seen in CT logs: {len(subs)}")
            st.code("\n".join(subs[:200]) or "none")
        except Exception:
            st.info("crt.sh timed out or returned nothing.")
    return True


# name: (label, placeholder, validator, runner, cost)
MODULES = {
    "ip": ("IP address", "8.8.8.8", v_ip, m_ip, 1),
    "username": ("Username", "", v_user, m_user, 2),
    "email": ("Email address", "name@example.com", v_email, m_email, 1),
    "domain": ("Domain", "example.com", v_domain, m_domain, 2),
}

# ------------------------------------------------------------------ views
TERMS = """
- Do not use this service to locate, track, harass, or intimidate anyone.
- Lookups are logged (module, input, time) for abuse review and shown in your history.
- Accounts that break these rules are banned and credits are forfeited.
- Credits are non-refundable. Crypto payments are final once sent.
"""


def auth_view():
    st.title("found you")
    st.markdown('<p class="muted">Security and infrastructure lookups. Account and credits required.</p>', unsafe_allow_html=True)
    _, mid, _ = st.columns([1, 2, 1])
    with mid:
        t_in, t_up = st.tabs(["sign in", "create account"])
        with t_in:
            u = st.text_input("Username", key="li_u")
            p = st.text_input("Password", type="password", key="li_p")
            if st.button("Sign in"):
                uid = check_login(u, p)
                if uid:
                    st.session_state.uid = uid
                    st.rerun()
                time.sleep(1)  # slow down guessing
                st.error("Wrong username or password.")
        with t_up:
            u = st.text_input("Username", key="su_u")
            p = st.text_input("Password (10+ characters)", type="password", key="su_p")
            with st.expander("Terms"):
                st.markdown(TERMS)
            ok = st.checkbox("I agree to the terms")
            if st.button("Create account"):
                if not ok:
                    st.error("You need to accept the terms.")
                elif err := create_user(u, p):
                    st.error(err)
                else:
                    st.session_state.uid = check_login(u, p)
                    st.rerun()


def module_view(user, name):
    label, placeholder, validate, runner, cost = MODULES[name]
    st.markdown(f'<p class="muted">{cost} credit{"s" if cost > 1 else ""} per lookup</p>', unsafe_allow_html=True)
    value = st.text_input(label, placeholder=placeholder, key=f"in_{name}")
    if st.button("Run", key=f"run_{name}") and value:
        try:
            clean = validate(value)
        except ValueError as e:
            st.error(str(e))
            return
        if not spend(user["id"], cost, name, clean):
            st.error("Not enough credits. Add some in the credits tab.")
            return
        try:
            if runner(clean) is False:
                refund(user["id"], cost)
                st.caption("Lookup failed, credits returned.")
        except Exception:
            refund(user["id"], cost)
            st.error("Something went wrong, credits returned.")


def credits_view(user):
    st.write(f"balance: **{user['credits']}** credits")
    coins = ["ETC"] + (["BTC"] if BTC_ADDRESS else [])
    c1, c2 = st.columns(2)
    pack = c1.selectbox("Pack", list(PACKS), format_func=lambda k: f"{k} - ${PACKS[k][0]}")
    coin = c2.selectbox("Pay with", coins)
    if not BTC_ADDRESS:
        st.caption("BTC is off until BTC_ADDRESS is set in secrets.")
    if st.button("Create invoice"):
        try:
            create_invoice(user["id"], coin, *PACKS[pack])
        except Exception:
            st.error("Couldn't fetch the price. Try again in a moment.")

    with closing(db()) as c:
        invs = c.execute(
            "SELECT * FROM invoices WHERE user_id=? AND status='pending' AND created>? ORDER BY created DESC",
            (user["id"], int(time.time()) - INVOICE_TTL),
        ).fetchall()
    for inv in invs:
        with st.container(border=True):
            mins = max(0, (inv["created"] + INVOICE_TTL - int(time.time())) // 60)
            st.write(f"invoice `{inv['id']}` - {inv['credits']} credits - expires in {mins} min")
            st.write("Send exactly this amount (the last digits identify your payment):")
            st.code(fmt_amount(inv["coin"], inv["amount"]))
            st.write("to:")
            st.code(inv["address"])
            if inv["coin"] == "BTC":
                st.caption("Credits are added after 1 confirmation.")
            else:
                st.caption("Credits are added after 10 confirmations (a few minutes).")
            if st.button("Check payment", key=f"chk_{inv['id']}"):
                try:
                    txid = check_etc(inv) if inv["coin"] == "ETC" else check_btc(inv)
                except Exception:
                    st.error("Couldn't reach the block explorer. Try again.")
                    continue
                if txid and settle(inv, txid):
                    st.success("Payment confirmed, credits added.")
                    st.rerun()
                else:
                    st.info("Not seen yet. Wait a few minutes and check again.")


def history_view(user):
    with closing(db()) as c:
        use = c.execute("SELECT module, query, ts FROM usage WHERE user_id=? ORDER BY ts DESC LIMIT 50", (user["id"],)).fetchall()
        inv = c.execute("SELECT id, coin, usd, credits, status, created FROM invoices WHERE user_id=? ORDER BY created DESC LIMIT 20", (user["id"],)).fetchall()
    st.write("lookups")
    df = pd.DataFrame([dict(r) for r in use])
    if not df.empty:
        df["ts"] = pd.to_datetime(df["ts"], unit="s")
    st.dataframe(df, use_container_width=True, hide_index=True)
    st.write("invoices")
    df = pd.DataFrame([dict(r) for r in inv])
    if not df.empty:
        df["created"] = pd.to_datetime(df["created"], unit="s")
    st.dataframe(df, use_container_width=True, hide_index=True)


# ------------------------------------------------------------------ main
uid = st.session_state.get("uid")
user = get_user(uid) if uid else None

if not user:
    auth_view()
else:
    with st.sidebar:
        st.markdown(f"**{user['username']}**")
        st.metric("Credits", user["credits"])
        if st.button("Sign out"):
            st.session_state.clear()
            st.rerun()
        st.markdown('<p class="muted">Lookups on private individuals are not supported.</p>', unsafe_allow_html=True)

    st.title("found you")
    names = list(MODULES) + ["credits", "history"]
    for tab, name in zip(st.tabs(names), names):
        with tab:
            if name == "credits":
                credits_view(user)
            elif name == "history":
                history_view(user)
            else:
                module_view(user, name)