import json
import re
import sys
import time
from datetime import datetime
from pathlib import Path

import requests
from bs4 import BeautifulSoup

EXTENSIONS = [
    "https://chromewebstore.google.com/detail/picture-in-picture-pip-fl/ladkmpkpnkooecmndbadcdkpjkmbkdpa",
    "https://chromewebstore.google.com/detail/docsafterdark/pihphjfnfjmdbhakhjifipfdgbpenobg",
    "https://chromewebstore.google.com/detail/youblock-lite/looigibllgojbefbpalaagkkcenlompd",
    "https://chromewebstore.google.com/detail/search-fixer-for-youtube/bojdknokkpgboeonegndfcgkaommhleo",
    "https://chromewebstore.google.com/detail/anypip-picture-in-picture/gepffghbolhjojibgohkdecdibdpbali",
    "https://chromewebstore.google.com/detail/download-youtube-thumbnai/alpoemkipgiligmabhmkhhfenlccdhpm",
    "https://chromewebstore.google.com/detail/ultimate-car-driving-game/aomkpefnllinimbhddlfhelelngakbbn",
    "https://chromewebstore.google.com/detail/sponsorblock-for-youtube/mnjggcdmjocbbbhaepdhchncahnbgone",
    "https://chromewebstore.google.com/detail/youtube-shorts-block/jiaopdjbehhjgokpphdfgmapkobbnmjp",
    "https://chromewebstore.google.com/detail/youtube-popout-player/kmfikkopdhmbdbkndkamabamlkkgkpod",
]

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
}
OUT_DIR = Path("metadata_output")

# Helpers
def extension_id_from_url(url):
    m = re.search(r"([a-p]{32})", url)
    return m.group(1) if m else None

def parse_count(s):
    s = s.replace(",", "").strip()
    mult = 1
    if s.endswith("K"):
        mult, s = 1_000, s[:-1]
    elif s.endswith("M"):
        mult, s = 1_000_000, s[:-1]
    try:
        return int(float(s) * mult)
    except ValueError:
        return None

def first(pattern, text, flags=0):
    m = re.search(pattern, text, flags)
    return m.group(1).strip() if m else None

# Fetching 
def fetch_listing(url):
    r = requests.get(url, headers=HEADERS, params={"hl": "en"}, timeout=20)
    r.raise_for_status()
    return r.text

# Parsing 
def parse_listing(html, url=None):
    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text("\n")
    text = re.sub(r"\n\s*\n+", "\n", text)

    def meta(prop):
        tag = soup.find("meta", attrs={"property": prop}) or soup.find("meta", attrs={"name": prop})
        return tag["content"].strip() if tag and tag.get("content") else None

    title = meta("og:title") or (soup.title.string if soup.title else None)
    name = re.sub(r"\s*-\s*Chrome Web Store\s*$", "", title or "")

    rm = re.search(r"(\d(?:\.\d)?)\s*\(?\s*([\d.,]+[KM]?)\s*ratings", text)
    rating = float(rm.group(1)) if rm else None
    rating_count = parse_count(rm.group(2)) if rm else None

    um = re.search(r"([\d,]+)\s+users", text)
    users = parse_count(um.group(1)) if um else None

    category = first(r"Extension\s*\n?\s*([A-Za-z&' ,/-]+?)\s*\n?\s*[\d,]+\s+users", text)

    updated_raw = first(r"Updated\s*\n?\s*([A-Z][a-z]+ \d{1,2}, \d{4})", text)
    last_updated = None
    if updated_raw:
        try:
            last_updated = datetime.strptime(updated_raw, "%B %d, %Y").date().isoformat()
        except ValueError:
            last_updated = updated_raw

    overview = first(r"\nOverview\n(.*?)\n(?:\d(?:\.\d)?\s*out of|Details\n)", text, re.S)

    perm_expl = first(r"Permission explanations:\s*(.*?)(?:Data usage explanations:|\Z)", overview or "", re.S)
    data_expl = first(r"Data usage explanations:\s*(.*)", overview or "", re.S)

    def link_with_text(pred):
        for a in soup.find_all("a", href=True):
            if pred(a.get_text(" ", strip=True), a["href"]):
                return a["href"]
        return None

    dev_site = link_with_text(lambda t, h: t.lower() == "website")
    privacy_policy = link_with_text(
        lambda t, h: "privacy policy" in t.lower() and "google.com/privacypolicy" not in h
    )
    dev_email = first(r"Email\s*\n?\s*([\w.+-]+@[\w-]+\.[\w.-]+)", text)

    priv = first(r"\nPrivacy\n(.*?)\nSupport\n", text, re.S) or ""
    disclosure = first(r"(The developer has disclosed[^.]*\.)", priv)
    declares = first(r"This developer declares that your data is\s*(.*)", priv, re.S)
    declared_list = [l.strip(" -*") for l in (declares or "").split("\n") if len(l.strip()) > 10]

    badges = {
        "featured": bool(re.search(r"\bFeatured\b", text)),
        "established_publisher": "Established Publisher" in text,
        "follows_recommended_practices": "Follows recommended practices" in text,
    }

    result = {
        "extension_id": extension_id_from_url(url or ""),
        "store_url": url,
        "name": name,
        "short_description": meta("og:description") or meta("description"),
        "long_description": overview,
        "category": category,
        "users": users,
        "rating": rating,
        "rating_count": rating_count,
        "version": first(r"Version\s*\n?\s*([\d.]+)", text),
        "last_updated": last_updated,
        "size": first(r"Size\s*\n?\s*([\d.]+\s*[KMG]i?B)", text),
        "developer": {
            "website": dev_site,
            "email": dev_email,
            "is_trader": False if "Non-trader" in text else None,
        },
        "privacy": {
            "policy_url": privacy_policy,
            "disclosure_statement": disclosure,
            "declarations": declared_list,
        },
        "developer_permission_explanations": perm_expl,
        "developer_data_usage_explanations": data_expl,
        "badges": badges,
        "scraped_at": datetime.now().isoformat(timespec="seconds"),
    }
    result["signals"] = compute_signals(result)
    return result

# Risk/Context signals 
def compute_signals(d):
    sig = []
    if d["last_updated"] and re.match(r"\d{4}-\d{2}-\d{2}", d["last_updated"]):
        age_days = (datetime.now() - datetime.fromisoformat(d["last_updated"])).days
        if age_days > 548:
            sig.append({"id": "STALE", "detail": f"Not updated in {age_days // 30} months"})
    if d["users"] is not None and d["users"] < 1000:
        sig.append({"id": "LOW_USERS", "detail": f"Only {d['users']} users"})
    if d["rating_count"] is not None and d["rating_count"] < 20:
        sig.append({"id": "FEW_RATINGS", "detail": f"Only {d['rating_count']} ratings"})
    if d["rating"] is not None and d["rating"] < 3.5:
        sig.append({"id": "LOW_RATING", "detail": f"Rated {d['rating']}"})
    if not d["privacy"]["policy_url"]:
        sig.append({"id": "NO_PRIVACY_POLICY", "detail": "No privacy policy link on listing"})
    if not d["developer"]["website"]:
        sig.append({"id": "NO_DEVELOPER_WEBSITE", "detail": "Developer lists no website"})
    if not d["privacy"]["disclosure_statement"]:
        sig.append({"id": "NO_DATA_DISCLOSURE", "detail": "No data-collection disclosure found"})
    return sig

# Main
def analyze_url(url):
    return parse_listing(fetch_listing(url), url)

def main():
    OUT_DIR.mkdir(exist_ok=True)

    if len(sys.argv) == 3 and sys.argv[1] == "--html":
        html = Path(sys.argv[2]).read_text(encoding="utf-8")
        print(json.dumps(parse_listing(html), indent=2))
        return

    urls = sys.argv[1:] or EXTENSIONS
    results = []
    for url in urls:
        try:
            data = analyze_url(url)
        except Exception as e:
            print(f"FAILED {url}: {e}")
            continue
        results.append(data)
        (OUT_DIR / f"{data['extension_id']}_metadata.json").write_text(
            json.dumps(data, indent=2), encoding="utf-8"
        )
        print(f"ok  {data['name']}  ({data['users']} users, {len(data['signals'])} signals)")
        time.sleep(2)

    (OUT_DIR / "all_metadata.json").write_text(json.dumps(results, indent=2), encoding="utf-8")

if __name__ == "__main__":
    main()