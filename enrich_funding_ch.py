# -*- coding: utf-8 -*-
"""
Enrichissement « levées de fonds / financement » via UK Companies House (GRATUIT).
Couvre les entreprises GB (~6952). Pour chaque société :
  - profil            : statut, date de création, codes SIC (secteur), type de comptes,
                        has_charges (dette garantie présente), has_insolvency_history
  - filing-history    : catégorie « capital » -> SH01 (allotment of shares = émissions
                        d'actions = LEVÉES en equity) + dates.
Signal de financement = nb d'émissions d'actions (SH01) + présence de charges (dette).

Sortie : funding_ch.json  {company_number: {...}}  (repris/rempli incrémentalement).
Clé API : Companies House (gratuite) via env CH_API_KEY, sinon fichier
          ../ARIZ-Copilot/clé-CompaniesHouse.txt (une ligne). Auth = HTTP Basic (clé:'').

Lancement :  python enrich_funding_ch.py         (reprend là où il s'est arrêté)
Limite débit CH : 600 requêtes / 5 min -> on vise ~1.6 req/s.
"""
import os, re, sys, json, time, base64, urllib.request, urllib.error
from datetime import datetime
from pymongo import MongoClient

sys.stdout.reconfigure(encoding="utf-8")
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "funding_ch.json")

def _load_key():
    k = os.getenv("CH_API_KEY")
    if k:
        return k.strip()
    for p in (os.path.join(HERE, "..", "clé-CompaniesHouse.txt"),          # dossier Claude
              os.path.join(HERE, "..", "ARIZ-Copilot", "clé-CompaniesHouse.txt")):
        if os.path.exists(p):
            return open(p, encoding="utf-8").read().strip()
    raise FileNotFoundError("clé-CompaniesHouse.txt introuvable")

KEY = _load_key()
AUTH = "Basic " + base64.b64encode(f"{KEY}:".encode()).decode()
BASE = "https://api.company-information.service.gov.uk"

MONGO = "mongodb+srv://contact_db_user:zxwQrfsotwZAmRGR@cluster0.aca2e1i.mongodb.net/hivescan_data?appName=Cluster0"
coll = MongoClient(MONGO)["hivescan_data"]["data"]

def ch_get(path):
    """GET Companies House avec gestion 429 (backoff) et 404 (None)."""
    for attempt in range(5):
        req = urllib.request.Request(BASE + path, headers={"Authorization": AUTH, "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            if e.code == 429:
                wait = 15 * (attempt + 1)
                print(f"    429 rate limit -> pause {wait}s", flush=True)
                time.sleep(wait)
                continue
            if e.code in (500, 502, 503):
                time.sleep(3 * (attempt + 1)); continue
            return {"__error__": f"{e.code}"}
        except Exception:
            time.sleep(3 * (attempt + 1))
    return {"__error__": "retries"}

def ch_number_from(doc):
    """Numéro Companies House fiable (extrait de l'URL registre, garde les zéros/préfixes)."""
    url = doc.get("results_company_registry_url") or ""
    m = re.search(r"/company/([A-Za-z0-9]+)", url)
    if m:
        return m.group(1)
    n = doc.get("results_company_company_number")
    return str(n) if n is not None else None

def enrich_one(num):
    prof = ch_get(f"/company/{num}")
    if prof is None:
        return {"found": False}
    if isinstance(prof, dict) and prof.get("__error__"):
        return {"error": prof["__error__"]}
    time.sleep(0.6)
    # filings « capital » (SH01 = allotment of shares, statements of capital, etc.)
    fh = ch_get(f"/company/{num}/filing-history?category=capital&items_per_page=100")
    allot = []
    if isinstance(fh, dict) and fh.get("items"):
        for it in fh["items"]:
            t = (it.get("type") or "").upper()
            desc = it.get("description") or ""
            if t.startswith("SH01") or "allot" in desc.lower() or t.startswith("SH"):
                allot.append({"date": it.get("date"), "type": t, "desc": desc[:80]})
    return {
        "found": True,
        "name": prof.get("company_name"),
        "status": prof.get("company_status"),
        "created": prof.get("date_of_creation"),
        "sic": prof.get("sic_codes") or [],
        "accounts_type": ((prof.get("accounts") or {}).get("last_accounts") or {}).get("type"),
        "has_charges": bool(prof.get("has_charges")),
        "has_insolvency": bool(prof.get("has_insolvency_history")),
        "capital_filings": len(fh.get("items", [])) if isinstance(fh, dict) else 0,
        "share_allotments": len(allot),          # <-- nb de levées en equity (SH01)
        "last_allotment": (allot[0]["date"] if allot else None),
        "allotments": allot[:6],
    }

def main():
    data = {}
    if os.path.exists(OUT):
        try:
            data = json.load(open(OUT, encoding="utf-8"))
        except Exception:
            data = {}
    cur = coll.find({"results_company_jurisdiction_code": "gb"},
                    {"results_company_registry_url": 1, "results_company_company_number": 1, "_id": 0})
    docs = list(cur)
    total = len(docs)
    print(f"{total} sociétés GB ; déjà faites : {len(data)}", flush=True)
    done = 0
    for d in docs:
        num = ch_number_from(d)
        if not num or num in data:
            continue
        data[num] = enrich_one(num)
        done += 1
        time.sleep(0.6)  # ~1.6 req/s max sur 2 appels -> marge sous 600/5min
        if done % 25 == 0:
            json.dump(data, open(OUT, "w", encoding="utf-8"), ensure_ascii=False)
            with_raise = sum(1 for v in data.values() if v.get("share_allotments"))
            print(f"  {len(data)}/{total}  (levées détectées: {with_raise})", flush=True)
    json.dump(data, open(OUT, "w", encoding="utf-8"), ensure_ascii=False)
    with_raise = sum(1 for v in data.values() if v.get("share_allotments"))
    print(f"\n✓ Terminé : {len(data)} sociétés, {with_raise} avec ≥1 émission d'actions (levée).", flush=True)

if __name__ == "__main__":
    main()
