# -*- coding: utf-8 -*-
"""
Enrichissement COUVERTURE + SANTÉ pour les sociétés DANOISES (juridiction 'dk'),
via cvrapi.dk (données publiques CVR) — GRATUIT, SANS CLÉ (User-Agent descriptif requis).

Comme pour NO : le registre n'expose pas librement les levées de capital. On récupère
la santé (active / faillite / cessée), l'âge, l'effectif, le secteur. share_allotments=0,
raises_tracked=False. Schéma compatible funding_ch/fr.json.

Sortie : funding_dk.json  {cvr: {...}}.  Lancement : python enrich_dk.py  (reprenable)
"""
import os, sys, json, time, re, urllib.request, urllib.parse, urllib.error
from pymongo import MongoClient

sys.stdout.reconfigure(encoding="utf-8")
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "funding_dk.json")
MONGO = "mongodb+srv://contact_db_user:zxwQrfsotwZAmRGR@cluster0.aca2e1i.mongodb.net/hivescan_data?appName=Cluster0"
coll = MongoClient(MONGO)["hivescan_data"]["data"]
UA = {"User-Agent": "hivescan-poc/1.0 research (denis.cavallucci@insa-strasbourg.fr)",
      "Accept": "application/json"}
BASE = "https://cvrapi.dk/api?country=dk&search="

def http_json(url):
    for attempt in range(4):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=30) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            if e.code == 429:
                time.sleep(20 * (attempt + 1)); continue
            if e.code in (500, 502, 503):
                time.sleep(4 * (attempt + 1)); continue
            return {"__error__": str(e.code)}
        except Exception:
            time.sleep(4 * (attempt + 1))
    return {"__error__": "retries"}

def _cvr(doc):
    s = re.sub(r"\D", "", str(doc.get("results_company_company_number") or ""))
    return s if len(s) == 8 else None

def _iso(dk):
    # "11/11 - 2022" -> "2022-11-11"
    m = re.match(r"\s*(\d{1,2})/(\d{1,2})\s*-\s*(\d{4})", dk or "")
    return f"{m.group(3)}-{int(m.group(2)):02d}-{int(m.group(1)):02d}" if m else (dk or None)

def enrich_one(cvr):
    e = http_json(BASE + cvr)
    if e is None:
        return {"found": False}
    if not isinstance(e, dict) or e.get("__error__"):
        return {"error": (e or {}).get("__error__", "?")}
    bankrupt = bool(e.get("creditbankrupt"))
    ended = bool(e.get("enddate"))
    status = "konkurs" if bankrupt else ("ophoert" if ended else "active")
    ind = e.get("industrycode")
    return {
        "found": True,
        "name": e.get("name"),
        "status": status,
        "created": _iso(e.get("startdate")),
        "sic": [str(ind)] if ind else [],
        "accounts_type": e.get("companydesc"),
        "employees": e.get("employees"),
        "has_charges": False,
        "has_insolvency": bankrupt,
        "capital_filings": 0,
        "share_allotments": 0,
        "last_allotment": None,
        "allotments": [],
        "raises_tracked": False,
        "source": "CVR (cvrapi.dk)",
    }

def main():
    data = {}
    if os.path.exists(OUT):
        try: data = json.load(open(OUT, encoding="utf-8"))
        except Exception: data = {}
    docs = list(coll.find({"results_company_jurisdiction_code": "dk"},
                          {"results_company_company_number": 1, "_id": 0}))
    total = len(docs)
    print(f"{total} sociétés DK ; déjà faites : {len(data)}", flush=True)
    done = 0
    for d in docs:
        cvr = _cvr(d)
        if not cvr or cvr in data:
            continue
        data[cvr] = enrich_one(cvr)
        done += 1
        time.sleep(1.2)          # cvrapi.dk : rester poli (débit modéré)
        if done % 25 == 0:
            json.dump(data, open(OUT, "w", encoding="utf-8"), ensure_ascii=False)
            active = sum(1 for v in data.values() if v.get("status") == "active")
            print(f"  {len(data)}/{total}  (actives: {active})", flush=True)
    json.dump(data, open(OUT, "w", encoding="utf-8"), ensure_ascii=False)
    print(f"\n✓ Terminé DK : {len(data)} sociétés.", flush=True)

if __name__ == "__main__":
    main()
