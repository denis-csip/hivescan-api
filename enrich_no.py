# -*- coding: utf-8 -*-
"""
Enrichissement COUVERTURE + SANTÉ pour les sociétés NORVÉGIENNES (juridiction 'no'),
via l'API officielle Brønnøysundregistrene (Enhetsregisteret) — GRATUIT, SANS CLÉ.

⚠️ Contrairement à GB (Companies House SH01) et FR (BODACC capital), le registre
norvégien n'expose PAS librement les augmentations de capital / levées. On récupère
donc la SANTÉ de la société (active / faillite / liquidation), l'âge, la forme
juridique, le secteur et l'effectif. Le champ share_allotments reste 0 et
`raises_tracked=False` (honnêteté : la donnée de levée n'est pas publiée ici).

Sortie : funding_no.json  {orgnr: {...}}  — schéma compatible funding_ch/fr.json.
Lancement :  python enrich_no.py       (reprend là où il s'est arrêté)
"""
import os, sys, json, time, re, urllib.request, urllib.error
from pymongo import MongoClient

sys.stdout.reconfigure(encoding="utf-8")
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "funding_no.json")
MONGO = "mongodb+srv://contact_db_user:zxwQrfsotwZAmRGR@cluster0.aca2e1i.mongodb.net/hivescan_data?appName=Cluster0"
coll = MongoClient(MONGO)["hivescan_data"]["data"]
UA = {"User-Agent": "hivescan-poc/1.0 (research)", "Accept": "application/json"}
BASE = "https://data.brreg.no/enhetsregisteret/api/enheter/"

def http_json(url):
    for attempt in range(4):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=30) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            if e.code == 429:
                time.sleep(10 * (attempt + 1)); continue
            if e.code in (500, 502, 503):
                time.sleep(3 * (attempt + 1)); continue
            return {"__error__": str(e.code)}
        except Exception:
            time.sleep(3 * (attempt + 1))
    return {"__error__": "retries"}

def _orgnr(doc):
    s = re.sub(r"\D", "", str(doc.get("results_company_company_number") or ""))
    return s if len(s) == 9 else None

def enrich_one(org):
    e = http_json(BASE + org)
    if e is None:
        return {"found": False}
    if not isinstance(e, dict) or e.get("__error__"):
        return {"error": (e or {}).get("__error__", "?")}
    konkurs = bool(e.get("konkurs"))
    tvang = bool(e.get("underTvangsavviklingEllerTvangsopplosning"))
    avvikling = bool(e.get("underAvvikling"))
    status = "konkurs" if konkurs else ("tvangsavvikling" if tvang else ("avvikling" if avvikling else "active"))
    naering = (e.get("naeringskode1") or {}).get("kode")
    return {
        "found": True,
        "name": e.get("navn"),
        "status": status,
        "created": e.get("registreringsdatoEnhetsregisteret") or e.get("stiftelsesdato"),
        "sic": [naering] if naering else [],
        "accounts_type": (e.get("organisasjonsform") or {}).get("kode"),   # AS, ENK, ...
        "employees": e.get("antallAnsatte"),
        "has_charges": False,
        "has_insolvency": konkurs or tvang,
        "capital_filings": 0,
        "share_allotments": 0,          # non publié librement en NO
        "last_allotment": None,
        "allotments": [],
        "raises_tracked": False,        # la donnée de levée n'existe pas dans cette source
        "source": "Brønnøysundregistrene",
    }

def main():
    data = {}
    if os.path.exists(OUT):
        try: data = json.load(open(OUT, encoding="utf-8"))
        except Exception: data = {}
    docs = list(coll.find({"results_company_jurisdiction_code": "no"},
                          {"results_company_company_number": 1, "_id": 0}))
    total = len(docs)
    print(f"{total} sociétés NO ; déjà faites : {len(data)}", flush=True)
    done = 0
    for d in docs:
        org = _orgnr(d)
        if not org or org in data:
            continue
        data[org] = enrich_one(org)
        done += 1
        time.sleep(0.2)
        if done % 50 == 0:
            json.dump(data, open(OUT, "w", encoding="utf-8"), ensure_ascii=False)
            active = sum(1 for v in data.values() if v.get("status") == "active")
            print(f"  {len(data)}/{total}  (actives: {active})", flush=True)
    json.dump(data, open(OUT, "w", encoding="utf-8"), ensure_ascii=False)
    print(f"\n✓ Terminé NO : {len(data)} sociétés.", flush=True)

if __name__ == "__main__":
    main()
