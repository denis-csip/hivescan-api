# -*- coding: utf-8 -*-
"""
Enrichissement « levées de fonds » pour les sociétés US (juridiction 'us_ri'),
via SEC EDGAR — déclarations **Form D** (offres de titres privées = levées auprès
d'investisseurs). GRATUIT, sans clé (User-Agent avec contact requis par la SEC).

Signal = nb de Form D déposés par la société (chaque Form D = une offre privée) +
le MONTANT vendu (totalAmountSold) de la plus récente. Schéma compatible funding_*.json
(share_allotments = nb de Form D). Sortie : funding_us.json {company_number: {...}}.

Lancement : python enrich_us.py   (reprenable)
"""
import os, sys, json, time, re, urllib.request, urllib.parse, urllib.error
from pymongo import MongoClient

sys.stdout.reconfigure(encoding="utf-8")
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "funding_us.json")
MONGO = "mongodb+srv://contact_db_user:zxwQrfsotwZAmRGR@cluster0.aca2e1i.mongodb.net/hivescan_data?appName=Cluster0"
coll = MongoClient(MONGO)["hivescan_data"]["data"]
UA = {"User-Agent": "Hivescan research (denis.cavallucci@insa-strasbourg.fr)"}
EFTS = "https://efts.sec.gov/LATEST/search-index?"

def _norm(s):
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())

def http(url, raw=False):
    for attempt in range(5):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=30) as r:
                return r.read() if raw else json.load(r)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            if e.code in (429, 403):
                time.sleep(8 * (attempt + 1)); continue
            if e.code in (500, 502, 503):
                time.sleep(3 * (attempt + 1)); continue
            return None
        except Exception:
            time.sleep(3 * (attempt + 1))
    return None

def _amount(cik, adsh):
    try:
        url = "https://www.sec.gov/Archives/edgar/data/%d/%s/primary_doc.xml" % (int(cik), adsh.replace("-", ""))
        xml = http(url, raw=True)
        if not xml:
            return None
        xml = xml.decode("utf-8", "ignore")
        m = re.search(r"<totalAmountSold>(.*?)</totalAmountSold>", xml)
        if m and m.group(1).strip().isdigit():
            return int(m.group(1).strip())
    except Exception:
        pass
    return None

def enrich_one(name):
    r = http(EFTS + urllib.parse.urlencode({"q": '"%s"' % name, "forms": "D"}))
    if not isinstance(r, dict):
        return {"found": False}
    hits = ((r.get("hits") or {}).get("hits")) or []
    nc = _norm(name)
    # Garde anti-bruit : ne garder que les Form D DÉPOSÉS par cette société (nom du déposant).
    mine = [h for h in hits if any(nc and nc in _norm(dn) for dn in (h.get("_source", {}).get("display_names") or []))]
    base = {"found": True, "name": name, "status": "active", "sic": [],
            "has_charges": False, "has_insolvency": False, "capital_filings": len(hits),
            "raises_tracked": True, "source": "SEC EDGAR — Form D"}
    if not mine:
        base.update({"share_allotments": 0, "last_allotment": None, "allotments": [], "amount_sold": None})
        return base
    mine.sort(key=lambda h: (h.get("_source", {}).get("file_date") or ""), reverse=True)
    top = mine[0]
    src = top.get("_source", {})
    cik = (src.get("ciks") or [""])[0]
    adsh = top.get("_id", "").split(":")[0]
    amount = _amount(cik, adsh) if cik and adsh else None
    time.sleep(0.2)
    base.update({
        "share_allotments": len(mine),
        "last_allotment": src.get("file_date"),
        "amount_sold": amount,
        "allotments": [{"date": h.get("_source", {}).get("file_date"), "type": "FORM_D",
                        "desc": "Offre privée (Form D)"} for h in mine[:6]],
    })
    return base

def main():
    data = {}
    if os.path.exists(OUT):
        try: data = json.load(open(OUT, encoding="utf-8"))
        except Exception: data = {}
    docs = list(coll.find({"results_company_jurisdiction_code": "us_ri"},
                          {"results_company_name": 1, "results_company_company_number": 1, "_id": 0}))
    total = len(docs)
    print(f"{total} sociétés US ; déjà faites : {len(data)}", flush=True)
    done = 0
    for d in docs:
        num = str(d.get("results_company_company_number") or "")
        if not num or num in data:
            continue
        data[num] = enrich_one(d.get("results_company_name") or "")
        done += 1
        time.sleep(0.28)   # SEC : rester bien sous 10 req/s
        if done % 25 == 0:
            json.dump(data, open(OUT, "w", encoding="utf-8"), ensure_ascii=False)
            wr = sum(1 for v in data.values() if v.get("share_allotments"))
            print(f"  {len(data)}/{total}  (avec Form D: {wr})", flush=True)
    json.dump(data, open(OUT, "w", encoding="utf-8"), ensure_ascii=False)
    wr = sum(1 for v in data.values() if v.get("share_allotments"))
    print(f"\n✓ Terminé US : {len(data)} sociétés, {wr} avec ≥1 Form D (levée privée).", flush=True)

if __name__ == "__main__":
    main()
