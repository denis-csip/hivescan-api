# -*- coding: utf-8 -*-
"""
Enrichissement « levées de fonds / financement » pour les sociétés FRANÇAISES
(juridictions fr + DOM : re, gp, mq, gf), 100 % GRATUIT, SANS CLÉ.

Deux sources publiques :
  1) API Recherche d'entreprises (recherche-entreprises.api.gouv.fr) — statut
     (actif/cessé), date de création, tranche d'effectif, nature juridique,
     nb de dirigeants, présence de finances (CA).  Clé du SIREN.
  2) BODACC (bodacc-datadila.opendatasoft.com, dataset annonces-commerciales) —
     les annonces « Modification » dont modificationsgenerales.descriptif
     contient « capital » = AUGMENTATIONS/MODIFICATIONS DE CAPITAL = équivalent
     français des SH01 (levées en equity).  Les « jugement » = procédures
     collectives (redressement/liquidation) = signal d'insolvabilité.

Sortie : funding_fr.json  {SIREN: {...}}  — MÊME schéma que funding_ch.json
(champ clé « share_allotments » = nb d'événements capital) pour que
/company-funding et l'UI fonctionnent à l'identique.

Lancement :  python enrich_funding_fr.py     (reprend là où il s'est arrêté)
"""
import os, sys, json, time, re, urllib.request, urllib.parse, urllib.error
from pymongo import MongoClient

sys.stdout.reconfigure(encoding="utf-8")
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "funding_fr.json")

MONGO = "mongodb+srv://contact_db_user:zxwQrfsotwZAmRGR@cluster0.aca2e1i.mongodb.net/hivescan_data?appName=Cluster0"
coll = MongoClient(MONGO)["hivescan_data"]["data"]

UA = {"User-Agent": "hivescan-poc/1.0 (research)", "Accept": "application/json"}
RECH = "https://recherche-entreprises.api.gouv.fr/search?q="
BODACC = ("https://bodacc-datadila.opendatasoft.com/api/explore/v2.1/catalog/"
          "datasets/annonces-commerciales/records")

def http_json(url):
    """GET JSON avec gestion 429 (backoff) et 404 (None)."""
    for attempt in range(5):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=30) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            if e.code == 429:
                wait = 10 * (attempt + 1)
                print(f"    429 -> pause {wait}s", flush=True); time.sleep(wait); continue
            if e.code in (500, 502, 503):
                time.sleep(3 * (attempt + 1)); continue
            return {"__error__": str(e.code)}
        except Exception:
            time.sleep(3 * (attempt + 1))
    return {"__error__": "retries"}

_ETAT = {"A": "active", "C": "cessee"}

def _siren(doc):
    n = doc.get("results_company_company_number")
    s = re.sub(r"\D", "", str(n or ""))
    return s if len(s) == 9 else None

def _rech(siren):
    r = http_json(RECH + siren)
    if not isinstance(r, dict):
        return {}
    res = r.get("results") or []
    if not res:
        return {}
    e = res[0]
    fin = e.get("finances") or {}
    last_ca = None
    if isinstance(fin, dict) and fin:
        y = sorted(fin.keys())[-1]
        last_ca = (fin.get(y) or {}).get("ca")
    return {
        "name": e.get("nom_complet") or e.get("nom_raison_sociale"),
        "etat": _ETAT.get(e.get("etat_administratif"), e.get("etat_administratif")),
        "created": e.get("date_creation"),
        "naf": e.get("activite_principale"),
        "effectif": e.get("tranche_effectif_salarie"),
        "nature": e.get("nature_juridique"),
        "dirigeants": len(e.get("dirigeants") or []),
        "last_ca": last_ca,
    }

def _bodacc(siren):
    """Compte les annonces, dont les événements 'capital' et les procédures."""
    url = (BODACC + "?where=" + urllib.parse.quote(f'registre LIKE "{siren}"')
           + "&limit=100&order_by=" + urllib.parse.quote("dateparution desc"))
    r = http_json(url)
    if not isinstance(r, dict):
        return {"total": 0, "capital": [], "procedures": 0, "deposits": 0}
    recs = r.get("results") or []
    cap, proc, dep = [], 0, 0
    for x in recs:
        fam = (x.get("familleavis_lib") or "").lower()
        if x.get("jugement"):
            proc += 1
        if "dépôt" in fam or "depot" in fam:
            dep += 1
        mg = x.get("modificationsgenerales")
        if isinstance(mg, str):                     # certains records renvoient un JSON encodé
            try: mg = json.loads(mg)
            except Exception: mg = {"descriptif": mg}
        blob = (json.dumps(mg or {}, ensure_ascii=False) + " "
                + json.dumps(x.get("acte") or {}, ensure_ascii=False))
        if "capital" in blob.lower():
            desc = (mg or {}).get("descriptif") or "Modification de capital"
            cap.append({"date": x.get("dateparution"), "type": "CAPITAL", "desc": desc[:80]})
    return {"total": r.get("total_count") or len(recs),
            "capital": cap, "procedures": proc, "deposits": dep}

def enrich_one(siren):
    rc = _rech(siren)
    time.sleep(0.35)
    bo = _bodacc(siren)
    cap = bo["capital"]
    if not rc and bo["total"] == 0:
        return {"found": False}
    return {
        "found": True,
        "name": rc.get("name"),
        "status": rc.get("etat"),
        "created": rc.get("created"),
        "sic": [rc.get("naf")] if rc.get("naf") else [],
        "accounts_type": ("comptes déposés" if bo["deposits"] else None),
        "effectif": rc.get("effectif"),
        "last_ca": rc.get("last_ca"),
        "has_charges": False,                       # pas d'équivalent gratuit direct en FR
        "has_insolvency": bo["procedures"] > 0,     # procédure collective BODACC
        "capital_filings": bo["total"],
        "share_allotments": len(cap),               # <-- événements capital = levées (analog SH01)
        "last_allotment": (cap[0]["date"] if cap else None),
        "allotments": cap[:6],
    }

def main():
    data = {}
    if os.path.exists(OUT):
        try:
            data = json.load(open(OUT, encoding="utf-8"))
        except Exception:
            data = {}
    docs = list(coll.find({"results_company_jurisdiction_code": {"$in": ["fr", "re", "gp", "mq", "gf"]}},
                          {"results_company_company_number": 1, "_id": 0}))
    total = len(docs)
    print(f"{total} sociétés FR/DOM ; déjà faites : {len(data)}", flush=True)
    done = 0
    for d in docs:
        siren = _siren(d)
        if not siren or siren in data:
            continue
        data[siren] = enrich_one(siren)
        done += 1
        time.sleep(0.35)
        if done % 25 == 0:
            json.dump(data, open(OUT, "w", encoding="utf-8"), ensure_ascii=False)
            wr = sum(1 for v in data.values() if v.get("share_allotments"))
            print(f"  {len(data)}/{total}  (événements capital détectés: {wr})", flush=True)
    json.dump(data, open(OUT, "w", encoding="utf-8"), ensure_ascii=False)
    wr = sum(1 for v in data.values() if v.get("share_allotments"))
    print(f"\n✓ Terminé : {len(data)} sociétés, {wr} avec ≥1 événement de capital.", flush=True)

if __name__ == "__main__":
    main()
