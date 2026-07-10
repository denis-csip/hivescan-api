from fastapi import FastAPI, Query, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi_pagination import Page, add_pagination, paginate
from pymongo import MongoClient
from typing import Optional, List
from collections import Counter
import re
import os
import json
import time
import hmac
import hashlib
import base64
import unicodedata
import urllib.request
import urllib.parse
import urllib.error

app = FastAPI()
add_pagination(app)

# --- Authentification (défini AVANT le CORS pour que les 401 aient les en-têtes CORS) ---
# Deux mécanismes, activables par variables d'env :
#   • Login IDEAS (comme ARIZ-Copilot) : SESSION_SECRET défini -> l'endpoint
#     /ideas-login valide les identifiants IDEAS (API GraphQL) et émet un JETON
#     de session signé (HMAC, sans état). Le client le renvoie en Bearer.
#   • Clé partagée simple : ACCESS_KEY défini -> header X-Access-Key ou ?key=.
# Si AUCUN des deux n'est défini (dev local) -> aucune restriction.
ACCESS_KEY = os.getenv("ACCESS_KEY")
SESSION_SECRET = os.getenv("SESSION_SECRET")
IDEAS_APP = os.getenv("IDEAS_APP", "ARIZ-Copilot")               # x-application accepté par IDEAS
IDEAS_ENDPOINT = os.getenv("IDEAS_ENDPOINT", "https://ideas.aiard.eu/api")
_AUTH_REQUIRED = bool(ACCESS_KEY or SESSION_SECRET)
_OPEN_PATHS = {"/", "/docs", "/openapi.json", "/redoc", "/ideas-login", "/auth-status"}

def _b64u(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")

def _b64u_dec(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def _make_token(email, days=7):
    payload = _b64u(json.dumps({"email": email, "exp": int(time.time()) + days * 86400}).encode())
    sig = _b64u(hmac.new(SESSION_SECRET.encode(), payload.encode(), hashlib.sha256).digest())
    return f"{payload}.{sig}"

def _verify_token(tok):
    if not (SESSION_SECRET and tok and "." in tok):
        return None
    payload, sig = tok.rsplit(".", 1)
    expect = _b64u(hmac.new(SESSION_SECRET.encode(), payload.encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(sig, expect):
        return None
    try:
        data = json.loads(_b64u_dec(payload))
    except Exception:
        return None
    return data if data.get("exp", 0) >= time.time() else None

@app.middleware("http")
async def _access_gate(request, call_next):
    if _AUTH_REQUIRED and request.method != "OPTIONS" and request.url.path not in _OPEN_PATHS:
        auth = request.headers.get("authorization") or ""
        tok = auth[7:] if auth[:7].lower() == "bearer " else (
            request.headers.get("x-access-key") or request.query_params.get("key"))
        ok = bool(tok) and ((ACCESS_KEY and tok == ACCESS_KEY) or _verify_token(tok) is not None)
        if not ok:
            return JSONResponse({"detail": "Authentification requise."}, status_code=401)
    return await call_next(request)

def _ideas_signin(email, password):
    """Valide les identifiants auprès de l'API GraphQL IDEAS (repris d'ARIZ-Copilot)."""
    esc = lambda s: s.replace("\\", "\\\\").replace('"', '\\"')
    mutation = ('mutation { signin(email: "%s", password: "%s") '
                '{ id name email token } }' % (esc(email), esc(password)))
    body = json.dumps({"query": mutation}).encode()
    req = urllib.request.Request(
        IDEAS_ENDPOINT, data=body, method="POST",
        headers={"Content-Type": "application/json", "x-application": IDEAS_APP})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            j = json.load(r)
    except Exception:
        return None, "network"
    if j.get("errors"):
        return None, (j["errors"][0] or {}).get("message", "auth")
    u = (j.get("data") or {}).get("signin")
    return (u, None) if u else (None, "invalid")

@app.get("/auth-status")
def auth_status():
    """Le POC interroge cet endpoint (ouvert) pour savoir s'il doit afficher le login."""
    return {"login_required": _AUTH_REQUIRED, "ideas": bool(SESSION_SECRET)}

@app.post("/ideas-login")
async def ideas_login(request: Request):
    body = await request.json()
    email = (body.get("email") or "").strip()
    password = body.get("password") or ""
    if not email or not password:
        raise HTTPException(status_code=400, detail="Email et mot de passe requis.")
    if not SESSION_SECRET:
        raise HTTPException(status_code=503, detail="Login IDEAS non configuré (SESSION_SECRET absent).")
    u, err = _ideas_signin(email, password)
    if err or not u:
        raise HTTPException(status_code=401, detail="Identifiants IDEAS invalides.")
    return {"token": _make_token(u.get("email") or email),
            "name": u.get("name"), "email": u.get("email") or email}

# --- CORS : ajouté EN DERNIER = middleware le plus EXTERNE, pour que ses en-têtes
# s'appliquent AUSSI aux réponses 401 du gate (sinon le navigateur bloque la lecture
# de la réponse). En prod, définir ALLOWED_ORIGINS = le(s) domaine(s) du POC.
_origins_env = os.getenv("ALLOWED_ORIGINS", "*").strip()
_allow_origins = ["*"] if _origins_env == "*" else [o.strip() for o in _origins_env.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allow_origins,
    allow_methods=["GET", "POST", "OPTIONS"],   # POST requis pour /ideas-login
    allow_headers=["*"],
)

# MongoDB : URI depuis l'env (prod) ; sinon fichier local NON commité (dev).
# Aucun secret en dur dans le code.
def _load_mongo_uri():
    u = os.getenv("MONGO_URI")
    if u:
        return u.strip()
    p = os.path.join(os.path.dirname(__file__), "..", "mongo_uri.txt")
    if os.path.exists(p):
        return open(p, encoding="utf-8").read().strip()
    raise RuntimeError("MONGO_URI absent : définir la variable d'env MONGO_URI "
                       "(ou créer v0_api_hivescan-main/mongo_uri.txt en local).")

MONGO_URI = _load_mongo_uri()
DB_NAME = os.getenv("MONGO_DB", "hivescan_data")
COLLECTION_NAME = os.getenv("MONGO_COLLECTION", "data")
# Borne mémoire de /search : nb max de documents complets chargés (évite l'OOM en
# prod quand un mot-clé large matche des milliers d'entreprises). Configurable.
MAX_SEARCH_DOCS = int(os.getenv("MAX_SEARCH_DOCS", "500"))

client = MongoClient(MONGO_URI)
db = client[DB_NAME]
collection = db[COLLECTION_NAME]

# --- Décomposition du score d'innovation (traçabilité, cf. thèse Ch. 8) ---------
# Les 5 features "plus = mieux" qui composent innovation_index (l'âge est un
# facteur contextuel/pénalité, traité à part → pas de barre "plus = mieux").
SCORE_FEATURES = {
    "average_triz_score": "Score TRIZ",
    "citations_per_article": "Citations / article",
    "number_of_publications": "Publications",
    "ratio_publishing_officers": "Officiers publiants",
    "employee_count": "Effectif",
}

def _is_num(v):
    return isinstance(v, (int, float)) and v == v  # v==v écarte les NaN

def _feature_maxes():
    """Max de chaque feature sur toute la base (pour normaliser, comme dans la thèse)."""
    maxes = {}
    for f in SCORE_FEATURES:
        d = collection.find_one({f: {"$gt": 0}}, sort=[(f, -1)], projection={f: 1})
        m = (d or {}).get(f)
        maxes[f] = m if (_is_num(m) and m > 0) else 1.0
    return maxes

FEATURE_MAX = _feature_maxes()

def score_breakdown(doc):
    """Contribution normalisée (0–1) de chaque feature disponible pour ce document."""
    out = {}
    for f, label in SCORE_FEATURES.items():
        v = doc.get(f)
        if _is_num(v) and v > 0:
            out[label] = round(min(v / FEATURE_MAX[f], 1.0), 3)
    return out

# --- Radar : 5 dimensions (catégories thèse Ch. 8) pour le profil d'innovation ---
def _feature_avgs():
    avgs = {}
    for f in SCORE_FEATURES:
        r = list(collection.aggregate(
            [{"$match": {f: {"$gt": 0}}}, {"$group": {"_id": None, "a": {"$avg": f"${f}"}}}]))
        avgs[f] = (r[0]["a"] if r else 0) or 0
    return avgs

FEATURE_AVG = _feature_avgs()

# axe -> (libellé, feature source)
RADAR_AXES = [
    ("solving", "Problème-solving", "average_triz_score"),
    ("impact", "Impact", "citations_per_article"),
    ("production", "Production", "number_of_publications"),
    ("human", "Capital humain", "ratio_publishing_officers"),
    ("context", "Contexte", "employee_count"),
]

def _axis_value(feat, raw, age_days=None):
    # Contexte : effectif si dispo, sinon proxy « jeunesse startup » via l'âge.
    if feat == "employee_count" and not (_is_num(raw) and raw > 0):
        if _is_num(age_days) and age_days > 0:
            return round(max(0.1, min(1.0, 1 - (age_days / 365) / 15)), 3)
        return 0.3
    if not (_is_num(raw) and raw > 0):
        return 0.0
    return round(min(raw / (FEATURE_MAX.get(feat, 1) or 1), 1.0), 3)

def company_radar(doc):
    ak = next((k for k in doc if k.startswith("age_in_days")), None)
    age = doc.get(ak) if ak else None
    return [{"key": k, "label": lbl, "value": _axis_value(feat, doc.get(feat), age)}
            for k, lbl, feat in RADAR_AXES]

def _population_radar():
    out = []
    for k, lbl, feat in RADAR_AXES:
        v = round(min((FEATURE_AVG.get(feat, 0) or 0) / (FEATURE_MAX.get(feat, 1) or 1), 1.0), 3)
        if feat == "employee_count" and v == 0:
            v = 0.3
        out.append({"key": k, "label": lbl, "value": v})
    return out

POP_RADAR = _population_radar()

# --- Libellés de topics = Table 9.9 « Chosen Topics » de la thèse (Human-in-the-Loop
#     LLM Labeling, §9.2.6). Thèse indexée 1..30 ; notre base 0..29 → label[id]=Table9.9[id+1].
#     Alignement vérifié sur les titres représentatifs (topics 1/5/27).
TOPIC_LABELS = {
    0: "General research approaches, modeling & structural efficiency analysis",
    1: "Effects and properties in physical and chemical reaction systems",
    2: "Performance improvement, influencing factors, and uncertainty analysis",
    3: "Techniques, algorithms, case studies, and associated risk analysis",
    4: "Technology applications: mechanisms, evaluation, and market potential",
    5: "Quantitative measurement, estimation, and optimization of system parameters",
    6: "Process performance and surface characterization tools",
    7: "Device integration, feature combination, and validation",
    8: "Time-resolved data analysis, monitoring, and observational capabilities",
    9: "Impact assessment methodologies for water, loads, and sensors",
    10: "Spectroscopic structural analysis and measurement of materials and cells",
    11: "Project analysis: development, interactions, rates, costs, and targets",
    12: "Environmental and network architectures: temperature, radiation, and damage",
    13: "Simulation methods and frameworks for populations, composition, classification",
    14: "Material components, beam dynamics, and laboratory imaging",
    15: "Group dynamics, concentration distributions, and decay processes",
    16: "Particle emission properties and computational behavior analysis",
    17: "Observational surveys, detection, and trend assessment",
    18: "Geometric equations, dataset learning, and resource policy",
    19: "Industrial frequency, data clustering, and scientific coding",
    20: "Energy modeling, management, and service interfaces",
    21: "Production design, information quality, and crystal ion studies",
    22: "Flow dynamics, wave spectra, and transport optimization",
    23: "Modeling of formation, transfer coefficients, and basin analysis",
    24: "Parameter testing, stability, and growth-loss dynamics analysis",
    25: "Experimental studies of space systems, stars, and environmental zones",
    26: "Signal detection and satellite-based observational instrumentation",
    27: "Diverse topics: workshops, colliders, and multilingual case studies",
    28: "General scientific synthesis and comparison",
    29: "Plant chemistry and environmental monitoring",
}

@app.get("/")
def root():
    return {"message": "Search API is running", "feature_max": FEATURE_MAX,
            "pop_radar": POP_RADAR, "topic_labels": TOPIC_LABELS, "lens": bool(LENS_KEY)}

# --- Lens (brevets) : signal de crédibilité par entreprise ------------------
# Une entreprise de la base qui détient des brevets = crédibilité renforcée pour
# un investisseur (maturité commerciale). Clé Lens lue côté serveur uniquement.
def _load_lens_key():
    k = os.getenv("LENS_KEY")
    if k:
        return k.strip()
    p = os.getenv("LENS_KEY_FILE") or os.path.join(
        os.path.dirname(__file__), "..", "..", "ARIZ-Copilot", "clé-Lens.txt")
    try:
        return open(p, encoding="utf-8").read().strip()
    except Exception:
        return None

LENS_KEY = _load_lens_key()
_LEGAL_SUFFIX = re.compile(
    r"\b(LIMITED|LTD|LLC|INC|PLC|GMBH|CORP|CORPORATION|COMPANY|CO|GROUP|HOLDINGS?|SA|SAS|BV|AB|AG|OY|LP|SL|SRL)\b\.?",
    re.I,
)
_patent_cache = {}

def _clean_company(name):
    return re.sub(r"\s+", " ", _LEGAL_SUFFIX.sub("", name or "")).strip(" .,&-")

def _norm(s):
    # Enlève les accents (Lefèvre -> LEFEVRE) puis garde A-Z0-9, pour un matching robuste.
    s = unicodedata.normalize("NFKD", s or "").encode("ascii", "ignore").decode()
    return re.sub(r"[^A-Z0-9]+", " ", s.upper()).strip()

def _lens_post(payload):
    req = urllib.request.Request(
        "https://api.lens.org/patent/search",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Authorization": f"Bearer {LENS_KEY}", "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=40) as r:
        return json.load(r)

def _patent_samples(data):
    out = []
    for p in data.get("data", []):
        b = p.get("biblio", {}) or {}
        titles = b.get("invention_title") or []
        parties = b.get("parties", {}) or {}
        apps = parties.get("applicants", []) or []
        out.append({
            "title": (titles[0].get("text") if titles else "") or "",
            "jurisdiction": p.get("jurisdiction"),
            "year": (p.get("date_published") or "")[:4],
            "applicant": ((apps[0].get("extracted_name") or {}).get("value") if apps else "") or "",
        })
    return out

def _lens_company_patents(name):
    """Brevets déposés AU NOM de l'entreprise (applicant), avec garde anti-collision."""
    q = _clean_company(name)
    if len(re.findall(r"[A-Za-zÀ-ÿ]{3,}", q)) < 2:
        return {"count": 0, "matched": False, "samples": [], "query": q}
    d = _lens_post({"query": {"match_phrase": {"applicant.name": q}}, "size": 4,
                    "include": ["jurisdiction", "date_published", "biblio.invention_title", "biblio.parties"]})
    samples = _patent_samples(d)
    qn = _norm(q)
    confident = any((_norm(s["applicant"]).startswith(qn) or qn.startswith(_norm(s["applicant"])))
                    for s in samples if s.get("applicant"))
    return {"count": d.get("total", 0) if confident else 0, "matched": confident,
            "samples": samples if confident else [], "query": q}

def _lens_officer_patents(officers, dom, jurisdiction=None):
    """Brevets où un DIRIGEANT est applicant OU inventeur, désambiguïsés.

    Désambiguïsation (leçon empirique) : le discriminant FORT est la RÉSIDENCE-PAYS
    de l'inventeur (elle écarte les homonymes étrangers : un « Imtiaz Ali » US, un
    « Zhengliang Wu » CN...) combinée au NOM COMPLET. Le domaine n'est PLUS un `must`
    (il jetait des vrais brevets, ex. Saad Khalil / 21 brevets électrodes GB, dont le
    texte ne répète pas les mots-clés de recherche) : il devient un simple FLAG de
    pertinence (`in_domain`). On ne garde le domaine comme garde-fou que si le pays
    est inconnu (sinon homonymes non bornés)."""
    offs = list(dict.fromkeys(
        [o.strip() for o in (officers or []) if o and len(re.findall(r"[A-Za-zÀ-ÿ]{3,}", o)) >= 2]))[:4]
    res = {}
    country = jurisdiction.upper() if jurisdiction else None
    if not offs or (not country and not dom):
        return res            # sans pays NI domaine : trop d'homonymes, on s'abstient
    should = []
    for o in offs:
        should.append({"match_phrase": {"applicant.name": o}})
        should.append({"match_phrase": {"inventor.name": o}})
    must = []
    if country:
        must.append({"match": {"inventor.residence": country}})   # discriminant principal
    else:
        must.append({"match": {"full_text": dom}})                # garde-fou si pas de pays
    payload = {"query": {"bool": {"should": should, "minimum_should_match": 1, "must": must}},
               "size": 50,
               "include": ["jurisdiction", "date_published", "biblio.invention_title", "biblio.parties",
                           "biblio.classifications_cpc", "abstract"]}
    try:
        d = _lens_post(payload)
    except Exception:
        return res
    domset = set(_norm(dom).split()) if dom else set()
    otoks = {o: set(_norm(o).split()) for o in offs}
    for p in d.get("data", []):
        b = p.get("biblio", {}) or {}
        parties = b.get("parties", {}) or {}
        names = [(x.get("extracted_name") or {}).get("value", "")
                 for x in ((parties.get("applicants") or []) + (parties.get("inventors") or []))]
        nsets = [set(_norm(n).split()) for n in names]
        title = ((b.get("invention_title") or [{}])[0].get("text")) or ""
        abs = ""
        ab = p.get("abstract")
        if isinstance(ab, list) and ab:
            abs = (ab[0] or {}).get("text", "") or ""
        in_domain = bool(domset & set(_norm(title + " " + abs).split())) if domset else False
        for o in offs:
            if otoks[o] and any(otoks[o].issubset(ns) for ns in nsets):
                slot = res.setdefault(o, {"count": 0, "in_domain": 0, "country": country, "samples": []})
                slot["count"] += 1
                if in_domain:
                    slot["in_domain"] += 1
                if len(slot["samples"]) < 3:
                    slot["samples"].append({"title": title, "year": (p.get("date_published") or "")[:4],
                                            "jurisdiction": p.get("jurisdiction"), "in_domain": in_domain})
                break
    return res

@app.get("/company-patents")
def company_patents(name: str = Query(...), officers: List[str] = Query(None),
                    domain: List[str] = Query(None), jurisdiction: str = Query(None)):
    if not LENS_KEY:
        raise HTTPException(status_code=503, detail="Clé Lens absente (LENS_KEY / clé-Lens.txt).")
    dom = " ".join(k for k in (domain or []) if k).strip()
    ck = f"{name}|{'|'.join(officers or [])}|{dom}|{jurisdiction}"
    if ck in _patent_cache:
        return _patent_cache[ck]
    try:
        company = _lens_company_patents(name)
        offs_res = _lens_officer_patents(officers, dom, jurisdiction)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Lens: {e}")
    company_c = company["count"] if company["matched"] else 0
    officer_c = sum(v["count"] for v in offs_res.values())
    officer_dom = sum(v.get("in_domain", 0) for v in offs_res.values())
    result = {"company": company, "officers": offs_res,
              "total": company_c + officer_c,
              "officer_total": officer_c,          # dirigeants (nom + pays de résidence)
              "officer_in_domain": officer_dom,    # sous-ensemble haute confiance (dans le domaine)
              "country": (jurisdiction or "").upper() or None,
              "matched": company["matched"] or officer_c > 0,
              "query": company.get("query")}
    _patent_cache[ck] = result
    return result

# --- Financement / levées de fonds (GRATUIT, multi-registres) ---------------------
# Signal unifié construit à partir des registres publics, MÊME schéma quel que soit
# le pays (share_allotments = nb d'événements de capital / émissions d'actions) :
#   - GB  : Companies House (SH01 = émissions d'actions, has_charges = dette). Batch enrich_funding_ch.py -> funding_ch.json
#   - FR+DOM : BODACC (modifs de capital) + API Recherche d'entreprises (statut, effectif).  Batch enrich_funding_fr.py -> funding_fr.json
# Les fichiers sont remplis incrémentalement : rechargement à chaud sur mtime
# (données fraîches sans redémarrer l'API).
_FUNDING_DIR = os.getenv("FUNDING_DIR", os.path.join(os.path.dirname(__file__), ".."))
_FUNDING_FILES = {
    "gb": (os.path.join(_FUNDING_DIR, "funding_ch.json"), "Companies House"),
    "fr": (os.path.join(_FUNDING_DIR, "funding_fr.json"), "BODACC + Recherche d'entreprises"),
    "no": (os.path.join(_FUNDING_DIR, "funding_no.json"), "Brønnøysundregistrene"),
    "dk": (os.path.join(_FUNDING_DIR, "funding_dk.json"), "CVR (Danemark)"),
}
_FR_JURS = {"fr", "re", "gp", "mq", "gf"}          # France métropole + DOM (SIREN INPI)
# Pays où seule la SANTÉ (statut/âge/faillite) est dispo librement — pas les levées.
_HEALTH_ONLY = {"no", "dk"}
_funding_cache = {}                                 # path -> {"mtime":..., "data":...}

def _load_funding_file(path):
    try:
        mt = os.path.getmtime(path)
    except OSError:
        return {}
    c = _funding_cache.setdefault(path, {"mtime": None, "data": {}})
    if c["mtime"] != mt:
        try:
            c["data"] = json.load(open(path, encoding="utf-8"))
            c["mtime"] = mt
        except Exception:
            pass
    return c["data"]

def _funding_key(doc, jur):
    """Clé de recherche dans le fichier financement selon le pays."""
    if jur == "gb":
        url = doc.get("results_company_registry_url") or ""
        m = re.search(r"/company/([A-Za-z0-9]+)", url)
        if m:
            return m.group(1)
        n = doc.get("results_company_company_number")
        return str(n) if n is not None else None
    num = re.sub(r"\D", "", str(doc.get("results_company_company_number") or ""))
    if jur in _FR_JURS:                             # SIREN à 9 chiffres
        return num if len(num) == 9 else None
    if jur == "no":                                 # organisasjonsnummer 9 chiffres
        return num if len(num) == 9 else None
    if jur == "dk":                                 # CVR 8 chiffres
        return num if len(num) == 8 else None
    return None

def funding_signal(f):
    """Score de crédibilité financement 0–1 (interprétable), commun à tous les pays."""
    if not f or not f.get("found"):
        return 0.0
    sa = f.get("share_allotments") or 0
    # événements capital / levées : 1 -> 0.55, 2 -> 0.73, 3 -> 0.91, 4+ -> ~1
    equity = 0.0 if sa <= 0 else min(1.0, 0.55 + 0.18 * (sa - 1))
    debt = 0.30 if f.get("has_charges") else 0.0     # dette garantie = financement obtenu (GB)
    return round(min(1.0, equity + (0 if equity == 0 else debt * 0.5) + (debt if equity == 0 else 0)), 3)

@app.get("/company-funding")
def company_funding(name: str = Query(...)):
    doc = collection.find_one(
        {"results_company_name": name},
        {"results_company_registry_url": 1, "results_company_company_number": 1,
         "results_company_jurisdiction_code": 1, "_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Société introuvable.")
    jur = doc.get("results_company_jurisdiction_code")
    file_jur = "fr" if jur in _FR_JURS else (jur if jur in _FUNDING_FILES else None)
    if not file_jur:
        return {"available": False, "jurisdiction": jur,
                "reason": "hors périmètre couvert (GB, FR/DOM, NO, DK pour l'instant)"}
    key = _funding_key(doc, jur)
    if not key:
        return {"available": False, "jurisdiction": jur, "reason": "identifiant registre manquant"}
    path, source = _FUNDING_FILES[file_jur]
    f = _load_funding_file(path).get(key)
    if f is None:
        return {"available": False, "number": key, "jurisdiction": jur,
                "source": source, "reason": "pas encore enrichi"}
    sig = funding_signal(f)
    return {"available": True, "number": key, "jurisdiction": jur, "source": source,
            "funding": f, "signal": sig,
            "equity_raises": f.get("share_allotments") or 0,
            "has_debt": bool(f.get("has_charges")),
            "last_raise": f.get("last_allotment"),
            # Santé (utile pour NO/DK où la levée n'est pas publiée) :
            "raises_tracked": f.get("raises_tracked", True),
            "status": f.get("status"),
            "has_insolvency": bool(f.get("has_insolvency"))}

# --- OpenAlex : publications propres pour un sujet (remplace les articles bruts) --
# Repris du pattern ARIZ-Copilot (openalex-papers). Gratuit ; clé optionnelle
# (Openalex_key.txt) pour éviter le délestage. Clé côté serveur uniquement.
def _load_openalex_key():
    k = os.getenv("OPENALEX_API_KEY")
    if k:
        return k.strip()
    p = os.path.join(os.path.dirname(__file__), "..", "..", "ARIZ-Copilot", "Openalex_key.txt")
    try:
        return open(p, encoding="utf-8").read().strip()
    except Exception:
        return None

OPENALEX_KEY = _load_openalex_key()
_openalex_cache = {}

def _reconstruct_abstract(inv):
    if not inv:
        return None
    words = {}
    for w, poss in inv.items():
        for p in poss:
            words[p] = w
    if not words:
        return None
    txt = " ".join(words[i] for i in sorted(words)).strip()
    return txt[:600] if len(txt) > 20 else None

@app.get("/openalex")
def openalex(keywords: List[str] = Query(None), n: int = Query(8, ge=1, le=25)):
    terms = " ".join(k for k in (keywords or []) if k).strip()
    if not terms:
        raise HTTPException(status_code=400, detail="Champ `keywords` requis.")
    ck = f"{terms}|{n}"
    if ck in _openalex_cache:
        return _openalex_cache[ck]
    params = {
        "search": terms,
        "per_page": str(n),
        "sort": "relevance_score:desc",
        "select": "title,publication_year,doi,cited_by_count,primary_location,authorships,abstract_inverted_index,open_access,id",
        "mailto": "hivescan-poc@insa-strasbourg.fr",
    }
    if OPENALEX_KEY:
        params["api_key"] = OPENALEX_KEY
    url = "https://api.openalex.org/works?" + urllib.parse.urlencode(params)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "hivescan-poc (insa-strasbourg)"})
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.load(r)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"OpenAlex: {e}")
    papers = []
    for w in data.get("results", []):
        doi = (w.get("doi") or "").replace("https://doi.org/", "") or None
        loc = w.get("primary_location") or {}
        papers.append({
            "title": w.get("title") or "",
            "authors": [a.get("author", {}).get("display_name") for a in (w.get("authorships") or [])][:4],
            "year": w.get("publication_year"),
            "venue": (loc.get("source") or {}).get("display_name"),
            "citations": w.get("cited_by_count"),
            "url": (w.get("open_access") or {}).get("oa_url") or (f"https://doi.org/{doi}" if doi else w.get("id")),
            "abstract": _reconstruct_abstract(w.get("abstract_inverted_index")),
        })
    result = {"papers": [p for p in papers if p["title"]]}
    _openalex_cache[ck] = result
    return result

# --- Publications des DIRIGEANTS via OpenAlex, avec désambiguïsation homonymes ---
# Méthode thèse §7.4.2 : requête par nom de dirigeant + FILTRE DE PERTINENCE AU
# DOMAINE (réduit ~50% des faux positifs type « John Smith »). Amélioration : on
# ajoute le PAYS d'affiliation (OpenAlex, contrairement à Semantic Scholar dont le
# champ affiliation était vide à 99% — cf. thèse §10.2.x).
_officer_cache = {}

def _openalex_works(params):
    if OPENALEX_KEY:
        params["api_key"] = OPENALEX_KEY
    params.setdefault("mailto", "hivescan-poc@insa-strasbourg.fr")
    url = "https://api.openalex.org/works?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"User-Agent": "hivescan-poc (insa-strasbourg)"})
    with urllib.request.urlopen(req, timeout=25) as r:
        return json.load(r)

def _paper_from_work(w, officer=None):
    doi = (w.get("doi") or "").replace("https://doi.org/", "") or None
    loc = w.get("primary_location") or {}
    return {
        "officer": officer,
        "title": w.get("title") or "",
        "authors": [a.get("author", {}).get("display_name") for a in (w.get("authorships") or [])][:4],
        "year": w.get("publication_year"),
        "venue": (loc.get("source") or {}).get("display_name"),
        "citations": w.get("cited_by_count"),
        "url": (w.get("open_access") or {}).get("oa_url") or (f"https://doi.org/{doi}" if doi else w.get("id")),
        "abstract": _reconstruct_abstract(w.get("abstract_inverted_index")),
        "doi": doi,
    }

@app.get("/officer-pubs")
def officer_pubs(officers: List[str] = Query(None), domain: List[str] = Query(None),
                 jurisdiction: str = Query(None), per: int = Query(4, ge=1, le=8)):
    names = list(dict.fromkeys([o.strip() for o in (officers or []) if o and o.strip()]))[:4]
    dom = " ".join(k for k in (domain or []) if k).strip()
    if not names:
        raise HTTPException(status_code=400, detail="Champ `officers` requis.")
    ck = f"{'|'.join(names)}|{dom}|{jurisdiction}"
    if ck in _officer_cache:
        return _officer_cache[ck]

    out, seen, resolved = [], set(), {}
    domterms = [t for t in re.findall(r"[a-zàâäéèêëïîôöùûüç]{4,}", dom.lower())] if dom else []
    for name in names:
        _nt = _norm(name).split()
        if len(_nt) < 2:
            continue
        # Ordre nom/prénom inconnu (OpenCorporates : « NOM Prénom » OU « Prénom NOM »)
        # → on teste les deux sens.
        cand = [(_nt[0], _nt[-1]), (_nt[-1], _nt[0])]  # (prénom, nom)
        filt = [f"raw_author_name.search:{name}"]
        if jurisdiction:
            filt.append(f"authorships.countries:{jurisdiction.upper()}")
        # TOUTES les publis du nom (pas que le domaine). Tri par PERTINENCE du nom
        # (défaut OpenAlex) et non par citations : sinon des homonymes très cités
        # (ex. Lefèvre médecins) enterrent la bonne personne (Laurent Lefèvre).
        try:
            got = _openalex_works({
                "per_page": "50", "filter": ",".join(filt),
                "select": "title,publication_year,doi,cited_by_count,primary_location,authorships,abstract_inverted_index,open_access,id",
            }).get("results", [])
        except Exception:
            got = []

        # Regroupe par PERSONNE (author_id), en marquant chaque work domaine/hors-domaine.
        clusters = {}
        for w in got:
            if not w.get("title"):
                continue
            hay = ((w.get("title") or "") + " " +
                   (_reconstruct_abstract(w.get("abstract_inverted_index")) or "")).lower()
            is_dom = (not domterms) or any(t in hay for t in domterms)
            for a in (w.get("authorships") or []):
                au = a.get("author") or {}
                at = _norm(au.get("display_name")).split()
                # Précis : même NOM + prénom (complet ou initiale), dans un des 2 ordres.
                if len(at) >= 2 and any(
                        at[-1] == last and (at[0] == first or (len(at[0]) == 1 and at[0] == first[:1])
                                            or (len(first) == 1 and first == at[0][:1]))
                        for first, last in cand):
                    aid = au.get("id") or " ".join(at)
                    c = clusters.setdefault(aid, {"name": au.get("display_name"), "works": []})
                    c["works"].append((_paper_from_work(w, officer=name), is_dom))
                    break
        if not clusters:
            continue
        # Choix de la personne : priorité au cluster ayant des publis DANS le domaine,
        # sinon au plus fourni (tie-break citations).
        def _cscore(k):
            ws = clusters[k]["works"]
            return (sum(1 for _, d in ws if d), len(ws),
                    sum((p.get("citations") or 0) for p, _ in ws))
        best_id = max(clusters, key=_cscore)
        best = clusters[best_id]
        nd = sum(1 for _, d in best["works"] if d)
        total_all = sum(len(v["works"]) for v in clusters.values())
        dominant = len(best["works"]) >= max(2, 0.5 * total_all) and len(clusters) <= 3
        # Affiché seulement si : match domaine (fiable) OU nom nettement identifiable.
        # Sinon (nom commun ambigu ET hors domaine) → rien de fiable.
        if nd == 0 and not dominant:
            continue
        resolved[name] = {"author": best["name"], "author_id": best_id,
                          "n_candidates": len(clusters), "in_domain": nd > 0}
        ws_sorted = sorted(best["works"], key=lambda x: (x[1], x[0].get("citations") or 0), reverse=True)
        for p, is_dom in ws_sorted[:4]:
            key = p["doi"] or p["title"][:60].lower()
            if key in seen:
                continue
            seen.add(key)
            p["resolved_author"] = best["name"]
            p["author_id"] = best_id
            p["in_domain"] = is_dom
            out.append(p)

    out.sort(key=lambda p: (p.get("in_domain", False), p.get("citations") or 0), reverse=True)
    result = {"papers": out[:12], "officers": names, "domain": dom, "resolved": resolved}
    _officer_cache[ck] = result
    return result

@app.get("/search", response_model=Page[dict])
def search(
    company: Optional[str] = Query(None, description="Company name to search for"),
    founder: Optional[str] = Query(None, description="Founder name to search for"),
    keywords: Optional[List[str]] = Query(None, description="Keyword to search inside possible_triz_levels.title/abstract"),
    jurisdiction: Optional[str] = Query(None, description="Filter by jurisdiction"),
    topic_id: Optional[int] = Query(None, description="Topic number to return, percentage in descending order"),
    sort: Optional[str] = Query(None, description="Sort by field and order, e.g. citations:asc or year:desc"),
    innovation_min: Optional[float] = Query(None, ge=0.0, le=1.0, description="Minimum innovation index (0–1)"),
    innovation_max: Optional[float] = Query(None, ge=0.0, le=1.0, description="Maximum innovation index (0–1)"),
    
):
    """
    Search documents. Title/abstract are inside possible_triz_levels (an array of subdocs).
    
    Search documents in MongoDB.

    - name: match company or author name
    - keywords: list of keywords to search inside possible_triz_levels.title/abstract
    - jurisdiction: comma-separated country codes
    - sort: e.g. &sort=citations:desc or &sort=year:asc
    
    """

    filters = []

    def regex_obj(s: str):
        return {"$regex": re.escape(s.strip()), "$options": "i"}
    
    def topic_number_extraction(companies, topic_id):
        matches = []
        
        for company in companies:
            for paper in company["possible_triz_levels"]:
                for topic, prob in paper.get("top_3_topic_probs", []):
                    if topic == topic_id:
                        matches.append({
                            "company": company["results_company_name"],
                            "paperId": paper["paperId"],
                            "title": paper["title"],
                            "abstract":paper["abstract"],
                            "ner":paper["ner"],
                            "topic_id": topic,
                            "score": prob,
                            "year": paper.get("year"),
                        })

        return matches
    
    if company:
        filters.append({"results_company_name": regex_obj(company)})
    
    if founder:
        filters.append({"officer_list": regex_obj(founder)})
    
    if jurisdiction:
        # allow multiple jurisdictions, separated by commas
        countries = [j.strip().lower() for j in jurisdiction.split(",") if j.strip()]
        if countries:
            filters.append({"results_company_jurisdiction_code": {"$in": countries}})

        
        
    if keywords:
        # if multiple keywords, match if *any* keyword appears in title OR abstract
        keyword_filters = []
    
        for kw in keywords:
            kwr = regex_obj(kw)
            keyword_filters.append({"possible_triz_levels.title": kwr})
            keyword_filters.append({"possible_triz_levels.abstract": kwr})
        filters.append({"$or": keyword_filters})
        


    if innovation_min is not None or innovation_max is not None:
        innovation_filter = {}
        if innovation_min is not None:
            innovation_filter["$gte"] = innovation_min
        if innovation_max is not None:
            innovation_filter["$lte"] = innovation_max
        filters.append({"innovation_index": innovation_filter})

    mongo_query = {"$and": filters} if filters else {}

    # Classement + borne mémoire, en DEUX temps (Atlas M0 : tri bloquant limité à
    # 32 Mo, sans allowDiskUse -> impossible de trier des documents lourds).
    #   1) requête LÉGÈRE projetée (nom + champ de tri) -> tri + limite peu coûteux.
    #   2) on ne charge les documents COMPLETS que pour les MAX_SEARCH_DOCS meilleurs.
    if sort:
        try:
            field, direction = sort.split(":")
            order = 1 if direction.lower().strip() == "asc" else -1
        except ValueError:
            raise HTTPException(status_code=400,
                                detail="Invalid sort format. Use field:asc or field:desc")
        rank_field = field
    else:
        rank_field, order = "innovation_index", -1

    ranked = list(collection.aggregate([
        {"$match": mongo_query},
        {"$project": {"_id": 0, "results_company_name": 1, rank_field: 1}},
        {"$sort": {rank_field: order}},
        {"$limit": MAX_SEARCH_DOCS},
    ]))
    names = [r.get("results_company_name") for r in ranked if r.get("results_company_name")]
    if not names:
        raise HTTPException(status_code=404, detail="No documents matched your query")

    full_by_name = {d["results_company_name"]: d
                    for d in collection.find({"results_company_name": {"$in": names}}, {"_id": 0})}
    # On respecte l'ordre du classement (phase 1).
    results = [full_by_name[n] for n in names if n in full_by_name]
    
    #!!!!!!!!!!!!!!!!!!!!!!!
    #rebuild and test if this only gets the corresponding articles
    
    #need to add a way to add asc et desc to filter for articles
    if keywords:
        try:
            # Compile les regex une fois (mêmes règles que le $match Mongo).
            regex_list = [re.compile(re.escape(kw), re.IGNORECASE) for kw in keywords]

            filtered_results = []
            for doc in results:
                # On ne garde QUE les articles qui matchent réellement le(s) mot(s)-clé(s).
                matching = []
                for lvl in doc.get("possible_triz_levels", []):
                    title = lvl.get("title") or ""
                    abstract = lvl.get("abstract") or ""
                    if any(r.search(title) or r.search(abstract) for r in regex_list):
                        matching.append(lvl)

                if matching:
                    # Tri des articles pertinents par citations décroissantes.
                    matching.sort(key=lambda l: l.get("citationCount") or 0, reverse=True)
                    # On conserve tout le document entreprise (juridiction, innovation_index, …)
                    # mais on remplace ses articles par les seuls articles pertinents.
                    doc["possible_triz_levels"] = matching
                    doc["matched_article_count"] = len(matching)
                    filtered_results.append(doc)

            # >>> LE FIX : on renvoie bien les résultats filtrés (avant, cette ligne
            #     était commentée, donc l'API renvoyait tous les articles).
            #     Le classement des entreprises est fait plus bas (par innovation_index).
            results = filtered_results

        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    # --- Enrichissement + classement par potentiel d'innovation ------------------
    if topic_id is None:
        for doc in results:
            # Radar 5 dimensions (avant nettoyage NaN : utilise l'effectif/âge bruts).
            doc["radar"] = company_radar(doc)
            # NaN -> None pour un JSON propre (ex. employee_count manquant).
            ec = doc.get("employee_count")
            if isinstance(ec, float) and ec != ec:
                doc["employee_count"] = None
            # Décomposition du score (traçabilité).
            doc["score_breakdown"] = score_breakdown(doc)
        # Classement par défaut = innovation_index décroissant (cœur de HiveScan).
        # Si l'utilisateur a demandé un `sort` explicite, on respecte l'ordre Mongo.
        if not sort:
            results.sort(key=lambda d: d.get("innovation_index") or 0, reverse=True)

    if topic_id is not None:
        
        matches = topic_number_extraction(results, topic_id)
        matches.sort(key=lambda x: x["score"], reverse=True)
        return paginate(matches)
    
    if not results: 
        raise HTTPException(status_code=404, detail="No documents matched your query")
    
    return paginate(results)



#jurisdiction seems to work, but need to use only as a filter
#also add a .lower

#need to add real DB online - but currently offline

#need to sort AFTER getting filtered_results