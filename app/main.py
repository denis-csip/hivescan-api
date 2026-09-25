from fastapi import FastAPI, Query, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi_pagination import Page, add_pagination, paginate
from pymongo import MongoClient
from typing import Optional, List
import re
import os
import json
import time
import hmac
import hashlib
import base64
import uuid
import datetime
import unicodedata
import urllib.request
import urllib.parse

app = FastAPI()
add_pagination(app)

def _cache_put(cache, key, val, cap=2000):
    """Caches mémoire bornés : au-delà de `cap` entrées on repart à vide (simple et
    suffisant pour un POC — évite la fuite mémoire sur un dyno longue durée)."""
    if len(cache) >= cap:
        cache.clear()
    cache[key] = val
    return val

# --- Authentification (défini AVANT le CORS pour que les 401 aient les en-têtes CORS) ---
# Deux mécanismes, activables par variables d'env :
#   • Login IDEAS (comme ARIZ-Copilot) : SESSION_SECRET défini -> l'endpoint
#     /ideas-login valide les identifiants IDEAS (API GraphQL) et émet un JETON
#     de session signé (HMAC, sans état). Le client le renvoie en Bearer.
#   • Clé partagée simple : ACCESS_KEY défini -> header X-Access-Key ou ?key=.
# Si AUCUN des deux n'est défini (dev local) -> aucune restriction.
ACCESS_KEY = os.getenv("ACCESS_KEY")
SESSION_SECRET = os.getenv("SESSION_SECRET")
# Admins (allowlist d'emails) : peuvent éditer la formule d'idéalité. Denis par défaut.
ADMIN_EMAILS = {e.strip().lower() for e in os.getenv(
    "ADMIN_EMAILS", "denis.cavallucci@insa-strasbourg.fr").split(",") if e.strip()}
def _is_admin(email):
    return bool(email) and email.strip().lower() in ADMIN_EMAILS
IDEAS_APP = os.getenv("IDEAS_APP", "ARIZ-Copilot")               # x-application accepté par IDEAS
IDEAS_ENDPOINT = os.getenv("IDEAS_ENDPOINT", "https://ideas.aiard.eu/api")
_AUTH_REQUIRED = bool(ACCESS_KEY or SESSION_SECRET)
_OPEN_PATHS = {"/", "/docs", "/openapi.json", "/redoc", "/ideas-login", "/auth-status",
               "/funding-coverage", "/domains", "/domain-meta"}

def _b64u(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")

def _b64u_dec(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def _make_token(email, admin=False, days=7):
    payload = _b64u(json.dumps({"email": email, "admin": bool(admin),
                                "exp": int(time.time()) + days * 86400}).encode())
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
                '{ id name email token job avatar organizations { id name } } }'
                % (esc(email), esc(password)))
    body = json.dumps({"query": mutation}).encode()
    req = urllib.request.Request(
        IDEAS_ENDPOINT, data=body, method="POST",
        # Le User-Agent par défaut « Python-urllib » est BLOQUÉ (403) par la protection
        # anti-robots Cloudflare d'IDEAS (depuis sept. 2026). Tout autre UA passe.
        headers={"Content-Type": "application/json", "x-application": IDEAS_APP,
                 "User-Agent": "hivescan/1.0 (+https://hivescan.net)", "Accept": "application/json"})
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
def auth_status(request: Request):
    """Le POC interroge cet endpoint (ouvert) pour savoir s'il doit afficher le login.
    Lit le jeton (optionnel) pour indiquer si l'utilisateur est admin."""
    auth = request.headers.get("authorization") or ""
    tok = auth[7:] if auth[:7].lower() == "bearer " else None
    data = _verify_token(tok) if tok else None
    is_admin = bool(data and (data.get("admin") or _is_admin(data.get("email"))))
    return {"login_required": _AUTH_REQUIRED, "ideas": bool(SESSION_SECRET),
            "storage_ready": studies_col is not None, "is_admin": is_admin}

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
    orgs = [o.get("name") for o in (u.get("organizations") or []) if o.get("name")]
    mail = u.get("email") or email
    admin = _is_admin(mail)
    return {"token": _make_token(mail, admin),
            "name": u.get("name"), "email": mail, "is_admin": admin,
            "avatar": u.get("avatar"), "job": u.get("job"), "organizations": orgs}

# --- Études sauvegardées par utilisateur (persistance façon ARIZ-Copilot) ----------
# Chaque étude = une recherche sauvegardée (mots-clés + filtres), rattachée à l'email
# IDEAS. Écriture via la connexion RW (studies_col). Le user est identifié par son jeton.
def _current_email(request: Request):
    auth = request.headers.get("authorization") or ""
    tok = auth[7:] if auth[:7].lower() == "bearer " else None
    return (_verify_token(tok) or {}).get("email") if tok else None

def _study_public(d):
    return {"id": d.get("sid"), "name": d.get("name"), "query": d.get("query") or [],
            "jurisdiction": d.get("jurisdiction"), "innovation_min": d.get("innovation_min"),
            "result_count": d.get("result_count"), "category_id": d.get("category_id"),
            "domain": d.get("domain"), "position": d.get("position", 0),
            "has_results": bool(d.get("results")),
            "created": d.get("created"), "updated": d.get("updated")}

@app.get("/studies")
def list_studies(request: Request):
    email = _current_email(request)
    if not email or studies_col is None:
        return {"studies": [], "storage": studies_col is not None}
    docs = list(studies_col.find({"email": email}, {"_id": 0}).sort("position", 1).limit(300))
    return {"studies": [_study_public(d) for d in docs], "storage": True}

@app.post("/studies")
async def save_study(request: Request):
    email = _current_email(request)
    if not email:
        raise HTTPException(status_code=401, detail="Non authentifié.")
    if studies_col is None:
        raise HTTPException(status_code=503, detail="Stockage des études non configuré (MONGO_URI_RW).")
    body = await request.json()
    q = body.get("query") or []
    if isinstance(q, str):
        q = [q]
    now = datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"
    doc = {"sid": uuid.uuid4().hex, "email": email,
           "name": (body.get("name") or " ".join(q) or "Étude").strip()[:120],
           "query": [str(k) for k in q][:12],
           "jurisdiction": body.get("jurisdiction"),
           "innovation_min": body.get("innovation_min"),
           "result_count": body.get("result_count"),
           "category_id": body.get("category_id"),
           "domain": body.get("domain"),
           "position": -time.time(),     # nouveau = en tête (tri par position ascendant)
           "created": now, "updated": now}
    # Snapshot des résultats (pour consultation instantanée sans re-run) — borné à
    # 60 entreprises + garde-fou taille (limite doc Mongo 16 Mo).
    results = body.get("results")
    if isinstance(results, list) and results:
        snap = results[:60]
        try:
            if len(json.dumps(snap)) < 9_000_000:
                doc["results"] = snap
        except Exception:
            pass
    studies_col.insert_one(dict(doc))
    return _study_public(doc)

@app.get("/studies/{sid}")
def get_study(sid: str, request: Request):
    email = _current_email(request)
    if not email or studies_col is None:
        raise HTTPException(status_code=401, detail="Non autorisé.")
    d = studies_col.find_one({"sid": sid, "email": email}, {"_id": 0})
    if not d:
        raise HTTPException(status_code=404, detail="Étude introuvable.")
    out = _study_public(d)
    out["results"] = d.get("results")     # snapshot complet (peut être None)
    return out

@app.patch("/studies/{sid}")
async def update_study(sid: str, request: Request):
    email = _current_email(request)
    if not email or studies_col is None:
        raise HTTPException(status_code=401, detail="Non autorisé.")
    body = await request.json()
    patch = {}
    if "name" in body:
        patch["name"] = ((body.get("name") or "").strip()[:120]) or "Étude"
    if "category_id" in body:
        patch["category_id"] = body.get("category_id")
    if "position" in body:
        try:
            patch["position"] = float(body.get("position"))
        except (TypeError, ValueError):
            pass
    if patch:
        patch["updated"] = datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"
        studies_col.update_one({"sid": sid, "email": email}, {"$set": patch})
    return {"ok": True, "id": sid}

@app.delete("/studies/{sid}")
def delete_study(sid: str, request: Request):
    email = _current_email(request)
    if not email:
        raise HTTPException(status_code=401, detail="Non authentifié.")
    if studies_col is not None:
        studies_col.delete_one({"sid": sid, "email": email})
    return {"deleted": sid}

# --- Dossiers / catégories d'études (par utilisateur, façon ARIZ-Copilot) ----------
def _cat_public(d):
    return {"id": d.get("cid"), "name": d.get("name"), "color": d.get("color") or "blue",
            "position": d.get("position", 0)}

@app.get("/categories")
def list_categories(request: Request):
    email = _current_email(request)
    if not email or categories_col is None:
        return {"categories": []}
    docs = list(categories_col.find({"email": email}, {"_id": 0}).sort("position", 1).limit(60))
    return {"categories": [_cat_public(d) for d in docs]}

@app.post("/categories")
async def create_category(request: Request):
    email = _current_email(request)
    if not email or categories_col is None:
        raise HTTPException(status_code=503, detail="Stockage non configuré (MONGO_URI_RW).")
    body = await request.json()
    doc = {"cid": uuid.uuid4().hex, "email": email,
           "name": (body.get("name") or "Dossier").strip()[:60],
           "color": body.get("color") or "blue", "position": time.time()}
    categories_col.insert_one(dict(doc))
    return _cat_public(doc)

@app.patch("/categories/{cid}")
async def update_category(cid: str, request: Request):
    email = _current_email(request)
    if not email or categories_col is None:
        raise HTTPException(status_code=401, detail="Non autorisé.")
    body = await request.json()
    patch = {}
    if "name" in body:
        patch["name"] = ((body.get("name") or "").strip()[:60]) or "Dossier"
    if "color" in body:
        patch["color"] = body.get("color")
    if "position" in body:
        try:
            patch["position"] = float(body.get("position"))
        except (TypeError, ValueError):
            pass
    if patch:
        categories_col.update_one({"cid": cid, "email": email}, {"$set": patch})
    return {"ok": True, "id": cid}

@app.delete("/categories/{cid}")
def delete_category(cid: str, request: Request):
    email = _current_email(request)
    if not email:
        raise HTTPException(status_code=401, detail="Non authentifié.")
    if categories_col is not None:
        categories_col.delete_one({"cid": cid, "email": email})
        if studies_col is not None:      # les études du dossier repassent « sans dossier »
            studies_col.update_many({"email": email, "category_id": cid}, {"$set": {"category_id": None}})
    return {"deleted": cid}

# --- CORS : ajouté EN DERNIER = middleware le plus EXTERNE, pour que ses en-têtes
# s'appliquent AUSSI aux réponses 401 du gate (sinon le navigateur bloque la lecture
# de la réponse). En prod, définir ALLOWED_ORIGINS = le(s) domaine(s) du POC.
_origins_env = os.getenv("ALLOWED_ORIGINS", "*").strip()
_allow_origins = ["*"] if _origins_env == "*" else [o.strip() for o in _origins_env.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allow_origins,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],   # POST=login, PATCH/DELETE=études/dossiers
    allow_headers=["*"],
)

# Secrets : variable d'environnement (prod) ; sinon coffre local HORS OneDrive (dev).
# Aucun secret en dur dans le code, aucun fichier de clé dans un dossier synchronisé.
VAULT_FILE = os.environ.get("CLAUDE_SECRETS_FILE") or os.path.join(
    os.path.expanduser("~"), ".secrets", "claude.env")
_vault_cache = None


def _vault_get(name):
    """Valeur lue dans le coffre local (fichier de lignes « NAME=valeur »), ou None."""
    global _vault_cache
    if _vault_cache is None:
        _vault_cache = {}
        if os.path.exists(VAULT_FILE):
            with open(VAULT_FILE, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, _, v = line.partition("=")
                    _vault_cache[k.strip()] = v.strip()
    return _vault_cache.get(name) or None


def _load_mongo_uri():
    u = (os.getenv("MONGO_URI") or "").strip() or _vault_get("MONGO_URI")
    if u:
        return u
    raise RuntimeError("MONGO_URI absent : définir la variable d'env MONGO_URI, "
                       f"ou ajouter « MONGO_URI=... » dans {VAULT_FILE}.")

MONGO_URI = _load_mongo_uri()
DB_NAME = os.getenv("MONGO_DB", "hivescan_data")
COLLECTION_NAME = os.getenv("MONGO_COLLECTION", "data")
# Borne mémoire de /search : nb max de documents complets chargés (évite l'OOM en
# prod quand un mot-clé large matche des milliers d'entreprises). Configurable.
MAX_SEARCH_DOCS = int(os.getenv("MAX_SEARCH_DOCS", "500"))
# Articles gardés PAR ENTREPRISE dans /search (les plus cités). Charger tous les articles
# de 500 entreprises = ~110 Mo BSON (52k articles) -> OOM sur le dyno 512 Mo. Plafonner +
# projeter (sans abstract/authors, les gros champs) ramène à ~3,5 Mo. On garde tous les
# petits champs affichés par le POC : ner, fieldsOfStudy, score TRIZ, revue, lien PDF.
ARTICLES_PER_COMPANY = int(os.getenv("ARTICLES_PER_COMPANY", "25"))

client = MongoClient(MONGO_URI)
db = client[DB_NAME]
collection = db[COLLECTION_NAME]

# Connexion LECTURE-ÉCRITURE dédiée aux ÉTUDES utilisateur (le user principal de
# l'API est en lecture seule). MONGO_URI_RW = chaîne d'un utilisateur RW ; si absent,
# la fonctionnalité « études » est désactivée proprement (le POC bascule en local).
_MONGO_URI_RW = os.getenv("MONGO_URI_RW")
studies_col = None
categories_col = None
config_col = None
if _MONGO_URI_RW:
    try:
        _rwdb = MongoClient(_MONGO_URI_RW)[DB_NAME]
        studies_col = _rwdb["hivescan_studies"]; studies_col.create_index("email")
        categories_col = _rwdb["hivescan_categories"]; categories_col.create_index("email")
        config_col = _rwdb["hivescan_config"]     # ex. formule d'idéalité (par domaine)
    except Exception:
        studies_col = None; categories_col = None; config_col = None

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

def _json_safe(o):
    # Les docs Mongo (et les fichiers d'enrichissement) peuvent contenir des NaN
    # (dissolution_date, branch, number_of_employees…). Starlette sérialise avec
    # allow_nan=False -> ValueError -> 500 SANS en-têtes CORS (« NetworkError » côté
    # navigateur). Tout endpoint qui renvoie un dict brut de docs doit passer par ici.
    # (/search y échappe via paginate/pydantic.)
    if isinstance(o, float):
        return None if (o != o or o == float("inf") or o == float("-inf")) else o
    if isinstance(o, dict):
        return {k: _json_safe(v) for k, v in o.items()}
    if isinstance(o, list):
        return [_json_safe(v) for v in o]
    return o

def _feature_maxes(coll):
    """Max de chaque feature sur une collection (normalisation propre au domaine)."""
    maxes = {}
    for f in SCORE_FEATURES:
        d = coll.find_one({f: {"$gt": 0}}, sort=[(f, -1)], projection={f: 1})
        m = (d or {}).get(f)
        maxes[f] = m if (_is_num(m) and m > 0) else 1.0
    return maxes

def score_breakdown(doc, fmax):
    """Contribution normalisée (0–1) de chaque feature, vs le max du DOMAINE."""
    out = {}
    for f, label in SCORE_FEATURES.items():
        v = doc.get(f)
        if _is_num(v) and v > 0:
            out[label] = round(min(v / (fmax.get(f, 1) or 1), 1.0), 3)
    return out

# --- Radar : 5 dimensions (catégories thèse Ch. 8) pour le profil d'innovation ---
def _feature_avgs(coll):
    avgs = {}
    for f in SCORE_FEATURES:
        r = list(coll.aggregate(
            [{"$match": {f: {"$gt": 0}}}, {"$group": {"_id": None, "a": {"$avg": f"${f}"}}}]))
        avgs[f] = (r[0]["a"] if r else 0) or 0
    return avgs

# axe -> (libellé, feature source)
RADAR_AXES = [
    ("solving", "Problème-solving", "average_triz_score"),
    ("impact", "Impact", "citations_per_article"),
    ("production", "Production", "number_of_publications"),
    ("human", "Capital humain", "ratio_publishing_officers"),
    ("context", "Contexte", "employee_count"),
]

def _axis_value(feat, raw, fmax, age_days=None):
    # Contexte : effectif si dispo, sinon proxy « jeunesse startup » via l'âge.
    if feat == "employee_count" and not (_is_num(raw) and raw > 0):
        if _is_num(age_days) and age_days > 0:
            return round(max(0.1, min(1.0, 1 - (age_days / 365) / 15)), 3)
        return 0.3
    if not (_is_num(raw) and raw > 0):
        return 0.0
    return round(min(raw / (fmax.get(feat, 1) or 1), 1.0), 3)

def company_radar(doc, fmax):
    ak = next((k for k in doc if k.startswith("age_in_days")), None)
    age = doc.get(ak) if ak else None
    return [{"key": k, "label": lbl, "value": _axis_value(feat, doc.get(feat), fmax, age)}
            for k, lbl, feat in RADAR_AXES]

def _population_radar(favg, fmax):
    out = []
    for k, lbl, feat in RADAR_AXES:
        v = round(min((favg.get(feat, 0) or 0) / (fmax.get(feat, 1) or 1), 1.0), 3)
        if feat == "employee_count" and v == 0:
            v = 0.3
        out.append({"key": k, "label": lbl, "value": v})
    return out

# === Domaines disciplinaires : un jeu de startups (= une collection) par domaine ===
# Énergie = collection actuelle (thèse Connor, sponsor EDF). Les autres domaines se
# peuplent en important un nouveau bundle OpenCorporates comme collection dédiée ;
# ils apparaissent « à venir » tant qu'ils sont vides.
DOMAINS = {
    "energy":     {"label": "Énergie",     "collection": COLLECTION_NAME},
    "cosmetics":  {"label": "Cosmétique",  "collection": "data_cosmetics"},
    "metallurgy": {"label": "Métallurgie", "collection": "data_metallurgy"},
    "biotech":    {"label": "Biotech",     "collection": "data_biotech"},
    "plastics":   {"label": "Plasturgie",  "collection": "data_plastics"},
    "railway":    {"label": "Ferroviaire", "collection": "data_railway"},
    "packaging":  {"label": "Packaging",   "collection": "data_packaging"},
}
DEFAULT_DOMAIN = os.getenv("DEFAULT_DOMAIN", "energy")
_domain_cache = {}

def _domain_ctx(domain):
    """Contexte d'un domaine (collection + normalisation propre), calculé une fois."""
    dom = domain if domain in DOMAINS else DEFAULT_DOMAIN
    if dom not in _domain_cache:
        coll = db[DOMAINS[dom]["collection"]]
        fmax = _feature_maxes(coll)
        favg = _feature_avgs(coll)
        _domain_cache[dom] = {"domain": dom, "coll": coll, "fmax": fmax, "favg": favg,
                              "pop": _population_radar(favg, fmax)}
    return _domain_cache[dom]

_domain_ctx(DEFAULT_DOMAIN)               # pré-chauffe le domaine par défaut au démarrage

# --- Libellés de topics = Table 9.9 « Chosen Topics » de la thèse (Human-in-the-Loop
#     LLM Labeling, §9.2.6). Thèse indexée 1..30 ; notre base 0..29 → label[id]=Table9.9[id+1].
#     Alignement vérifié sur les titres représentatifs (topics 1/5/27).
TOPIC_LABELS = {
    0: "General research approaches, modeling, and structural efficiency analysis",
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
    26: "Signal detection and satellite-based observational instrumentation investigations",
    27: "Diverse topics: workshops, colliders, and multilingual case studies",
    28: "General scientific synthesis and comparison",
    29: "Plant chemistry and environmental monitoring",
}

@app.get("/")
def root():
    # Healthcheck + marqueur de build (le POC consomme /domain-meta, plus cette racine).
    return {"message": "Search API is running", "build": "oa-nav-1", "lens": bool(LENS_KEY),
            "openalex": bool(OPENALEX_KEY)}

@app.get("/domains")
def list_domains():
    """Domaines disciplinaires disponibles (ouvert) — le POC peuple son sélecteur."""
    out = []
    for did, meta in DOMAINS.items():
        try:
            n = db[meta["collection"]].estimated_document_count()
        except Exception:
            n = 0
        out.append({"id": did, "label": meta["label"], "count": n, "populated": n > 0})
    return {"domains": out, "default": DEFAULT_DOMAIN}

# --- Topics PAR DOMAINE : libellés + mots caractéristiques (SN-grams les plus probables du
#     topic dans le modèle ETM), écrits par hivescan-ingest/topics.py dans `hivescan_topic_models`.
#     Chaque domaine a SON modèle : les 30 topics de l'énergie ne décrivent pas le biotech.
#     Repli : l'énergie garde la Table 9.9 en dur si la collection est vide ; les autres, rien.
TOPIC_MODELS_COLL = "hivescan_topic_models"

def _topic_meta(domain):
    ctx = _domain_ctx(domain)
    if "topics" not in ctx:
        doc = None
        try:
            doc = db[TOPIC_MODELS_COLL].find_one({"domain": ctx["domain"]}, {"_id": 0})
        except Exception:
            pass
        doc = doc or {}
        labels = {int(k): v for k, v in (doc.get("labels") or {}).items() if v}
        if not labels and ctx["domain"] == "energy":
            labels = TOPIC_LABELS
        words = {int(k): [w for w in (v or [])][:10] for k, v in (doc.get("top_words") or {}).items()}
        # Vue d'ensemble (hivescan-ingest/topicmap.py) : taille, dynamique, concepts phares par topic.
        ctx["topics"] = {"labels": labels, "words": words, "overview": doc.get("overview") or [],
                         "overview_years": doc.get("overview_years"), "overview_windows": doc.get("overview_windows")}
    return ctx["topics"]

@app.get("/domain-meta")
def domain_meta(domain: str = Query(None)):
    """Normalisation + libellés et mots-clés des topics propres au domaine choisi (radar population)."""
    ctx = _domain_ctx(domain)
    tm = _topic_meta(domain)
    return {"domain": ctx["domain"], "pop_radar": ctx["pop"], "feature_max": ctx["fmax"],
            "topic_labels": tm["labels"], "topic_words": tm["words"], "topic_overview": tm["overview"],
            "overview_years": tm["overview_years"], "overview_windows": tm["overview_windows"]}

# --- Inventive Confidence Index (ICI) : 7 sous-indices, éditable par l'admin --------
# Uniquement des signaux publics/objectifs/reproductibles (cf. thèse Connor). Chaque
# sous-indice est normalisé 0–1 (affiché 0–100). ICI = moyenne pondérée des termes
# DISPONIBLES ; un terme peut passer en dénominateur (pénalité). Poids par défaut =
# priorité à la solidité inventive (PS/SP/HC/PP) sur les validations externes (IM/FP/EC).
DEFAULT_IDEALITY = {"terms": [
    {"key": "solving",    "code": "PS", "label": "Problem Solving",        "side": "num", "coef": 30},
    {"key": "production", "code": "SP", "label": "Scientific Production",   "side": "num", "coef": 20},
    {"key": "human",      "code": "HC", "label": "Human Capital",          "side": "num", "coef": 15},
    {"key": "patents",    "code": "PP", "label": "Patent Performance",     "side": "num", "coef": 15},
    {"key": "impact",     "code": "IM", "label": "Impact",                 "side": "num", "coef": 10},
    {"key": "funding",    "code": "FP", "label": "Funding Performance",    "side": "num", "coef": 5},
    {"key": "context",    "code": "EC", "label": "Ecosystem Context",      "side": "num", "coef": 5},
]}

def _current_admin(request: Request):
    auth = request.headers.get("authorization") or ""
    tok = auth[7:] if auth[:7].lower() == "bearer " else None
    data = _verify_token(tok) if tok else None
    if not data:
        return False
    # admin si le claim est présent OU si l'email est dans l'allowlist (sessions
    # ouvertes avant l'ajout du claim -> pas besoin de se reconnecter).
    return bool(data.get("admin")) or _is_admin(data.get("email"))

@app.get("/ideality")
def get_ideality(domain: str = Query(None)):
    dom = domain if domain in DOMAINS else DEFAULT_DOMAIN
    if config_col is not None:
        d = config_col.find_one({"_id": f"ideality:{dom}"}, {"_id": 0})
        if d and d.get("terms"):
            return {"domain": dom, "terms": d["terms"], "custom": True}
    return {"domain": dom, "terms": DEFAULT_IDEALITY["terms"], "custom": False}

@app.post("/ideality")
async def save_ideality(request: Request, domain: str = Query(None)):
    if not _current_admin(request):
        raise HTTPException(status_code=403, detail="Réservé aux administrateurs.")
    if config_col is None:
        raise HTTPException(status_code=503, detail="Stockage non configuré (MONGO_URI_RW).")
    dom = domain if domain in DOMAINS else DEFAULT_DOMAIN
    body = await request.json()
    clean = []
    for t in (body.get("terms") or []):
        if not isinstance(t, dict) or not t.get("key"):
            continue
        try:
            coef = max(0.0, min(100.0, float(t.get("coef", 1))))
        except (TypeError, ValueError):
            coef = 1.0
        clean.append({"key": str(t["key"]), "code": str(t.get("code", ""))[:6],
                      "label": str(t.get("label", t["key"]))[:40],
                      "side": "den" if t.get("side") == "den" else "num", "coef": round(coef, 2)})
    config_col.update_one({"_id": f"ideality:{dom}"},
                          {"$set": {"terms": clean, "domain": dom}}, upsert=True)
    return {"ok": True, "domain": dom, "terms": clean}

@app.delete("/ideality")
def reset_ideality(request: Request, domain: str = Query(None)):
    if not _current_admin(request):
        raise HTTPException(status_code=403, detail="Réservé aux administrateurs.")
    dom = domain if domain in DOMAINS else DEFAULT_DOMAIN
    if config_col is not None:
        config_col.delete_one({"_id": f"ideality:{dom}"})
    return {"ok": True, "domain": dom, "terms": DEFAULT_IDEALITY["terms"]}

# --- Lens (brevets) : signal de crédibilité par entreprise ------------------
# Une entreprise de la base qui détient des brevets = crédibilité renforcée pour
# un investisseur (maturité commerciale). Clé Lens lue côté serveur uniquement.
def _load_lens_key():
    k = os.getenv("LENS_KEY") or os.getenv("LENS_API_KEY")
    if k:
        return k.strip()
    return _vault_get("LENS_API_KEY")

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

# --- Accès Lens (brevets) : quota serré -> cache PERSISTANT + garde-fous ------------------
# Lens Patent API : quota par MINUTE et par MOIS (~18 000 requêtes restantes au 24/09/2026).
# Le tableau du POC demande les brevets de dizaines d'entreprises d'un coup (2 appels chacune),
# et le cache mémoire était perdu à chaque mise en veille de Render (15 min sans visite) : tout
# était redemandé. Désormais : réponses Lens ALLÉGÉES (champs utiles seulement, pour la limite
# de 512 Mo d'Atlas M0) gardées 30 jours dans `hivescan_lens_cache` ; appels simultanés plafonnés ;
# un 429 est retenté brièvement, puis signalé « occupé » (503) — jamais converti en « 0 brevet ».
import threading
_LENS_GATE = threading.BoundedSemaphore(int(os.getenv("LENS_CONCURRENCY", "3")))
LENS_CACHE_DAYS = int(os.getenv("LENS_CACHE_DAYS", "30"))
lens_cache_col = None
if _MONGO_URI_RW:
    try:
        lens_cache_col = MongoClient(_MONGO_URI_RW)[DB_NAME]["hivescan_lens_cache"]
        lens_cache_col.create_index("fetched_at", expireAfterSeconds=LENS_CACHE_DAYS * 86400)
    except Exception:
        lens_cache_col = None

class LensBusy(Exception):
    """Quota Lens momentanément épuisé (429 persistant)."""

def _lens_trim(d):
    """Garde la forme de la réponse Lens mais seulement les champs lus par l'API."""
    out = []
    for p in d.get("data") or []:
        b = p.get("biblio") or {}
        parties = b.get("parties") or {}
        def names(k):
            return [{"extracted_name": {"value": (x.get("extracted_name") or {}).get("value", "")}}
                    for x in (parties.get(k) or [])][:20]
        title = ((b.get("invention_title") or [{}])[0] or {}).get("text") or ""
        ab = p.get("abstract")
        abt = ((ab[0] or {}).get("text", "") if isinstance(ab, list) and ab else "") or ""
        cpc = [{"symbol": c.get("symbol")} for c in ((b.get("classifications_cpc") or {}).get("classifications") or [])
               if isinstance(c, dict) and c.get("symbol")][:8]
        q = {"jurisdiction": p.get("jurisdiction"), "date_published": p.get("date_published"),
             "biblio": {"invention_title": [{"text": title}],
                        "parties": {"applicants": names("applicants"), "inventors": names("inventors")},
                        "classifications_cpc": {"classifications": cpc}}}
        if abt:
            q["abstract"] = [{"text": abt[:500]}]
        out.append(q)
    return {"total": d.get("total", 0), "data": out}

def _lens_post(payload, tries=3):
    key = hashlib.sha1(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
    if lens_cache_col is not None:
        try:
            hit = lens_cache_col.find_one({"_id": key}, {"data": 1})
            if hit:
                return hit["data"]
        except Exception:
            pass
    body = json.dumps(payload).encode("utf-8")
    for attempt in range(tries):
        req = urllib.request.Request(
            "https://api.lens.org/patent/search", data=body,
            headers={"Authorization": f"Bearer {LENS_KEY}", "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with _LENS_GATE:
                with urllib.request.urlopen(req, timeout=40) as r:
                    data = _lens_trim(json.load(r))
            break
        except urllib.error.HTTPError as e:
            if e.code != 429:
                raise
            if attempt == tries - 1:
                raise LensBusy()
            wait = e.headers.get("x-rate-limit-retry-after-seconds") or e.headers.get("Retry-After") or 2 * (attempt + 1)
            try:
                wait = float(wait)
            except ValueError:
                wait = 2 * (attempt + 1)
            time.sleep(min(max(wait, 0.5), 10))
    if lens_cache_col is not None:
        try:
            lens_cache_col.replace_one({"_id": key}, {"_id": key, "data": data,
                                                      "fetched_at": datetime.datetime.utcnow()}, upsert=True)
        except Exception:
            pass
    return data

# --- Désambiguïsation IA des brevets « à vérifier » (LLM peu gourmand) ------------
# Un brevet au nom d'un homonyme même-pays, hors des mots-clés du domaine, est
# « à vérifier » (risque d'homonyme). On demande à un LLM léger (Gemini 2.5 Flash-Lite,
# ~10× moins cher que Haiku, même famille de clé qu'Inventioneering) de juger la
# PROXIMITÉ THÉMATIQUE entre la classe technique du brevet (codes CPC en premier,
# puis titre) et la typologie de la startup : une forte proximité rend probable
# qu'il s'agit bien de la même personne (on brevète dans son domaine). Au-dessus d'un
# seuil de confiance, le brevet est compté. Optionnel : inactif si GEMINI_API_KEY
# absent (les brevets restent « à vérifier », comportement actuel). Sortie structurée
# (responseSchema) → JSON validé, thinking désactivé. Cache par (entreprise, domaine).
_GEMINI_KEY = os.getenv("GEMINI_API_KEY", "").strip()
_PATENT_LLM_MODEL = os.getenv("PATENT_LLM_MODEL", "gemini-2.5-flash-lite")
try:
    _PATENT_LLM_THRESHOLD = float(os.getenv("PATENT_LLM_THRESHOLD", "0.7"))
except ValueError:
    _PATENT_LLM_THRESHOLD = 0.7
_llm_patent_cache = {}
# Schéma Gemini (sous-ensemble OpenAPI : types en MAJUSCULES, pas d'additionalProperties).
_PATENT_JUDGE_SCHEMA = {
    "type": "OBJECT",
    "properties": {
        "startup_field": {"type": "STRING"},
        "judgments": {"type": "ARRAY", "items": {
            "type": "OBJECT",
            "properties": {
                "index": {"type": "INTEGER"},
                "confidence": {"type": "NUMBER"},
                "related": {"type": "BOOLEAN"},
            },
            "required": ["index", "confidence", "related"],
        }},
    },
    "required": ["startup_field", "judgments"],
}

def _gemini_json(user, schema, max_tokens=1024):
    """Appel Gemini generateContent (urllib, comme Lens) en sortie JSON structurée. Retourne le dict."""
    body = {
        "contents": [{"parts": [{"text": user}]}],
        "generationConfig": {
            "temperature": 0,
            "responseMimeType": "application/json",
            "responseSchema": schema,
            "maxOutputTokens": max_tokens,
            "thinkingConfig": {"thinkingBudget": 0},   # pas de raisonnement -> tokens minimaux
        },
    }
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{_PATENT_LLM_MODEL}:generateContent"
    req = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"),
        headers={"x-goog-api-key": _GEMINI_KEY, "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        resp = json.load(r)
    cands = resp.get("candidates") or []
    if not cands:
        return None
    parts = ((cands[0].get("content") or {}).get("parts")) or []
    txt = next((p.get("text") for p in parts if p.get("text")), None)
    return json.loads(txt) if txt else None

def _llm_confirm_patents(name, dom, broad):
    """broad = [{title, abstract, cpc}]. Retourne {confirmed, field, ok_titles} (proximité≥seuil)."""
    if not _GEMINI_KEY or not broad:
        return {"confirmed": 0, "field": "", "ok_titles": []}
    broad = broad[:24]
    key = f"{_PATENT_LLM_MODEL}|{name}|{dom}|" + "|".join((p.get("title") or "")[:50] for p in broad)
    if key in _llm_patent_cache:
        return _llm_patent_cache[key]
    # Prompt « CPC-first » : les codes CPC sont le signal fort ; titre en appui, résumé
    # court (le résumé pèse le plus en tokens, on le limite -> juste nécessaire).
    lines = []
    for i, p in enumerate(broad):
        cpc = ", ".join((p.get("cpc") or [])[:6])
        ab = (p.get("abstract") or "")[:140]
        lines.append(f"[{i}] CPC : {cpc or '—'} | Titre : {p.get('title','')}" + (f" | Résumé : {ab}" if ab else ""))
    user = (
        f"Une startup nommée « {name} » travaille dans le domaine : « {dom} ».\n"
        "Les brevets ci-dessous sont au nom d'une personne portant le même nom qu'un de ses dirigeants "
        "et résidant dans le même pays, MAIS leur texte ne contient pas les mots-clés du domaine.\n"
        "Pour CHAQUE brevet, estime la probabilité (confidence, 0 à 1) qu'il relève du MÊME champ "
        "technique que la startup — proximité thématique entre la classe technique du brevet "
        "(codes CPC surtout, puis titre) et l'activité de la startup. Forte proximité => probable "
        "même personne (on brevète dans son domaine) ; faible proximité => probable homonyme. "
        "Mets related=true si thématiquement proche. Déduis aussi le champ technique de la startup.\n\n"
        "Brevets :\n" + "\n".join(lines)
    )
    try:
        data = _gemini_json(user, _PATENT_JUDGE_SCHEMA)
    except Exception:
        data = None
    if not data:
        return {"confirmed": 0, "field": "", "ok_titles": []}
    ok = []
    for j in data.get("judgments", []):
        try:
            i = int(j.get("index")); c = float(j.get("confidence"))
        except (TypeError, ValueError):
            continue
        if c >= _PATENT_LLM_THRESHOLD and 0 <= i < len(broad):
            ok.append(broad[i].get("title") or "")
    out = {"confirmed": len(ok), "field": str(data.get("startup_field", ""))[:120], "ok_titles": ok[:6]}
    return _cache_put(_llm_patent_cache, key, out, cap=1000)

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
    # Pas de try/except ici : un échec Lens doit remonter (503/502), pas devenir « 0 brevet » en cache.
    d = _lens_post(payload)
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
        cpc_raw = (b.get("classifications_cpc") or {}).get("classifications") or []
        cpc = [c.get("symbol") for c in cpc_raw if isinstance(c, dict) and c.get("symbol")][:8]
        in_domain = bool(domset & set(_norm(title + " " + abs).split())) if domset else False
        for o in offs:
            if otoks[o] and any(otoks[o].issubset(ns) for ns in nsets):
                slot = res.setdefault(o, {"count": 0, "in_domain": 0, "country": country, "samples": [], "broad": []})
                slot["count"] += 1
                if in_domain:
                    slot["in_domain"] += 1
                elif len(slot["broad"]) < 8:
                    # « à vérifier » (hors mots-clés) : on garde titre+résumé+CPC pour le juge IA.
                    slot["broad"].append({"title": title, "abstract": abs, "cpc": cpc})
                if len(slot["samples"]) < 3:
                    slot["samples"].append({"title": title, "year": (p.get("date_published") or "")[:4],
                                            "jurisdiction": p.get("jurisdiction"), "in_domain": in_domain})
                break
    return res

@app.get("/company-patents")
def company_patents(name: str = Query(...), officers: List[str] = Query(None),
                    domain: List[str] = Query(None), jurisdiction: str = Query(None),
                    deep: bool = Query(False)):
    # deep=True (fiche détail) : lance la désambiguïsation IA des brevets « à vérifier ».
    # deep=False (tri en masse) : lexical seul, pas d'appel LLM (coût maîtrisé).
    if not LENS_KEY:
        raise HTTPException(status_code=503,
                            detail="Clé Lens absente (env LENS_KEY, ou LENS_API_KEY dans le coffre local).")
    dom = " ".join(k for k in (domain or []) if k).strip()
    ck = f"{name}|{'|'.join(officers or [])}|{dom}|{jurisdiction}|{int(deep)}"
    if ck in _patent_cache:
        return _patent_cache[ck]
    try:
        company = _lens_company_patents(name)
        offs_res = _lens_officer_patents(officers, dom, jurisdiction)
    except LensBusy:
        # Quota Lens momentanément épuisé : le POC réessaiera (rien n'est mis en cache).
        return JSONResponse(status_code=503, headers={"Retry-After": "30"},
                            content={"detail": "Lens momentanément saturé, réessayer", "retry_after": 30})
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Lens: {e}")
    company_c = company["count"] if company["matched"] else 0
    officer_c = sum(v["count"] for v in offs_res.values())
    officer_dom = sum(v.get("in_domain", 0) for v in offs_res.values())
    # Désambiguïsation IA (proximité thématique) des brevets « à vérifier », si activée.
    llm_confirmed, llm_field = 0, ""
    if deep and _GEMINI_KEY:
        broad = [b for v in offs_res.values() for b in v.get("broad", [])]
        if broad:
            jr = _llm_confirm_patents(_clean_company(name) or name, dom, broad)
            llm_confirmed, llm_field = jr.get("confirmed", 0), jr.get("field", "")
    result = {"company": company, "officers": offs_res,
              "total": company_c + officer_c,
              "officer_total": officer_c,          # dirigeants (nom + pays de résidence)
              "officer_in_domain": officer_dom,    # sous-ensemble haute confiance (dans le domaine, lexical)
              "officer_llm_confirmed": llm_confirmed,  # brevets « à vérifier » confirmés par proximité thématique (IA)
              "llm_field": llm_field,              # typologie de la startup déduite par le LLM
              "llm_available": bool(_GEMINI_KEY),
              "country": (jurisdiction or "").upper() or None,
              "matched": company["matched"] or officer_c > 0,
              "query": company.get("query")}
    return _cache_put(_patent_cache, ck, result)

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
    "us_ri": (os.path.join(_FUNDING_DIR, "funding_us.json"), "SEC EDGAR — Form D"),
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
    if jur == "us_ri":                              # identifiant registre RI (numérique)
        return num or None
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

@app.get("/funding-coverage")
def funding_coverage():
    """Couverture financement par pays (ouvert) : nb enrichies / trouvées / avec levée."""
    out = {}
    for jur, (path, source) in _FUNDING_FILES.items():
        data = _load_funding_file(path)
        found = [v for v in data.values() if isinstance(v, dict) and v.get("found")]
        raises = [v for v in found if v.get("share_allotments")]
        out[jur] = {"source": source, "enriched": len(data), "found": len(found),
                    "with_raise": len(raises)}
    return out

@app.get("/company-funding")
def company_funding(name: str = Query(...), domain: str = Query(None)):
    doc = _domain_ctx(domain)["coll"].find_one(
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
    return _json_safe({"available": True, "number": key, "jurisdiction": jur, "source": source,
            "funding": f, "signal": sig,
            "equity_raises": f.get("share_allotments") or 0,
            "has_debt": bool(f.get("has_charges")),
            "last_raise": f.get("last_allotment"),
            # Santé (utile pour NO/DK où la levée n'est pas publiée) :
            "raises_tracked": f.get("raises_tracked", True),
            "status": f.get("status"),
            "has_insolvency": bool(f.get("has_insolvency"))})

# --- OpenAlex : publications propres pour un sujet (remplace les articles bruts) --
# Repris du pattern ARIZ-Copilot (openalex-papers). Gratuit ; clé optionnelle
# (env OPENALEX_API_KEY, sinon coffre local) pour éviter le délestage. Côté serveur uniquement.
# NB (audit 2026-07) : l'endpoint /openalex n'est PLUS appelé par le POC (qui utilise
# /officer-pubs) ; conservé comme brique de démo. _reconstruct_abstract, lui, sert aux deux.
def _load_openalex_key():
    k = os.getenv("OPENALEX_API_KEY")
    if k:
        return k.strip()
    return _vault_get("OPENALEX_API_KEY")

OPENALEX_KEY = _load_openalex_key()
_openalex_cache = {}

def _openalex_headers():
    # Sans clé : budget gratuit de 0,10 $/jour PARTAGÉ par l'IP (429 jusqu'à minuit UTC) ;
    # avec clé : 10 000 req/jour. Clé en en-tête, jamais dans l'URL (qui finit dans les journaux).
    h = {"User-Agent": "hivescan-poc (insa-strasbourg)"}
    if OPENALEX_KEY:
        h["Authorization"] = "Bearer " + OPENALEX_KEY
    return h

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
    url = "https://api.openalex.org/works?" + urllib.parse.urlencode(params)
    try:
        req = urllib.request.Request(url, headers=_openalex_headers())
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
    return _cache_put(_openalex_cache, ck, result)

# --- Publications des DIRIGEANTS via OpenAlex, avec désambiguïsation homonymes ---
# Méthode thèse §7.4.2 : requête par nom de dirigeant + FILTRE DE PERTINENCE AU
# DOMAINE (réduit ~50% des faux positifs type « John Smith »). Amélioration : on
# ajoute le PAYS d'affiliation (OpenAlex, contrairement à Semantic Scholar dont le
# champ affiliation était vide à 99% — cf. thèse §10.2.x).
_officer_cache = {}

def _openalex_works(params):
    params.setdefault("mailto", "hivescan-poc@insa-strasbourg.fr")
    url = "https://api.openalex.org/works?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers=_openalex_headers())
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
    return _cache_put(_officer_cache, ck, result)

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
    domain: Optional[str] = Query(None, description="Domaine disciplinaire (energy, cosmetics, …)"),
    dedup: bool = Query(True, description="Regrouper les sociétés sœurs (mêmes publications) sous leur représentante"),
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
                            "paperId": paper.get("paperId"),
                            "title": paper.get("title"),
                            "abstract": paper.get("abstract"),   # absent depuis le plafonnement d'articles
                            "ner": paper.get("ner"),
                            "topic_id": topic,
                            "score": prob,
                            "year": paper.get("year"),
                        })

        return matches
    
    if company:
        filters.append({"results_company_name": regex_obj(company)})
    elif dedup:
        filters.append(DEDUP_FILTER)      # recherche par nom : on montre la société exacte, sœur ou non

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

    ctx = _domain_ctx(domain)            # collection + normalisation propres au domaine
    coll = ctx["coll"]
    ranked = list(coll.aggregate([
        {"$match": mongo_query},
        {"$project": {"_id": 0, "results_company_name": 1, rank_field: 1}},
        {"$sort": {rank_field: order}},
        {"$limit": MAX_SEARCH_DOCS},
    ]))
    names = [r.get("results_company_name") for r in ranked if r.get("results_company_name")]
    if not names:
        raise HTTPException(status_code=404, detail="No documents matched your query")

    # Phase 2 : NE PAS charger les documents complets (110 Mo pour un mot-clé large ->
    # OOM sur le dyno 512 Mo -> worker tué -> connexion coupée -> « NetworkError »). On
    # projette côté Mongo : articles filtrés au mot-clé, plafonnés aux N plus cités, SANS
    # abstract (jamais lu par le POC). ~3 Mo au lieu de 110. Filtre/tri déportés en agrégation.
    # Champs d'article servis : ceux réellement affichés par le POC (fiche détail + rapport) —
    # NER (entités déjà extraites), champs disciplinaires, score TRIZ/article, revue, lien PDF.
    # On EXCLUT seulement les gros champs (abstract, authors) responsables de l'OOM.
    art_fields = {f: f"$$a.{f}" for f in
                  ("title", "year", "citationCount", "ner", "top_3_topic_probs", "paperId",
                   "fieldsOfStudy", "name", "score", "referenceCount")}
    # openAccessPdf : garder UNIQUEMENT l'URL (l'objet complet embarque un long disclaimer).
    art_fields["openAccessPdf"] = {"url": "$$a.openAccessPdf.url"}
    if keywords:
        rgx = "(" + "|".join(re.escape(k) for k in keywords if k) + ")"
        arts_src = {"$filter": {"input": {"$ifNull": ["$possible_triz_levels", []]}, "as": "a",
                    "cond": {"$regexMatch": {
                        "input": {"$concat": [{"$ifNull": ["$$a.title", ""]}, " ",
                                              {"$ifNull": ["$$a.abstract", ""]}]},
                        "regex": rgx, "options": "i"}}}}
    else:
        arts_src = {"$ifNull": ["$possible_triz_levels", []]}
    pipe = [{"$match": {"results_company_name": {"$in": names}}},
            {"$addFields": {"_arts": arts_src}}]
    if keywords:
        # On ne garde que les entreprises ayant ≥1 article pertinent (comportement d'avant).
        pipe.append({"$match": {"_arts.0": {"$exists": True}}})
    pipe += [
        {"$addFields": {
            "matched_article_count": {"$size": "$_arts"},
            "possible_triz_levels": {"$map": {
                "input": {"$slice": [{"$sortArray": {"input": "$_arts",
                          "sortBy": {"citationCount": -1}}}, ARTICLES_PER_COMPANY]},
                "as": "a", "in": art_fields}}}},
        {"$project": {"_id": 0, "_arts": 0}},
    ]
    try:
        full_by_name = {d["results_company_name"]: d for d in coll.aggregate(pipe)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"search phase-2: {e}")
    # On respecte l'ordre du classement (phase 1).
    results = [full_by_name[n] for n in names if n in full_by_name]

    # --- Enrichissement + classement par potentiel d'innovation ------------------
    if topic_id is None:
        for doc in results:
            # Radar 5 dimensions (avant nettoyage NaN : utilise l'effectif/âge bruts).
            doc["radar"] = company_radar(doc, ctx["fmax"])
            # NaN -> None pour un JSON propre (ex. employee_count manquant).
            ec = doc.get("employee_count")
            if isinstance(ec, float) and ec != ec:
                doc["employee_count"] = None
            # Décomposition du score (traçabilité, normalisé au domaine).
            doc["score_breakdown"] = score_breakdown(doc, ctx["fmax"])
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

_topic_cache = {}          # (domaine, topic, size) -> réponse complète (requêtes sans filtre)

# --- Concepts d'un topic (navigation topics + mots-clés) ---------------------------------------
# Écrits par hivescan-ingest/concepts.py dans `hivescan_topic_concepts` (un doc par domaine × topic) :
# SN-grams SPÉCIFIQUES du topic (support × log lift sur le corpus), séparés en objets (groupes
# nominaux) et actions (verbe + complément), chacun relié aux sociétés qui l'emploient DANS le topic.
TOPIC_CONCEPTS_COLL = "hivescan_topic_concepts"
# Sociétés SŒURS (hivescan-ingest/clones.py) : même ensemble d'articles, même dirigeant — familles de
# sociétés de projet (jusqu'à 53). Seule la représentante apparaît dans les listes ; elle porte
# `clone_of.size` et `clone_of.members`. 50 % des sociétés à articles de l'énergie sont concernées.
DEDUP_FILTER = {"clone_of.hidden": {"$ne": True}}
_concepts_cache = {}

def _topic_concepts_doc(domain, topic_id):
    ctx = _domain_ctx(domain)
    key = (ctx["domain"], topic_id)
    if key not in _concepts_cache:
        try:
            _concepts_cache[key] = db[TOPIC_CONCEPTS_COLL].find_one(
                {"domain": ctx["domain"], "topic": topic_id}, {"_id": 0})
        except Exception:
            return None
    return _concepts_cache[key]

@app.get("/topic-concepts")
def topic_concepts(topic_id: int = Query(...), domain: Optional[str] = Query(None)):
    """Concepts distinctifs d'un topic (objets / actions) avec le nombre de sociétés concernées."""
    d = _topic_concepts_doc(domain, topic_id)
    if not d:
        return {"topic_id": topic_id, "available": False, "objects": [], "actions": []}
    # Sociétés de chaque concept en INDICES dans une liste commune (compact) : le POC calcule en
    # direct « combien en resterait-il si j'ajoute ce concept » sans nouvel appel.
    firms_of = d.get("firms") or {}
    names = sorted({n for fs in firms_of.values() for n in fs})
    pos = {n: i for i, n in enumerate(names)}
    slim = lambda items: [{"c": i["c"], "label": i["label"], "n": i["n"],
                           "f": [pos[n] for n in firms_of.get(i["c"], []) if n in pos]} for i in items]
    return {"topic_id": topic_id, "available": True, "n_firms": d.get("n_firms"),
            "objects": slim(d.get("objects", [])), "actions": slim(d.get("actions", [])), "names": len(names)}

# === Navigation par la classification des sujets OpenAlex (discipline > sous-discipline > sujet) ======
# Écrite par hivescan-ingest/oatopics.py (hivescan_oa_taxonomy : sociétés par nœud, sœurs comptées une fois)
# et concepts.py --group oa_subfield (hivescan_oa_concepts). Remplace les topics de la thèse comme point
# d'entrée : ceux-ci ne regroupent pas mieux que le hasard (mesuré), les sujets OpenAlex sont nommés et
# couvrent 87 % des articles. Filtre « énergie » : champ energy_lens (termes de l'Open Energy Ontology).
_oa_cache = {}
# Seuil « pertinence énergie » : ≥ 3 articles contenant un terme OEO. Mesuré (énergie, 2 312 sociétés
# distinctes) : garde 62 % des sociétés (risque d'homonymie élevé 41 %) et écarte les 38 % où il atteint
# 61 %. Signal PARTIEL : il ne remplace pas le contrôle des homonymes.
ENERGY_MIN_ARTICLES = int(os.getenv("ENERGY_MIN_ARTICLES", "3"))

def _oa(domain):
    ctx = _domain_ctx(domain); dom = ctx["domain"]
    if dom not in _oa_cache:
        nodes = {}
        for d in db["hivescan_oa_taxonomy"].find({"domain": dom}, {"_id": 0}):
            nodes[(d["kind"], d["id"])] = d
        energy = {d["results_company_name"] for d in ctx["coll"].find(
            {"energy_lens.n": {"$gte": ENERGY_MIN_ARTICLES}, **DEDUP_FILTER}, {"results_company_name": 1})}
        _oa_cache[dom] = {"nodes": nodes, "energy": energy}
    return _oa_cache[dom]

def _oa_summary(d, energy):
    return {"id": d["id"], "name": d["name"], "parent": d.get("parent"), "n_firms": d["n_firms"],
            "n_energy": sum(1 for n in d.get("firms", []) if n in energy), "n_articles": d.get("n_articles"),
            "growth": d.get("growth")}

@app.get("/oa-tree")
def oa_tree(domain: Optional[str] = Query(None)):
    """Disciplines et sous-disciplines (sans listes de sociétés) — page d'accueil de la navigation."""
    o = _oa(domain); nodes, energy = o["nodes"], o["energy"]
    fields = [_oa_summary(d, energy) for (k, _), d in nodes.items() if k == "field"]
    subs = [_oa_summary(d, energy) for (k, _), d in nodes.items() if k == "subfield"]
    for f in fields:
        f["subfields"] = sorted([s for s in subs if s["parent"] == f["id"]], key=lambda s: -s["n_firms"])
    fields.sort(key=lambda f: -f["n_firms"])
    return _json_safe({"fields": fields, "n_energy": len(energy)})

@app.get("/oa-node")
def oa_node(level: str = Query(..., pattern="^(field|subfield|topic)$"), id: int = Query(...),
            domain: Optional[str] = Query(None)):
    """Un nœud : ses enfants (sous-disciplines ou sujets) et, pour une sous-discipline, ses concepts."""
    o = _oa(domain); nodes, energy = o["nodes"], o["energy"]
    d = nodes.get((level, id))
    if not d:
        raise HTTPException(status_code=404, detail="Nœud inconnu.")
    child = {"field": "subfield", "subfield": "topic"}.get(level)
    children = sorted([_oa_summary(c, energy) for (k, _), c in nodes.items() if k == child and c.get("parent") == id],
                      key=lambda c: -c["n_firms"]) if child else []
    out = {"level": level, **_oa_summary(d, energy), "children": children, "child_level": child}
    if level in ("subfield", "topic"):
        sf = id if level == "subfield" else d.get("parent")
        cd = db["hivescan_oa_concepts"].find_one({"domain": _domain_ctx(domain)["domain"], "level": "subfield", "id": sf},
                                                 {"_id": 0}) or {}
        # Sociétés du nœud seulement (un sujet est un sous-ensemble de sa sous-discipline).
        scope = set(d.get("firms", []))
        firms_of = {c: [n for n in fs if n in scope] for c, fs in (cd.get("firms") or {}).items()}
        names = sorted({n for fs in firms_of.values() for n in fs}); pos = {n: i for i, n in enumerate(names)}
        slim = lambda items: [{"c": i["c"], "label": i["label"], "n": len(firms_of.get(i["c"], [])),
                               "f": [pos[n] for n in firms_of.get(i["c"], [])]}
                              for i in items if firms_of.get(i["c"])]
        out.update({"available": bool(cd), "objects": slim(cd.get("objects", [])), "actions": slim(cd.get("actions", [])),
                    "names": [n for n in names], "energy_idx": [pos[n] for n in names if n in energy]})
    return _json_safe(out)

@app.get("/oa-search")
def oa_search(level: str = Query(..., pattern="^(field|subfield|topic)$"), id: int = Query(...),
              domain: Optional[str] = Query(None),
              concepts: Optional[List[str]] = Query(None), cmode: str = Query("and", pattern="^(and|or)$"),
              energy: bool = Query(False, description="Seulement les sociétés « énergie » (termes OEO)"),
              jurisdiction: Optional[str] = Query(None), size: int = Query(60, ge=1, le=200)):
    """Sociétés d'un nœud, classées par nombre d'articles dans le nœud ; concepts (ET/OU), filtre énergie."""
    ctx = _domain_ctx(domain); coll = ctx["coll"]
    o = _oa(domain); d = o["nodes"].get((level, id))
    if not d:
        raise HTTPException(status_code=404, detail="Nœud inconnu.")
    names = list(d.get("firms", [])); arts_in = dict(zip(names, d.get("firm_arts", [])))
    funnel = [{"label": d["name"], "n": len(names)}]
    if energy:
        names = [n for n in names if n in o["energy"]]
        funnel.append({"label": "pertinence énergie", "n": len(names)})
    if concepts:
        sf = id if level == "subfield" else d.get("parent")
        cd = db["hivescan_oa_concepts"].find_one({"domain": ctx["domain"], "level": "subfield", "id": sf},
                                                 {"firms": 1, "objects": 1, "actions": 1}) or {}
        labels = {i["c"]: i["label"] for i in (cd.get("objects", []) + cd.get("actions", []))}
        keep = None
        for c in concepts:
            s = set((cd.get("firms") or {}).get(c, []))
            keep = s if keep is None else (keep & s if cmode == "and" else keep | s)
        names = [n for n in names if n in (keep or set())]
        funnel.append({"label": " · ".join(labels.get(c, c) for c in concepts), "n": len(names)})
    if jurisdiction:
        countries = {j.strip().lower() for j in jurisdiction.split(",") if j.strip()}
        ok = {x["results_company_name"] for x in coll.find(
            {"results_company_name": {"$in": names}, "results_company_jurisdiction_code": {"$in": list(countries)}},
            {"results_company_name": 1})}
        names = [n for n in names if n in ok]
    total = len(names)
    top = names[:size]                               # déjà classées par nombre d'articles dans le nœud
    by_name = {x["results_company_name"]: x for x in coll.find({"results_company_name": {"$in": top}, **DEDUP_FILTER},
                                                              {"_id": 0})}
    results = []
    for n in top:
        doc = by_name.get(n)
        if not doc:
            continue
        doc["node_articles"] = arts_in.get(n, 0)
        doc["radar"] = company_radar(doc, ctx["fmax"])
        ec = doc.get("employee_count")
        if isinstance(ec, float) and ec != ec:
            doc["employee_count"] = None
        doc["score_breakdown"] = score_breakdown(doc, ctx["fmax"])
        arts = sorted(doc.get("possible_triz_levels", []), key=lambda p: p.get("citationCount") or 0, reverse=True)
        doc["matched_article_count"] = len(arts)
        doc["possible_triz_levels"] = arts[:20]
        results.append(doc)
    return _json_safe({"items": results, "total": total, "funnel": funnel,
                       "node": {"level": level, "id": id, "name": d["name"]}})

@app.get("/topic-search")
def topic_search(topic_id: int = Query(..., description="Topic (0–29) à explorer — découverte topic-first, sans mot-clé"),
                 domain: Optional[str] = Query(None),
                 jurisdiction: Optional[str] = Query(None),
                 keywords: Optional[List[str]] = Query(None, description="Optionnel : combine topic ∩ mot-clé"),
                 concepts: Optional[List[str]] = Query(None, description="Optionnel : concepts du topic"),
                 cmode: str = Query("and", pattern="^(and|or)$", description="and = tous les concepts (converger) ; or = au moins un (élargir)"),
                 innovation_min: Optional[float] = Query(None, ge=0.0, le=1.0),
                 size: int = Query(60, ge=1, le=200),
                 dedup: bool = Query(True, description="Regrouper les sociétés sœurs")):
    """Découverte TOPIC-FIRST (thèse) : renvoie les ENTREPRISES dont ≥1 article relève du
    topic choisi (sortie du topic-modeling LDA/ETM), classées par PERTINENCE-TOPIC, enrichies
    (radar + décomposition) comme /search — donc affichables tel quel dans la table du POC.
    Combinable avec mot-clé/juridiction/innovation_min. `total` = compte réel du topic."""
    ctx = _domain_ctx(domain)
    coll = ctx["coll"]
    # Les affectations de topics sont STATIQUES : la réponse « topic seul » est déterministe
    # -> cache mémoire (évite count+aggregate ~1s à chaque clic ; cap petit, payloads ~1,3 Mo).
    unfiltered = not (jurisdiction or keywords or concepts or innovation_min is not None)
    tck = (ctx["domain"], topic_id, size, dedup)
    if unfiltered and tck in _topic_cache:
        return _topic_cache[tck]
    # Un article a top_3_topic_probs = [[id, prob], …] ; on matche une paire dont l'index 0 == topic_id.
    topic_filter = {"possible_triz_levels": {"$elemMatch": {"top_3_topic_probs": {"$elemMatch": {"0": topic_id}}}}}
    if dedup:
        topic_filter = {"$and": [topic_filter, DEDUP_FILTER]}
    filters = [topic_filter]
    # Entonnoir : topic seul, puis chaque concept ajouté (intersection des sociétés) -> nombre restant.
    funnel = []
    if concepts:
        cd = _topic_concepts_doc(domain, topic_id) or {}
        firms_of = cd.get("firms") or {}
        labels = {i["c"]: i["label"] for i in (cd.get("objects", []) + cd.get("actions", []))}
        funnel.append({"label": f"T{topic_id + 1}", "n": coll.count_documents(topic_filter)})
        keep = None
        for c in concepts:
            s = set(firms_of.get(c, []))
            keep = s if keep is None else (keep & s if cmode == "and" else keep | s)
            funnel.append({"label": labels.get(c, c.replace("_", " ")), "n": len(keep)})
        filters.append({"results_company_name": {"$in": sorted(keep or [])}})
    if jurisdiction:
        countries = [j.strip().lower() for j in jurisdiction.split(",") if j.strip()]
        if countries:
            filters.append({"results_company_jurisdiction_code": {"$in": countries}})
    if keywords:
        kf = []
        for kw in keywords:
            kwr = {"$regex": re.escape(kw), "$options": "i"}
            kf.append({"possible_triz_levels.title": kwr})
            kf.append({"possible_triz_levels.abstract": kwr})
        filters.append({"$or": kf})
    if innovation_min is not None:
        filters.append({"innovation_index": {"$gte": innovation_min}})
    q = {"$and": filters}
    total = coll.count_documents(q)
    if not total:
        return {"items": [], "total": 0, "topic_id": topic_id, "funnel": funnel,
                "topic_label": _topic_meta(domain)["labels"].get(topic_id)}
    # Deux temps (Atlas M0). Phase 1 : classement par PERTINENCE-TOPIC (pas par ICI, qui est
    # global -> les mêmes méga-publiantes en tête de CHAQUE topic). topic_score = somme des
    # probabilités de CE topic sur les articles de l'entreprise -> varie par topic, fait
    # remonter les entreprises réellement centrées sur le topic. ~0,7 s sur M0 (testé).
    ranked = list(coll.aggregate([
        {"$match": q},
        {"$project": {"_id": 0, "results_company_name": 1, "innovation_index": 1,
            "topic_score": {"$sum": {"$map": {"input": {"$ifNull": ["$possible_triz_levels", []]}, "as": "p", "in":
                {"$sum": {"$map": {"input": {"$ifNull": ["$$p.top_3_topic_probs", []]}, "as": "t", "in":
                    {"$cond": [{"$eq": [{"$arrayElemAt": ["$$t", 0]}, topic_id]}, {"$arrayElemAt": ["$$t", 1]}, 0]}}}}}}}}},
        {"$sort": {"topic_score": -1}},
        {"$limit": size},
    ]))
    names = [r.get("results_company_name") for r in ranked if r.get("results_company_name")]
    score_by_name = {r["results_company_name"]: r.get("topic_score", 0) for r in ranked if r.get("results_company_name")}
    full_by_name = {d["results_company_name"]: d
                    for d in coll.find({"results_company_name": {"$in": names}}, {"_id": 0})}
    results = [full_by_name[n] for n in names if n in full_by_name]
    for doc in results:
        doc["topic_score"] = round(score_by_name.get(doc["results_company_name"], 0), 3)
        doc["radar"] = company_radar(doc, ctx["fmax"])
        ec = doc.get("employee_count")
        if isinstance(ec, float) and ec != ec:
            doc["employee_count"] = None
        doc["score_breakdown"] = score_breakdown(doc, ctx["fmax"])
        # On ne garde QUE les articles DU TOPIC (comme /search pour les mots-clés). Sinon le
        # payload = docs complets = ~17 Mo pour 60 entreprises très publiantes -> OOM/timeout
        # Render. Ici ~1,3 Mo, et ça montre POURQUOI l'entreprise relève du topic.
        arts = [p for p in doc.get("possible_triz_levels", [])
                if any(isinstance(t, list) and t and t[0] == topic_id
                       for t in (p.get("top_3_topic_probs") or []))]
        arts.sort(key=lambda p: p.get("citationCount") or 0, reverse=True)
        doc["possible_triz_levels"] = arts[:20]
        doc["matched_article_count"] = len(arts)
    results.sort(key=lambda d: d.get("topic_score") or 0, reverse=True)   # pertinence-topic décroissante
    out = _json_safe({"items": results, "total": total, "topic_id": topic_id, "funnel": funnel,
                      "topic_label": _topic_meta(domain)["labels"].get(topic_id)})
    if unfiltered:
        _cache_put(_topic_cache, tck, out, cap=6)
    return out