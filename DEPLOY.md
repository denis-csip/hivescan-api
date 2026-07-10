# Déploiement Hivescan POC (API Render + page hivescan.net)

> ⚠️ Ne JAMAIS toucher à **hivescan.fr** (app prod de Connor). Ici on déploie
> uniquement le POC : API sur Render + page statique sur **hivescan.net**.

## 0. Pré-requis
- Laisser finir les 4 batches d'enrichissement (funding_ch/fr/no/dk.json à jour).
- Les secrets ne sont PLUS dans le code : ils passent en variables d'environnement.

## 1. Sécuriser MongoDB (Atlas)
- Créer/garder un utilisateur **lecture seule** sur `hivescan_data`.
- **Changer le mot de passe** de `contact_db_user` (il a circulé en clair).
- Network Access : autoriser l'IP sortante de Render (ou 0.0.0.0/0 le temps du POC).
- Récupérer la chaîne `mongodb+srv://…` → servira de `MONGO_URI`.

## 2. Pousser le code sur un dépôt Git (privé)
Depuis `v0_api_hivescan-main/` (le `.gitignore` exclut déjà secrets + venv) :
```
git init && git add . && git commit -m "Hivescan API"
git remote add origin <ton-repo-github-privé> && git push -u origin main
```
Vérifier que `mongo_uri.txt` et les `clé-*.txt` ne sont PAS poussés.
Les `funding_*.json` (données publiques) DOIVENT l'être (le Docker les embarque).

## 3. Créer le service sur Render
- Dashboard Render > **New > Blueprint** > sélectionner le dépôt (il lit `render.yaml`).
- Renseigner les variables d'environnement (onglet Environment) :
  | Variable | Valeur |
  |---|---|
  | `MONGO_URI` | chaîne Atlas (lecture seule) |
  | `LENS_KEY` | clé Lens.org |
  | `OPENALEX_API_KEY` | clé OpenAlex |
  | `ALLOWED_ORIGINS` | `https://hivescan.net,https://www.hivescan.net` |
- Déployer. Noter l'URL publique, ex. `https://hivescan-api.onrender.com`.
- Test : ouvrir `https://…onrender.com/` (doit répondre) puis
  `https://…onrender.com/company-funding?name=2J%20METHAVERT`.

## 4. Repointer le POC vers l'API Render
Dans `hivescan-poc/index.html`, l'API lit `window.HIVESCAN_API`. Au déploiement de
la page, injecter (au-dessus du `<script>` principal, ou dans le HTML servi) :
```html
<script>window.HIVESCAN_API="https://hivescan-api.onrender.com";</script>
```

## 5. Déployer la page sur hivescan.net (Hostinger)
- Uploader `hivescan-poc/index.html` via FTPS (même méthode que la landing) sous
  hivescan.net (ou un sous-dossier `/app`). NE PAS écraser autre chose sur le domaine.

## 6. Accès invités (à finaliser — décision en attente)
Recommandé : **mot de passe partagé** (protège les quotas Lens/OpenAlex). Options :
- Simple : Basic Auth au niveau de l'hébergeur de la page + un header partagé sur l'API.
- Ou Cloudflare Access devant hivescan.net.

## Notes
- Plan Render **free** : démarrage à froid ~50 s après inactivité. Passer à `starter`
  pour un POC réactif montré à des invités.
- Quotas : chaque fiche déclenche des appels Lens/OpenAlex/Companies House en direct
  (cache mémoire, perdu au redémarrage). Si l'usage grimpe, prévoir un cache persistant
  ou pré-calculer les brevets/publis.
