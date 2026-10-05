# Papertrust

**Self-hosted document signing that anyone can check, and nobody can quietly change.**

Papertrust turns a page of your application into a PDF, signs it, and gives you everything you need to prove later that the file is exactly the one you issued. One changed pixel, character or byte, and the check fails.

- **Your keys, your instance.** No accounts, no sign-up, no outside certificate authority, no third-party service. Every installation has its own identity.
- **Post-quantum.** Every signature is made twice, with **Ed25519** and **ML-DSA-65** (NIST FIPS 204). A forger would have to break both.
- **No master key held by a person.** The instance makes its own keys, keeps them encrypted, replaces them every year, and each new key is endorsed by the old one, so trust carries forward on its own.
- **Small and boring on purpose.** One Node.js service, one dependency (`playwright-core` to drive Chromium), one encrypted file on disk, a status page, and a test suite.

Created by **Thakur Ankush Singh (Vaishnavi Consultant)**. Open source under the [Apache License 2.0](LICENSE).

---

## Contents

1. [How it works](#how-it-works)
2. [Architecture](#architecture)
3. [Quick start](#quick-start)
4. [Deployment](#deployment)
5. [Settings](#settings)
6. [Using it from your application](#using-it-from-your-application)
7. [Trust model](#trust-model)
8. [Security](#security)
9. [Operations](#operations)
10. [Troubleshooting](#troubleshooting)
11. [FAQ](#faq)
12. [API reference](#api-reference)
13. [Project structure](#project-structure)
14. [Development](#development)
15. [License and credit](#license-and-credit)

---

## How it works

### The life of a signed document

```
 your application                              Papertrust (private network only)
 ────────────────                              ──────────────────────────────────
 1. user opens invoice INV-1
 2. app creates a one-time render link
 3. POST /v1/render { url, label: "INV-1" } ──▶ opens the link in headless Chromium
                                                waits for data-papertrust-ready="INV-1"
                                                prints the page to PDF, photographs it to PNG
                                                SHA-256 of the PDF
                                                signs "INV-1\n<sha256>" with Ed25519 AND ML-DSA-65
 4. stores PDF, sha256, kid, signature  ◀────── { kid, sha256, signature, pdf, png }
 5. user downloads the PDF

 … months later, someone sends you a PDF …

 6. sha256(file) == stored sha256 ?
    signature valid for the key `kid` (from GET /v1/keys) ?
    → both yes: genuine and unchanged.  Anything else: altered or not yours.
```

`POST /v1/sign` signs any short text the same way. Use it for what a PDF can't carry on paper: the contents of a QR code, a person's approval, a link in your own audit log.

### Step by step

1. **First start.** The instance makes its first key pair (one Ed25519 key, one ML-DSA-65 key), encrypts it into `keystore.json` and starts listening. Its identity is the fingerprint of these public keys, shown on the status page.
2. **Your application connects.** It fetches the public key chain from `GET /v1/keys`, checks the fingerprint once, and stores the key records. From then on it can verify signatures by itself, even when Papertrust is offline.
3. **Signing.** Your application sends authenticated requests (HMAC with the shared secret). Papertrust signs with the current key and returns the key id (`kid`) together with the signature pair.
4. **Rendering.** For PDFs, Papertrust loads a page of your application in Chromium, so the PDF it signs is the PDF it made itself; nothing can be swapped in between.
5. **Rotation.** Once a year (by default) the instance makes a new key pair, signs the new public record with the old key, and deletes the old private keys. Your application follows the endorsement and trusts the new key automatically.
6. **Verification.** Anyone holding the trusted public keys can check a signature with plain Ed25519 and ML-DSA verification: no call to Papertrust, no account, no network.

---

## Architecture

### Components

```
                         ┌──────────────────────────── Papertrust process ───────────────────────────┐
                         │                                                                            │
  HTTP :4100 ──────────▶ │  server.mjs      routing, body limits, error handling, counters, rotation   │
                         │     │                                                                      │
                         │     ├── auth.mjs        HMAC check, 60 s window, replay cache              │
                         │     ├── keystore.mjs    keys in memory; encrypted keystore.json on disk     │
                         │     │      └── keychain.mjs   public key records, endorsements, trust       │
                         │     │             └── signatures.mjs  Ed25519 + ML-DSA-65, domain separation│
                         │     ├── render.mjs      Chromium (playwright-core): page → PDF + PNG          │
                         │     └── status-page.mjs HTML status page (no scripts, strict CSP)            │
                         │                                                                            │
                         │  config.mjs  environment variables → validated settings                    │
                         └────────────────────────────────────────────────────────────────────────────┘
                                   │                                │
                          /data/keystore.json                Chromium (child process,
                          (AES-256-GCM, scrypt)              started on demand, closed when idle)
```

| Module | Responsibility |
|---|---|
| [`src/server.mjs`](src/server.mjs) | HTTP routes, authentication gate, request size limits, counters, scheduled key rotation, graceful shutdown. |
| [`src/auth.mjs`](src/auth.mjs) | Request signatures (HMAC-SHA256), clock window and replay protection. `signRequest()` is the client side. |
| [`src/signatures.mjs`](src/signatures.mjs) | Key generation, dual signing and verification, key ids and fingerprints, purpose-bound messages. |
| [`src/keychain.mjs`](src/keychain.mjs) | Public key records, endorsements, chain verification, `extendTrust()` for applications. |
| [`src/keystore.mjs`](src/keystore.mjs) | The encrypted keystore file: create, open, rotate, re-encrypt; atomic writes. |
| [`src/render.mjs`](src/render.mjs) | Headless Chromium: origin allow-list, request blocking, readiness check, PDF and PNG, concurrency limit, idle shutdown. |
| [`src/config.mjs`](src/config.mjs) | Reads and validates environment variables with clear error messages. |
| [`src/status-page.mjs`](src/status-page.mjs) | The status page at `/`: health, current key fingerprint, key history, counters. |
| [`src/canonical.mjs`](src/canonical.mjs) | Canonical JSON, so every implementation signs exactly the same bytes. |
| [`src/index.mjs`](src/index.mjs) | Library entry point for applications (`import … from "papertrust"`). |
| [`bin/papertrust.mjs`](bin/papertrust.mjs) | Command line: `start`, `secret`, `keys`, `rotate`, `rewrap`, `health`, `help`. |

### What lives where

| Data | Where | Secret? |
|---|---|---|
| Private keys (current key only) | `keystore.json`, encrypted with the keystore password | **Yes** |
| Public key records (all keys ever) | `keystore.json` and `GET /v1/keys` | No, publish freely |
| Shared secret | environment of Papertrust **and** your application | **Yes** |
| Keystore password | environment of Papertrust only | **Yes** |
| Documents, PDFs, signatures | **your application**, not Papertrust | No (but private to you) |

Papertrust has no database and keeps no documents. That is a design choice: the service stays small, has one thing to back up, and can't leak documents it never stored.

### Design decisions

- **Rendering inside the signer.** If your application made the PDF and Papertrust only signed a hash, a compromised application could get any file signed. Rendering inside Papertrust ties the signature to a file Papertrust produced from a page it loaded itself.
- **Two algorithms, both required.** Ed25519 is battle-tested; ML-DSA-65 survives quantum computers. Requiring both means a weakness found in either one alone doesn't break anything.
- **Trust on first use plus endorsements**, instead of a certificate authority. There is nobody to pay, nothing to renew by hand, and no single company or person who can sign for you.
- **Old private keys are deleted.** A backup stolen today can't be used to sign "old-looking" documents after the next rotation.
- **One process, no queue.** At most `PAPERTRUST_MAX_RENDERS` renders run at once; the rest wait their turn. That is plenty for document workloads and keeps memory predictable.

---

## Quick start

### With Docker

```bash
git clone https://github.com/AnkushDiverseCoder/Papertrust.git
cd Papertrust
docker build -t papertrust .

docker run -d --name papertrust \
  -e PAPERTRUST_SECRET="$(docker run --rm papertrust node bin/papertrust.mjs secret)" \
  -e PAPERTRUST_KEY_PASSWORD="$(docker run --rm papertrust node bin/papertrust.mjs secret)" \
  -e PAPERTRUST_ALLOWED_ORIGINS="http://myapp:3000" \
  -v papertrust-data:/data \
  --network your-app-network \
  papertrust
```

Keep a copy of both values: your application needs the secret, and you need the keystore password to restore a backup.

### Without Docker

Needs Node.js 24 or newer and a Chromium-family browser (Chrome, Chromium or Edge).

```bash
git clone https://github.com/AnkushDiverseCoder/Papertrust.git
cd Papertrust
npm install
cp .env.example .env              # fill in PAPERTRUST_SECRET and PAPERTRUST_KEY_PASSWORD (node bin/papertrust.mjs secret)
node --env-file=.env bin/papertrust.mjs
```

Open `http://localhost:4100/`: the status page shows the new identity and its fingerprint.

---

## Deployment

Papertrust runs anywhere Node.js 24 or Docker runs. Pick the way that fits your setup:

- [Docker](#docker)
- [Docker Compose](#docker-compose)
- [Dokploy](#dokploy-step-by-step), step by step
- [Coolify, CapRover, Portainer and similar](#coolify-caprover-portainer-and-similar)
- [Without Docker (systemd)](#without-docker-systemd)

### Requirements

| | Minimum | Comfortable |
|---|---|---|
| CPU | 1 core | 2 cores |
| Memory | 512 MB | 1 GB (each concurrent render uses about 150–250 MB while it runs) |
| Disk | 400 MB image + a few KB for the keystore | |
| Node.js (without Docker) | 24 | latest 24.x LTS |

Chromium starts on the first render and closes after five idle minutes, so an idle instance needs very little memory.

### The two addresses: private and public

This is the one idea to get right. Papertrust can be reached in two ways, and they do different jobs:

| | Private address | Public domain (optional) |
|---|---|---|
| Looks like | `http://papertrust:4100` (container or service name + port) | `https://signer.example.com` |
| Who uses it | **your application** | **you**, in a browser |
| Goes through | the private Docker network, never the internet | the internet → your reverse proxy (Traefik, nginx, a tunnel) → Papertrust |
| Can sign and render | **yes** (with the shared secret) | **no**, read-only |
| Can show the status page, `/health`, `/v1/keys` | yes | yes |

Why the domain is read-only: a reverse proxy adds forwarding headers (`X-Forwarded-For` and similar) to every request it passes on. Papertrust sees them and refuses `/v1/sign` and `/v1/render` with `403 signing is only available on the private network`, **even when the request carries the correct secret**. So even if the secret ever leaked, nobody on the internet could use your instance to sign anything. Your application, calling the private address directly, never goes through the proxy and is unaffected.

**How to use it:** in your application, set the Papertrust URL to the private address. Use the domain only to open the status page when you want to check on things. If you really need signing through a proxy (for example the application runs on another server), set `PAPERTRUST_ALLOW_PROXIED_SIGNING=true` and protect that route well.

### Network rules

- Your application must be able to reach Papertrust's **private address**, normally by being on the same Docker network.
- `PAPERTRUST_ALLOWED_ORIGINS` must be your application's private address as Papertrust sees it (for example `http://myapp:3000`). Render URLs must start with it.
- Papertrust makes no outgoing internet connections. While rendering, it blocks every request outside the allowed origins.
- If you give it a public domain, put a login in front of it (for example HTTP Basic Auth in your proxy), so the status page isn't open to everyone.

### Docker

```bash
docker network create papertrust-net            # skip if your application already has a network
docker build -t papertrust .
docker run -d --name papertrust --restart unless-stopped \
  --network papertrust-net \
  -e PAPERTRUST_SECRET="<random, 32+ characters>" \
  -e PAPERTRUST_KEY_PASSWORD="<another random value>" \
  -e PAPERTRUST_ALLOWED_ORIGINS="http://myapp:3000" \
  -v papertrust-data:/data \
  papertrust
```

Make the random values with `docker run --rm papertrust node bin/papertrust.mjs secret`. Run your application on the same network and point it at `http://papertrust:4100`. Don't use `-p`: no published port is needed.

### Docker Compose

Copy [`docker-compose.example.yml`](docker-compose.example.yml) to `docker-compose.yml`, create a `.env` next to it with `PAPERTRUST_SECRET` and `PAPERTRUST_KEY_PASSWORD`, set `PAPERTRUST_ALLOWED_ORIGINS` to your application's service name and port, then:

```bash
docker compose up -d
docker compose logs -f papertrust      # "created a new identity, key …" on the first start
```

Inside the same Compose project, your application reaches Papertrust at `http://papertrust:4100`.

### Dokploy, step by step

Dokploy puts every application on its shared network (`dokploy-network`), so applications reach each other by their **App Name**, even across projects. The App Name is the grey text under the application's title, for example `myproject-papertrust-ab12cd`.

**1. Create the Papertrust application**

1. In any project, **Create Service → Application**.
2. **General → Provider:** this repository (GitHub, or Git with `https://github.com/AnkushDiverseCoder/Papertrust.git`), branch `main`, build type **Dockerfile**.
3. **Environment:**
   ```
   PAPERTRUST_SECRET=<random, 32+ characters>
   PAPERTRUST_KEY_PASSWORD=<another random value>
   PAPERTRUST_ALLOWED_ORIGINS=http://<your app's App Name>:<its port>
   PAPERTRUST_NAME=<Your company> signer
   ```
   Decide these values **before the first deploy** and keep a copy of `PAPERTRUST_KEY_PASSWORD` in a password manager. Changing it later needs `rewrap` (see [Operations](#operations)).
4. **Advanced → Volumes → Add Volume → Volume Mount:** any volume name (e.g. `papertrust-data`), mount path **`/data`**. Without it, every redeploy would start a brand-new identity.
5. **Deploy.** The logs show:
   ```
   [papertrust] created a new identity, key 7536e7be66cc7137
   [papertrust] listening on http://127.0.0.1:4100 · rendering on
   ```
   Deploy once more: now it must say `opened keystore, current key …` with the **same** key. That proves the volume works.

**2. Optional: a domain for the status page**

1. **Domains → Add Domain:** your host (e.g. `signer.example.com`), path `/`, container port **4100**, HTTPS as you set up your other domains.
2. **Security → Add Basic Auth:** a username and password, so only you can open the page.
3. Open the domain: the status page shows **Working**, the key fingerprint and **PDF rendering: On**.

Remember: this domain is read-only (see [the two addresses](#the-two-addresses-private-and-public)). Never use it as your application's Papertrust URL.

**3. Connect your application**

In your application's **Environment**, use Papertrust's **App Name** as the host:

```
PAPERTRUST_URL=http://<papertrust App Name>:4100
PAPERTRUST_SECRET=<the same value as on Papertrust>
```

(Your application may call these differently; VaishnaviPay, for example, uses `SIGNER_URL` and `SIGNER_SHARED_SECRET`.) Redeploy the application.

**Dokploy troubleshooting**

| You see | Do this |
|---|---|
| `LOCKED, not signing: The keystore can't be opened with this password` | The keystore on the volume was made with a different password: the environment was edited after the first start. Open the status page for the fix: put the old value back, or run `node bin/papertrust.mjs rewrap` in **Docker → Terminal** with `PAPERTRUST_OLD_KEY_PASSWORD=<old>` (it works while locked), then redeploy. If nothing was signed yet, simply give the `/data` mount a new volume name and redeploy. |
| `created a new identity` on every deploy | The `/data` volume is missing or its mount path is wrong. |
| `rendering off` in the logs | `PAPERTRUST_ALLOWED_ORIGINS` is empty or not a plain origin (`http://name:port`, nothing after the port). |
| Your application says it can't reach Papertrust | Check the App Name and port (`4100`) in the application's URL; both apps must be Dokploy applications (or on `dokploy-network`). |
| `403 signing is only available on the private network` | Your application is calling the domain. Use `http://<App Name>:4100` instead. |

### Coolify, CapRover, Portainer and similar

The same recipe works on any platform that builds a Dockerfile:

1. Create an application from this repository with the Dockerfile build.
2. Attach persistent storage at `/data`.
3. Set the environment variables (see [Settings](#settings)).
4. Put it on the same internal network as your application, without a public port.
5. Your application calls it by its internal service name on port 4100.

A public domain is optional and read-only, as above.

### Without Docker (systemd)

On a Linux server with Node.js 24 and Chromium installed:

```bash
sudo useradd --system --home /opt/papertrust papertrust
sudo git clone https://github.com/AnkushDiverseCoder/Papertrust.git /opt/papertrust
cd /opt/papertrust && sudo npm ci --omit=dev
sudo install -d -o papertrust -m 700 /var/lib/papertrust
sudo install -m 600 /dev/null /etc/papertrust.env       # then put the settings in it, one VAR=value per line
sudo cp deploy/papertrust.service /etc/systemd/system/
sudo systemctl enable --now papertrust
journalctl -u papertrust -f
```

The unit file ([`deploy/papertrust.service`](deploy/papertrust.service)) runs it as an unprivileged user, keeps the keystore in `/var/lib/papertrust` and restarts it if it stops. Make it listen only on the private interface (`HOST=127.0.0.1` when the application runs on the same machine).

### Backups and restore

Back up two things, **separately**:

1. the data directory (`/data` volume, or `/var/lib/papertrust`), which holds `keystore.json`;
2. the keystore password (`PAPERTRUST_KEY_PASSWORD`), for example in a password manager.

One without the other is useless, which is the point. To restore, put `keystore.json` back, set the same password, and start. The instance comes back with the same identity, and every application keeps trusting it.

### Upgrading

Pull the new version and rebuild; the keystore and your applications keep working. The keystore format carries a version number. If a future release ever changes it, its release notes will explain the migration, so read them before upgrading across a major version.

### Monitoring

- `GET /health` returns `200 {"ok":true,…}` while the service is up, and `503 {"locked":true,…}` in locked mode. The Docker image's `HEALTHCHECK` uses `papertrust health`, which treats locked mode as alive: restarting wouldn't fix a password.
- The status page shows counters since start, the last problem (if any) and whether rendering works.
- Logs go to standard output, one line per event, prefixed with `[papertrust]`.

---

## Settings

All settings are environment variables. Only the first is required.

| Variable | Default | What it does |
|---|---|---|
| `PAPERTRUST_SECRET` | *(required)* | Shared with your application; authenticates every request. At least 32 characters. Make one with `papertrust secret`. |
| `PAPERTRUST_KEY_PASSWORD` | derived from the secret | Encrypts the keystore file. **Set your own**, so a leaked application secret alone can't unlock a stolen keystore. |
| `PAPERTRUST_ALLOWED_ORIGINS` | *(none)* | Comma-separated origins Papertrust may render, e.g. `http://myapp:3000`. Empty = signing only, rendering off. |
| `PAPERTRUST_DATA_DIR` | `./data` (`/data` in Docker) | Where `keystore.json` lives. Use persistent storage. |
| `PAPERTRUST_ROTATE_DAYS` | `365` | Replace the signing key after this many days. `0` turns automatic rotation off. |
| `PAPERTRUST_NAME` | `Papertrust` | Name shown on the status page. |
| `PAPERTRUST_MAX_RENDERS` | `2` | PDFs rendered at the same time (1–8). |
| `PAPERTRUST_ALLOW_PROXIED_SIGNING` | `false` | `true` lets requests arriving through a reverse proxy (a domain) sign and render. Leave it off: then a domain only ever shows the status page, health and public keys. |
| `CHROMIUM_PATH` | found automatically | Path to Chromium, Chrome or Edge. |
| `PORT`, `HOST` | `4100`, `0.0.0.0` | Where the service listens. |

---

## Using it from your application

Install the helpers (or copy them; they are short and have no dependencies):

```bash
npm install github:AnkushDiverseCoder/Papertrust
```

### 1. Calling Papertrust

Every `POST` carries an HMAC of the request, made with the shared secret. The secret itself is never sent.

```js
import { signRequest } from "papertrust";

async function papertrust(path, body) {
  const text = JSON.stringify(body);
  const res = await fetch(process.env.PAPERTRUST_URL + path, {
    method: "POST",
    headers: { "content-type": "application/json", ...signRequest(process.env.PAPERTRUST_SECRET, "POST", path, text) },
    body: text,
  });
  if (!res.ok) throw new Error((await res.json()).error);
  return res.json();
}

// sign any short text, for a purpose you name
const { kid, signature } = await papertrust("/v1/sign", { purpose: "invoice-facts", payload: '{"n":"INV-1","a":1000}' });

// render one of your pages to a signed PDF
const doc = await papertrust("/v1/render", { url: "http://myapp:3000/print/INV-1?ticket=…", label: "INV-1" });
// doc.pdf and doc.png are base64. Keep doc.sha256, doc.kid and doc.signature with the document.
```

### 2. Making a page renderable

Mark the document on the page Papertrust opens:

```html
<div data-papertrust-sheet data-papertrust-ready="INV-1">
  … the document, styled for A4 …
</div>
```

- `data-papertrust-ready` must equal the `label` you sent. It proves the page shows the document you asked for, not an error page.
- `data-papertrust-sheet` is the element photographed for the PNG.
- The page is opened **without your users' cookies**. Protect it with a short-lived, single-use token in the URL that your application creates just before calling `/v1/render`.
- Requests to origins outside `PAPERTRUST_ALLOWED_ORIGINS` are blocked during rendering. Inline images (data: URLs) or serve them from your application.
- Use print CSS (`@page { size: A4 }`, `@media print`) to control the PDF layout.

### 3. Storing

For each issued document keep: the PDF (or a pointer to it), `sha256`, `kid`, `signature`, the `label`, and when it was issued. Many applications also keep an append-only log of these rows.

### 4. Verifying

```js
import crypto from "node:crypto";
import { extendTrust, verifyPair } from "papertrust";

// once: fetch the key chain and decide which key to trust (compare its fingerprint with the status page)
const { keys } = await fetch(process.env.PAPERTRUST_URL + "/v1/keys").then((r) => r.json());
const trusted = extendTrust([pinnedKid], keys);           // the pinned key + every key endorsed after it
// save `trusted` in your database; refresh it when you meet a kid you don't know yet

// any time: is this the PDF we issued?
const record = trusted.find((r) => r.kid === stored.kid);
const sha = crypto.createHash("sha256").update(fileBytes).digest("hex");
const genuine = sha === stored.sha256
  && verifyPair(record.publicKeys, "file", `${stored.label}\n${sha}`, stored.signature);
```

---

## Trust model

**Identity.** On first start an instance makes its first key pair, the *genesis key*. Your application trusts it once, ideally after comparing its fingerprint with the one on the status page, the same way you accept an SSH host key.

**Rotation.** Every `PAPERTRUST_ROTATE_DAYS` the instance makes a new key pair, signs the new public record with the old key (an *endorsement*), and deletes the old private keys. Anyone who trusted any earlier key can follow the endorsements and trust the new key. Nothing needs to be reconfigured.

**Old documents** stay verifiable forever: the public records of all old keys stay in the chain.

**A changed password** doesn't destroy anything: the instance starts in *locked mode*, signs nothing, and its status page explains how to fix it.

**Losing the keystore** (or its password for good) means the instance can't sign as before. It starts a new identity whose genesis key is *not* endorsed, and applications must consciously trust it again. That is deliberate: a new key that nobody vouched for must never be trusted silently.

**No central party.** There is no certificate authority, no vendor account and no master key in someone's drawer. Each instance is its own authority, and its history of keys is public.

---

## Security

What Papertrust protects against:

- **Edited files.** Any change to a signed PDF changes its SHA-256, so the signature no longer matches.
- **Forged signatures.** Forging needs the private keys, or breaking both Ed25519 and ML-DSA-65.
- **Future quantum computers.** ML-DSA-65 is designed to resist them; Ed25519 alone would not.
- **Stolen keystore files.** The file is encrypted with AES-256-GCM under a key derived with scrypt (N = 32768) from the keystore password. Tampering with it is detected.
- **Strangers calling the API.** Requests need the shared secret (HMAC-SHA256), expire after 60 seconds and can't be replayed.
- **Cross-purpose replay.** Every signature is bound to its purpose (`papertrust/v1/<purpose>`), so a signature for one thing can't be reused for another.
- **Malicious pages.** Rendering only loads allowed origins and blocks all other requests; the status page runs no scripts and sends a strict Content-Security-Policy.

What it does not do:

- It proves **who issued** a document and that it is **unchanged**, not that its contents are true or correct.
- A printout or photo can't be checked byte for byte. For paper, print a short signed text (for example a QR code made with `/v1/sign`) on the document, and compare the paper with your stored original.
- Whoever controls the running instance and its password can sign. Run it on a private network, give it its own password, keep the host patched.

Found a security problem? Please report it privately; see [SECURITY.md](SECURITY.md).

---

## Operations

```bash
papertrust            # run the service (same as: papertrust start)
papertrust secret     # print a new random secret
papertrust keys       # print the key chain and fingerprints
papertrust rotate     # replace the key now (stop the service first)
papertrust rewrap     # re-encrypt the keystore after changing its password (stop the service first, or run it
                      # while the service is locked; give the old one in PAPERTRUST_OLD_KEY_PASSWORD or PAPERTRUST_OLD_SECRET)
papertrust health     # exit 0 while the service answers (used by the Docker health check)
papertrust help
```

Inside Docker: `docker exec -it papertrust node bin/papertrust.mjs keys`.

**Changing the keystore password:** stop the service, run `rewrap` with the old password in `PAPERTRUST_OLD_KEY_PASSWORD` and the new one in `PAPERTRUST_KEY_PASSWORD`, start the service with the new value.

**Changing the shared secret:** set the new value in both Papertrust and your application and restart both. If you never set `PAPERTRUST_KEY_PASSWORD`, the keystore password was derived from the old secret: run `rewrap` with `PAPERTRUST_OLD_SECRET` first, or better, set a separate `PAPERTRUST_KEY_PASSWORD` now.

---

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `PAPERTRUST_SECRET must be set…` on start | The secret is missing or shorter than 32 characters. Make one with `papertrust secret`. |
| `LOCKED, not signing: The keystore can't be opened with this password` | The keystore password changed (or the secret it was derived from). The instance stays up in **locked mode** and its status page explains the fix: put the old value back, or `rewrap` (allowed while locked), then restart. |
| `this Node.js can't make ML-DSA-65 signatures` | Use Node.js 24 or newer. The Docker image already does. |
| `/v1/render` answers `503 rendering is off` | Set `PAPERTRUST_ALLOWED_ORIGINS`, and make sure Chromium is installed (status page shows "Chromium found"). |
| `that URL is not on an allowed origin` | The render URL must start with one of the allowed origins exactly (scheme, host and port). |
| `the page answered 404` / `302` | The page needs a login or the token expired. Render pages must open without cookies. |
| `not marked ready for this label` | The page doesn't contain `data-papertrust-ready="<label>"` with the exact label you sent. |
| `403 signing is only available on the private network` | The request came through a domain or proxy. Call Papertrust on its private address (e.g. `http://papertrust:4100`), not its domain. |
| `401 not authenticated` | Wrong secret, the two machines' clocks differ by more than 60 seconds, or the same request was sent twice. |
| Fonts look wrong in the PDF | Install the fonts in the image (the default covers Latin and Devanagari) or embed web fonts from your own origin. |

---

## FAQ

**Is this a replacement for Adobe-style PDF signatures?**
No, it's a different model. Papertrust doesn't embed a signature in the PDF that a PDF reader checks against a commercial certificate authority. It signs the exact bytes and lets *your* application (or anyone with your public keys) verify them, without paying anybody or depending on anybody.

**Can someone else run Papertrust and pretend to be me?**
They can run the software, but not with your keys. Their instance has a different fingerprint, and nothing it signs verifies against your keys.

**What if my server is hacked?**
An attacker who controls the running instance can sign new things while they control it, as with any signing system. They can't change documents that were already issued without the change showing up, and they can't produce your past signatures for different content. Rotate the key and investigate.

**Does it store my documents?**
No. Papertrust only keeps its keys. Your application stores the PDFs and signatures.

**Can I use it from Python, Go, PHP…?**
Yes. The API is plain HTTP and JSON, and every format is specified below. Ed25519 and ML-DSA-65 are available in modern crypto libraries (for example OpenSSL 3.5+).

---

## API reference

| Method | Path | Auth | Body | Response |
|---|---|---|---|---|
| `GET` | `/` | none | | Status page (HTML) |
| `GET` | `/health` | none | | `{ ok, kid, rendering, version }` |
| `GET` | `/v1/keys` | none | | `{ current, keys: [keyRecord] }`, oldest first |
| `POST` | `/v1/sign` | HMAC | `{ purpose, payload }` | `{ kid, signature }` |
| `POST` | `/v1/render` | HMAC | `{ url, label }` | `{ kid, sha256, signature, pdf, png }` |

Errors are `{ error }` with status `400` (bad input), `401` (authentication), `413` (body over 64 KB), `422` (page can't be rendered), `503` (rendering off) or `500`.

### Formats (for implementations in other languages)

- **Signed bytes:** UTF-8 of `papertrust/v1/<purpose>` + `\n` + `<text>`. Purposes match `^[a-z][a-z0-9-]{0,31}$`; `key` and `file` are reserved for Papertrust.
- **Signature:** `{ "ed25519": base64url, "mldsa65": base64url }`. Valid only if **both** verify.
- **Rendered file:** purpose `file`, text `<label>\n<lowercase hex SHA-256 of the PDF>`.
- **Key record:** `{ v: 1, kid, scheme: "ed25519+ml-dsa-65", publicKeys: { ed25519, mldsa65 } (base64 SPKI DER), createdAt, prev, endorsement }`.
- **kid:** first 16 hex characters of SHA-256(Ed25519 SPKI bytes ‖ ML-DSA-65 SPKI bytes). The full hash is the fingerprint.
- **Endorsement:** the previous key's signature, purpose `key`, over the canonical JSON of the record without its `endorsement` field.
- **Canonical JSON:** object keys sorted at every depth, `undefined` values dropped, no whitespace (see [`src/canonical.mjs`](src/canonical.mjs)).
- **Request HMAC:** headers `x-papertrust-time` (milliseconds since 1970) and `x-papertrust-signature` = hex HMAC-SHA256(secret, `<time>.<METHOD>.<path>.<hex SHA-256 of body>`).
- **Keystore file:** see the comment at the top of [`src/keystore.mjs`](src/keystore.mjs).

---

## Project structure

```
Papertrust/
├── bin/papertrust.mjs          command line (start, secret, keys, rotate, rewrap, help)
├── src/
│   ├── server.mjs              HTTP service
│   ├── auth.mjs                request authentication
│   ├── signatures.mjs          Ed25519 + ML-DSA-65
│   ├── keychain.mjs            key records, endorsements, trust
│   ├── keystore.mjs            encrypted keystore file
│   ├── render.mjs              Chromium rendering
│   ├── config.mjs              settings
│   ├── status-page.mjs         status page and locked-mode page
│   ├── canonical.mjs           canonical JSON
│   └── index.mjs               library exports
├── test/                       node:test suites (crypto, keystore, server incl. a real render)
├── Dockerfile                  production image (Node 24 + Chromium, non-root, health check)
├── deploy/papertrust.service  systemd unit for servers without Docker
├── docker-compose.example.yml
├── .env.example
├── LICENSE                     Apache License 2.0
├── NOTICE                      attribution that must be kept
└── SECURITY.md                 how to report a vulnerability
```

---

## Development

```bash
npm install
npm test        # crypto, keystore and server tests, including a real render through Chromium
                # (render tests are skipped when no Chromium-family browser is installed)
```

The code is small and commented throughout. Start with [`src/server.mjs`](src/server.mjs), then [`src/signatures.mjs`](src/signatures.mjs) and [`src/keychain.mjs`](src/keychain.mjs).

Contributions are welcome. Open an issue first for anything larger than a fix, keep changes covered by tests, and don't add dependencies without a strong reason.

---

## License and credit

Papertrust is licensed under the [Apache License 2.0](LICENSE).
Copyright 2026 **Thakur Ankush Singh (Vaishnavi Consultant)**.

You may use, change and share it, including commercially. If you redistribute it or build on it, keep the [NOTICE](NOTICE) file with its attribution, as section 4(d) of the license requires.
