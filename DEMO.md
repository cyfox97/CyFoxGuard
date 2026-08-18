# CyFoxGuard Demo Environment

This demo brings up two intentionally-vulnerable, disposable lab targets so
you can try CyFoxGuard against something you're unambiguously authorized to
test: **OWASP Juice Shop** (web) and **OWASP crAPI** (API).

Never point CyFoxGuard at a target you don't own or don't have written
authorization to test. These two apps exist specifically to be scanned.

## 1. Start Juice Shop (web target)

From the repo root:

```bash
docker compose up -d
```

This starts Juice Shop at **http://localhost:3000**.

Default state: no login required to browse; a "Login" link exists but you
can also register your own throwaway account for identity-based tests
(useful for the BOLA/IDOR module — register two accounts, e.g. `userA@test.local`
and `userB@test.local`, both with password `Passw0rd!`, and use the JWTs
they receive as `--identity` values).

## 2. Start crAPI (API target)

crAPI ships its own official multi-service Docker Compose stack (Postgres,
MongoDB, Kafka, mailhog, and several microservices) that's larger than a
single-file demo can responsibly vendor without going stale. Fetch and run
the official one from OWASP directly:

```bash
curl -L -o /tmp/crapi.zip https://github.com/OWASP/crAPI/archive/refs/heads/main.zip
unzip /tmp/crapi.zip -d /tmp/
cd /tmp/crAPI-main/deploy/docker
docker compose pull
docker compose -f docker-compose.yml --compatibility up -d
```

This starts crAPI's web UI at **http://localhost:8888** and its API gateway
at **http://localhost:8080**. crAPI sends all outbound email (signup
confirmations, OTPs, etc.) to a local MailHog instance at
**http://localhost:8025** — check there for verification codes/OTPs when
registering test accounts.

Register two throwaway crAPI accounts the same way as Juice Shop (two
emails, confirm each via MailHog) so you have two identities for
`bola_idor` testing.

## 3. Run CyFoxGuard against each target

All commands below assume you've already run `pip install -r requirements.txt`
in the CyFoxGuard repo root.

### Juice Shop (web)

```bash
python cyfoxguard.py --target http://localhost:3000 --output-dir demo/juice-shop-results
```

### Juice Shop, safe mode (reduced payloads, no rate-limit flood)

```bash
python cyfoxguard.py --target http://localhost:3000 --safe --output-dir demo/juice-shop-results
```

### crAPI (API), with two identities for BOLA/IDOR and an OpenAPI spec

crAPI publishes an OpenAPI spec at its identity service; grab it first
(exact path may shift between crAPI versions — check crAPI's own docs if this
404s) and pass it in:

```bash
curl -o demo/crapi-openapi.json http://localhost:8080/openapi.json

python cyfoxguard.py \
  --target http://localhost:8080/identity/api/v2/user/dashboard \
  --openapi-spec demo/crapi-openapi.json \
  --identity "userA:Authorization=Bearer <JWT_FOR_USER_A>" \
  --identity "userB:Authorization=Bearer <JWT_FOR_USER_B>" \
  --output-dir demo/crapi-results
```

Get each JWT by logging into crAPI's UI (or its `/identity/api/auth/login`
endpoint) as each throwaway account and copying the token from the
response/localStorage.

### CI/CD mode against either target

```bash
export CYFOXGUARD_AUTHORIZED=I_HAVE_AUTHORIZATION
python cyfoxguard.py --target http://localhost:3000 --ci --fail-on high --output-dir demo/ci-results
```

## 4. View results

```bash
python cyfoxguard.py --target http://localhost:3000 --dashboard --output-dir demo/juice-shop-results
```

Then open **http://127.0.0.1:5151**. The standalone HTML report and attack
graph are also written directly into the output directory
(`report.html`, `attack_graph.html`, `findings.json`) — no server required
to view those two.

## 5. Tear down

```bash
docker compose down
cd /tmp/crAPI-main/deploy/docker && docker compose down
```
