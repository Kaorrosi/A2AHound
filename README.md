# A2AHound
 
**BloodHound for A2A agent ecosystems.**
 
A2AHound maps the agents in your [Agent2Agent (A2A)](https://a2a-protocol.org) ecosystem into [BloodHound](https://bloodhound.specterops.io) as an OpenGraph extension. 
 
It reads two kinds of documents that A2A agents publish:
 
- **Agent Cards** (`/.well-known/agent-card.json`, or `/.well-known/agent.json` on older agents)
- **OpenAPI specs** (`openapi.json` / `swagger.json`)

It then links everything into one graph so you can see your AI agents, their skills, the APIs behind them, and their operations. 

## What it models
 
| Node | What it is |
|---|---|
| `A2A_Ecosystem` | Root of a collection, like a Domain in AD |
| `A2A_Provider` | Organization that publishes agents |
| `A2A_Agent` | An agent, from its Agent Card |
| `A2A_Interface` | An endpoint the agent is reachable at (JSON-RPC, gRPC, HTTP+JSON) |
| `A2A_Host` | A server origin that hosts interfaces or API operations |
| `A2A_Skill` | Something an agent can do |
| `A2A_Extension` | A protocol extension the agent supports |
| `A2A_SecurityScheme` | API key, HTTP auth, OAuth2, OpenID Connect or mTLS |
| `A2A_AuthorizationServer` | OAuth / OIDC token issuer |
| `A2A_Scope` | OAuth scope |
| `A2A_Client` | Service account or OAuth client that calls agents (from enrichment data) |
| `A2A_PublicAccess` | "Anyone (Unauthenticated)", like Everyone in AD |
| `A2A_SigningKey` | Key that signs Agent Cards |
| `A2A_APISpec` | An OpenAPI document |
| `A2A_APIOperation` | One method + path in an API |
 

## Files
 
| File | Purpose |
|---|---|
| [`extension/A2AHound-Community-v1.0.0.zip`](extension/A2AHound-Community-v1.0.0.zip) | Installable Community extension bundle |
| [`extension/schema.json`](extension/schema.json) | OpenGraph extension definition schema |
| [`extension/saved_queries.json`](extension/saved_queries.json) | Saved Cypher queries included in the bundle |
| `a2ahound.py` | Collector: fetches cards and specs and writes a BloodHound payload |

 
## Quick start
 
**Requirements:** Python 3.8+ (standard library only, nothing to install) and BloodHound CE or Enterprise 8.0+ with OpenGraph.
 
**1. Install the extension.** In BloodHound, go to **Administration → OpenGraph Management** and upload [the extension bundle](extension/A2AHound-Community-v1.0.0.zip). Bundles require BloodHound 9.9 or later. For a schema-only installation, upload [`extension/schema.json`](extension/schema.json).
 
**2. Collect.**

The collector takes a host, a URL pointing to an agent card(agent.json) or an OpenAPI spec(openapi.json), or a local .json file. The collector works out which kind of document each one is, and you can mix them freely.

When given a host the collector probes `/.well-known/agent-card.json`, `/.well-known/agent.json` and common OpenAPI paths:
 
```bash
python3 a2ahound.py agents.example.com -o a2a.json
```
 
An agent card endpoint:
 
```bash
python3 a2ahound.py https://agents.example.com/.well-known/agent.json -o a2a.json
```
 
An OpenAPI endpoint:
 
```bash
python3 a2ahound.py https://api.example.com/openapi.json -o a2a.json
```
 
Several endpoints, or a combination of hosts, cards and specs:
 
```bash
python3 a2ahound.py agents.example.com \
  https://research.example.com/.well-known/agent-card.json \
  https://api.example.com/openapi.json \
  https://billing.example.com/swagger.json \
  -o a2a.json
```
 
A list of endpoints in a file, one per line (lines starting with `#` are ignored):
 
```text
# targets.txt
agents.example.com
https://research.example.com/.well-known/agent-card.json
https://api.example.com/openapi.json
```
 
```bash
python3 a2ahound.py -i targets.txt -o a2a.json
```
 
Saved files in a directory:
 
```bash
python3 a2ahound.py ./cards/*.json -o a2a.json
```
 
Multiple directories:
 
```bash
python3 a2ahound.py ./cards/*.json ./specs/*.json -o a2a.json
```
 
Everything at once (directories, live endpoints and a list):
 
```bash
python3 a2ahound.py ./cards/*.json ./specs/*.json agents.example.com -i targets.txt --ecosystem prod -o a2a.json
```
 
**3. Upload.** In BloodHound, go to **Administration → File Ingest** (or Quick Upload) and upload `a2a.json`.
 
**4. Explore.** In **Explore → Cypher**, open the extension's saved queries. Start with **Extension graph**.

## Collector options
 
| Option | What it does |
|---|---|
| `-o FILE` | Output payload (default `a2ahound-payload.json`) |
| `-i FILE` | Read targets from a file, one per line |
| `--ecosystem NAME` | Name of the root node, for keeping collections apart (default `a2a`) |
| `-H "Name: value"` | Send a header, such as `Authorization: Bearer …`. Only sent to the hosts you list, never to discovered ones |
| `--extended` | Also fetch authenticated extended agent cards (needs `-H` credentials) |
| `--resolve-issuers` | Fetch OIDC / OAuth discovery documents to get exact issuer names |
| `--enrich FILE` | Add service accounts, "runs as" and delegation data (format in `FIELD-MAPPING.md`) |
| `--skill-map FILE` | Explicit skill-to-API-operation links |
| `--min-confidence N` | Threshold for automatic skill-to-operation matches (default `0.8`; `0.5` adds tag matches) |
| `--no-probe-openapi` | Don't look for OpenAPI specs |
| `--insecure` | Skip TLS certificate checks |
 
## Saved queries

Browse the [saved query source](extension/saved_queries.json) or open it in the [Query Library](https://queries.specterops.io/?source=https%3A%2F%2Fraw.githubusercontent.com%2FKaorrosi%2FA2AHound%2Frefs%2Fheads%2Fmain%2Fextension%2Fsaved_queries.json&sourceLabel=A2AHound).

## Limitations
 
- **Card signatures** are recorded but not cryptographically verified (`verified: not_checked`).
- **OpenAPI operations with no `security` block** are linked to Anyone. If a gateway in front of the API enforces authentication, those edges are false positives.
- **Who an agent runs as and which agents it delegates to** aren't in Agent Cards. Add them with `--enrich` from your identity provider or deployment config.
- **The `environments` block** in the schema is only used by BloodHound Enterprise.
- **Nodes other than the ecosystem root** are identified by URL. The same host collected under two `--ecosystem` names becomes one node.
