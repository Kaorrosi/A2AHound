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
| [`extension/schema.json`](extension/schema.json) | OpenGraph extension definition schema. Install it in BloodHound first |
| `a2ahound.py` | Collector: fetches cards and specs and writes a BloodHound payload |

 
## Quick start
 
**Requirements:** Python 3.8+ (standard library only, nothing to install) and BloodHound CE or Enterprise 8.0+ with OpenGraph.
 
**1. Install the schema.** In BloodHound, go to **Administration → OpenGraph Management** and upload [`extension/schema.json`](extension/schema.json).
 
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
 
**4. Explore.** In **Explore → Cypher**, run:
 
```cypher
MATCH p=(a)-[r]->(b) WHERE type(r) STARTS WITH "A2A_" RETURN p
```


 
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
 
## Example queries
 
Every path from unauthenticated callers to a skill or API operation:
 
```cypher
MATCH (s:A2A_PublicAccess), (t) WHERE t:A2A_APIOperation OR t:A2A_Skill
MATCH p=allShortestPaths((s)-[:A2A_Anonymous|A2A_HasSkill|A2A_BackedBy|A2A_ServesAgent|A2A_CanDelegateTo|A2A_RunsAs|A2A_HasScope|A2A_GrantsAccessTo|A2A_HoldsCredential|A2A_AuthenticatesTo*1..8]->(t))
RETURN p
```
 
Token issuers to write and delete operations:
 
```cypher
MATCH (s:A2A_AuthorizationServer), (t:A2A_APIOperation) WHERE t.method IN ["POST","PUT","PATCH","DELETE"]
MATCH p=allShortestPaths((s)-[:A2A_IssuesTokensFor|A2A_DefinesScope|A2A_GrantsAccessTo|A2A_AuthenticatesTo|A2A_HasSkill|A2A_BackedBy*1..6]->(t))
RETURN p
```
 
Unsigned agent cards:
 
```cypher
MATCH (a:A2A_Agent) WHERE a.signed = false RETURN a
```
 
Each agent with its skills, interfaces, extensions and auth:
 
```cypher
MATCH p=(:A2A_Agent)-[:A2A_HasSkill|A2A_ServesAgent|A2A_SupportsExtension|A2A_ProtectedBy|A2A_AuthenticatesTo|A2A_Anonymous]-()
RETURN p
LIMIT 500
```
 
Agents, skills and the API operations behind them:
 
```cypher
MATCH p=(:A2A_Agent)-[:A2A_HasSkill|A2A_BackedBy*1..2]->()
RETURN p
LIMIT 500
```
 
Every agent to every skill and operation it can reach:
 
```cypher
MATCH (s:A2A_Agent), (t) WHERE (t:A2A_Skill OR t:A2A_APIOperation) AND s <> t
MATCH p=allShortestPaths((s)-[:A2A_HasSkill|A2A_BackedBy|A2A_RunsAs|A2A_HasScope|A2A_GrantsAccessTo|A2A_HoldsCredential|A2A_AuthenticatesTo|A2A_CanDelegateTo*1..8]->(t))
RETURN p
```
 
Hosts (servers) to the agents and skills they expose, or what a host compromise reaches:
 
```cypher
MATCH (s:A2A_Host), (t:A2A_Skill)
MATCH p=allShortestPaths((s)-[:A2A_HostsInterface|A2A_ServesAgent|A2A_HostsOperation|A2A_HasSkill|A2A_RunsAs|A2A_HasScope|A2A_GrantsAccessTo|A2A_CanDelegateTo*1..8]->(t))
RETURN p
```

 
## Limitations
 
- **Card signatures** are recorded but not cryptographically verified (`verified: not_checked`).
- **OpenAPI operations with no `security` block** are linked to Anyone. If a gateway in front of the API enforces authentication, those edges are false positives.
- **Who an agent runs as and which agents it delegates to** aren't in Agent Cards. Add them with `--enrich` from your identity provider or deployment config.
- **The `environments` block** in the schema is only used by BloodHound Enterprise.
- **Nodes other than the ecosystem root** are identified by URL. The same host collected under two `--ecosystem` names becomes one node.
