#!/usr/bin/env python3
"""
A2AHound collector: turns A2A Agent Cards and OpenAPI documents into a
BloodHound OpenGraph payload that conforms to a2a-extension-schema.json.

Targets can be:
  * a host or origin   (example.com, https://agents.example.com)
      -> probes /.well-known/agent-card.json, /.well-known/agent.json
         and common OpenAPI paths (/openapi.json, /swagger.json, ...)
  * a direct URL to a JSON document (agent card or OpenAPI)
  * a local .json file (agent card or OpenAPI, detected by content)

Standard library only. See FIELD-MAPPING.md for how every field is mapped.

Examples:
  python3 a2ahound.py agents.example.com https://api.example.com/openapi.json -o a2a.json
  python3 a2ahound.py -i targets.txt -H "Authorization: Bearer $TOKEN" --extended -o a2a.json
  python3 a2ahound.py ./cards/*.json ./specs/*.json --ecosystem prod -o a2a.json
"""
import argparse
import base64
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.request
from urllib.parse import urljoin, urlsplit

SOURCE_KIND = "A2ABase"

NODE_KINDS = {
    "A2A_Ecosystem", "A2A_Provider", "A2A_Agent", "A2A_Interface", "A2A_Host",
    "A2A_Skill", "A2A_Extension", "A2A_SecurityScheme", "A2A_AuthorizationServer",
    "A2A_Scope", "A2A_Client", "A2A_PublicAccess", "A2A_SigningKey",
    "A2A_APISpec", "A2A_APIOperation",
}
EDGE_KINDS = {
    "A2A_Contains", "A2A_Publishes", "A2A_HostsInterface", "A2A_ServesAgent",
    "A2A_HasSkill", "A2A_SupportsExtension", "A2A_HostsOperation",
    "A2A_DefinesOperation", "A2A_DescribedBy", "A2A_BackedBy", "A2A_ProtectedBy",
    "A2A_AuthenticatesTo", "A2A_TrustsIssuer", "A2A_IssuesTokensFor",
    "A2A_DefinesScope", "A2A_GrantsAccessTo", "A2A_HasScope", "A2A_HoldsCredential",
    "A2A_RunsAs", "A2A_CanDelegateTo", "A2A_Anonymous", "A2A_SignsCard",
    "A2A_SameAgentAs",
}

AGENT_CARD_PATHS = ["/.well-known/agent-card.json", "/.well-known/agent.json"]
OPENAPI_PATHS = ["/openapi.json", "/swagger.json", "/v3/api-docs", "/api-docs",
                 "/docs/openapi.json", "/api/openapi.json", "/openapi/v1.json",
                 "/swagger/v1/swagger.json"]
HTTP_METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")
MAX_BYTES = 10 * 1024 * 1024
DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443, "grpc": 443, "grpcs": 443}

SCHEME_WRAPPERS = {
    "apiKeySecurityScheme": "apiKey",
    "httpAuthSecurityScheme": "http",
    "oauth2SecurityScheme": "oauth2",
    "openIdConnectSecurityScheme": "openIdConnect",
    "mtlsSecurityScheme": "mutualTls",
    "mutualTlsSecurityScheme": "mutualTls",
}
SCHEME_TYPE_ALIASES = {"apikey": "apiKey", "http": "http", "basic": "http", "oauth2": "oauth2",
                       "openidconnect": "openIdConnect", "mutualtls": "mutualTls", "mtls": "mutualTls"}


def log(*a):
    print(*a, file=sys.stderr)


# ---------------------------------------------------------------- URL helpers

def origin(url):
    """scheme://host:port with default port filled in, or None."""
    if not url or not isinstance(url, str):
        return None
    if "://" not in url:
        url = "https://" + url
    p = urlsplit(url)
    scheme = (p.scheme or "https").lower()
    host = (p.hostname or "").lower()
    if not host:
        return None
    try:
        port = p.port or DEFAULT_PORTS.get(scheme)
    except ValueError:
        port = DEFAULT_PORTS.get(scheme)
    if ":" in host:
        host = f"[{host}]"
    return f"{scheme}://{host}:{port}" if port else f"{scheme}://{host}"


def canon_issuer(url):
    """Issuer identifier: lowercase scheme/host, default port dropped, no trailing slash."""
    if not url:
        return None
    p = urlsplit(url if "://" in url else "https://" + url)
    host = (p.hostname or "").lower()
    try:
        port = p.port
    except ValueError:
        port = None
    if port and port == DEFAULT_PORTS.get(p.scheme.lower()):
        port = None
    return f"{p.scheme.lower()}://{host}{':' + str(port) if port else ''}{p.path}".rstrip("/")


def norm_url(url):
    o = origin(url)
    if not o:
        return url
    p = urlsplit(url if "://" in url else "https://" + url)
    out = o + (p.path.rstrip("/") or "")
    return out + ("?" + p.query if p.query else "")


def is_http(url):
    return isinstance(url, str) and url.lower().startswith(("http://", "https://"))


def norm_token(s):
    return re.sub(r"[^a-z0-9]", "", str(s or "").lower())


def b64json(s):
    if not isinstance(s, str):
        return None
    try:
        return json.loads(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)).decode("utf-8"))
    except Exception:
        return None


def doc_kind(doc):
    if not isinstance(doc, dict):
        return None
    if "openapi" in doc or "swagger" in doc:
        return "openapi"
    if "skills" in doc or "supportedInterfaces" in doc or ("capabilities" in doc and "name" in doc):
        return "card"
    return None


# ---------------------------------------------------------------- HTTP

class Fetcher:
    """GET/POST JSON. User-supplied headers go only to the target hosts and are
    stripped on cross-host redirects, so credentials don't leak to discovered URLs."""

    def __init__(self, headers, auth_hosts, timeout, insecure):
        self.user_headers = headers
        self.auth_hosts = auth_hosts
        self.timeout = timeout
        self.cache = {}
        ctx = ssl._create_unverified_context() if insecure else ssl.create_default_context()
        strip = {h.lower() for h in headers} | {"authorization", "cookie"}

        class SafeRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, hdrs, newurl):
                new = super().redirect_request(req, fp, code, msg, hdrs, newurl)
                if new is not None and urlsplit(newurl).hostname != urlsplit(req.full_url).hostname:
                    for h in list(new.headers):
                        if h.lower() in strip:
                            del new.headers[h]
                return new

        self.opener = urllib.request.build_opener(SafeRedirect, urllib.request.HTTPSHandler(context=ctx))

    def json(self, url, method="GET", body=None, quiet=False):
        key = (method, url, json.dumps(body, sort_keys=True) if body is not None else None)
        if key in self.cache:
            return self.cache[key]
        hdrs = {"Accept": "application/json", "User-Agent": "A2AHound/1.0"}
        if (urlsplit(url).hostname or "").lower() in self.auth_hosts:
            hdrs.update(self.user_headers)
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            hdrs["Content-Type"] = "application/json"
        res = None
        try:
            req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
            with self.opener.open(req, timeout=self.timeout) as r:
                raw = r.read(MAX_BYTES + 1)
                if len(raw) > MAX_BYTES:
                    raise ValueError("response larger than 10 MB")
                res = (r.geturl(), json.loads(raw.decode("utf-8-sig")))
        except (urllib.error.URLError, OSError, ValueError) as e:
            if not quiet:
                log(f"  - {method} {url}: {getattr(e, 'reason', e)}")
        self.cache[key] = res
        return res


# ---------------------------------------------------------------- graph

class Graph:
    def __init__(self):
        self.nodes = {}
        self.edges = {}

    def node(self, nid, kind, **props):
        n = self.nodes.get(nid)
        if n is None:
            n = self.nodes[nid] = {"id": nid, "kinds": [kind], "properties": {}}
        elif kind not in n["kinds"]:
            n["kinds"].append(kind)
        for k, v in props.items():
            if v is not None:
                n["properties"][k] = v
        return nid

    def edge(self, kind, start, end, **props):
        e = self.edges.setdefault((kind, start, end), {})
        for k, v in props.items():
            if v is None:
                continue
            if isinstance(v, list) and isinstance(e.get(k), list):
                e[k] = sorted(set(e[k]) | set(v), key=str)
            else:
                e[k] = v


def clean(v):
    """OpenGraph properties: primitives or homogeneous arrays of primitives."""
    if v is None:
        return None
    if isinstance(v, (bool, int, float, str)):
        return v
    if isinstance(v, (list, tuple, set)):
        items = [x for x in (sorted(v, key=str) if isinstance(v, set) else v) if x is not None]
        if not items:
            return None
        if all(isinstance(x, str) for x in items) or all(isinstance(x, bool) for x in items):
            return list(items)
        if all(isinstance(x, (int, float)) and not isinstance(x, bool) for x in items):
            return list(items)
        return [x if isinstance(x, str) else json.dumps(x, sort_keys=True) for x in items]
    return json.dumps(v, sort_keys=True)


# ---------------------------------------------------------------- collector

class Collector:
    def __init__(self, args):
        self.a = args
        self.g = Graph()
        self.eco = f"A2A-ECO:{args.ecosystem}"
        self.g.node(self.eco, "A2A_Ecosystem", name=args.ecosystem.upper(), displayname=args.ecosystem)
        self.public = None
        self.agents = []          # dicts: id, name, version, provider, origins, docurl, links, skills, extended
        self.specs = {}           # url -> dict: id, url, origins, ops
        self.schemes = {}         # (owner_id, scheme name) -> {"id", "issuer", "type"}
        self.probed_openapi = set()
        self.seen_cards = set()
        self.issuer_cache = {}
        headers = {}
        for h in args.header or []:
            if ":" not in h:
                sys.exit(f"bad header (want 'Name: value'): {h}")
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
        self.auth_hosts = set()
        self.fetch = Fetcher(headers, self.auth_hosts, args.timeout, args.insecure)

    # ---- helpers
    def contains(self, nid):
        self.g.edge("A2A_Contains", self.eco, nid)

    def public_node(self):
        if not self.public:
            self.public = f"A2A-PUBLIC:{self.a.ecosystem}"
            self.g.node(self.public, "A2A_PublicAccess", name="ANYONE (UNAUTHENTICATED)",
                        displayname="Anyone (Unauthenticated)")
            self.contains(self.public)
        return self.public

    def host(self, url):
        o = origin(url)
        if not o:
            return None
        p = urlsplit(o)
        hid = f"A2A-HOST:{o}"
        self.g.node(hid, "A2A_Host", name=o, scheme=p.scheme, hostname=p.hostname,
                    port=p.port, tls=p.scheme in ("https", "wss", "grpcs"))
        self.contains(hid)
        return hid

    # ---- discovery
    def run(self, targets):
        for t in targets:
            if os.path.isfile(t):
                self.load_file(t)
                continue
            url = t if "://" in t else "https://" + t
            host = (urlsplit(url).hostname or "").lower()
            if host:
                self.auth_hosts.add(host)
            path = urlsplit(url).path
            if path and path != "/":
                res = self.fetch.json(url)
                if res:
                    self.handle_doc(res[1], res[0])
            else:
                self.probe_origin(url)
        self.correlate()
        if self.a.enrich:
            self.enrich(json.load(open(self.a.enrich, encoding="utf-8")))

    def load_file(self, path):
        try:
            doc = json.load(open(path, encoding="utf-8-sig"))
        except (OSError, ValueError) as e:
            log(f"  - {path}: {e}")
            return
        self.handle_doc(doc, None, source=os.path.abspath(path))

    def probe_origin(self, url):
        o = origin(url)
        if not o:
            return
        log(f"[*] probing {o}")
        base = o.rsplit(":", 1)[0] if o.endswith((":443", ":80")) else o
        for p in AGENT_CARD_PATHS:
            res = self.fetch.json(base + p, quiet=True)
            if res and doc_kind(res[1]) == "card":
                self.handle_doc(res[1], res[0])
                break
        if not self.a.no_probe_openapi:
            self.probe_openapi(o)

    def probe_openapi(self, o):
        if o in self.probed_openapi or not is_http(o):
            return
        self.probed_openapi.add(o)
        base = o.rsplit(":", 1)[0] if o.endswith((":443", ":80")) else o
        for p in OPENAPI_PATHS:
            res = self.fetch.json(base + p, quiet=True)
            if res and doc_kind(res[1]) == "openapi":
                self.handle_doc(res[1], res[0])
                break

    def handle_doc(self, doc, url, source=None):
        kind = doc_kind(doc)
        if kind == "card":
            self.parse_card(doc, url, source=source)
        elif kind == "openapi":
            self.parse_openapi(doc, url, source=source)
        else:
            log(f"  - {url or source}: not an agent card or OpenAPI document, skipped")

    # ---- security
    def norm_scheme(self, raw):
        if not isinstance(raw, dict):
            return {"type": "unknown"}
        for k, t in SCHEME_WRAPPERS.items():
            if isinstance(raw.get(k), dict):
                d = dict(raw[k])
                d["type"] = t
                return d
        d = dict(raw)
        t = str(d.get("type") or "unknown")
        if t.lower() == "basic":          # Swagger 2
            d.setdefault("scheme", "basic")
        d["type"] = SCHEME_TYPE_ALIASES.get(t.lower(), t)
        if d["type"] == "oauth2" and "flow" in d and "flows" not in d:   # Swagger 2
            d["flows"] = {d["flow"]: {k: d.get(k) for k in ("authorizationUrl", "tokenUrl", "scopes")}}
        return d

    def issuer_for(self, sc, base):
        def absu(u):
            return urljoin(base, u) if (u and base and is_http(base)) else u
        oidc, meta = absu(sc.get("openIdConnectUrl")), absu(sc.get("oauth2MetadataUrl"))
        flows = sc.get("flows") if isinstance(sc.get("flows"), dict) else {}
        token = auth = None
        for f in flows.values():
            if isinstance(f, dict):
                token = token or absu(f.get("tokenUrl"))
                auth = auth or absu(f.get("authorizationUrl"))
        disc = oidc or meta
        if disc and self.a.resolve_issuers and is_http(disc):
            if disc not in self.issuer_cache:
                res = self.fetch.json(disc, quiet=True)
                self.issuer_cache[disc] = res[1].get("issuer") if res and isinstance(res[1], dict) else None
            if self.issuer_cache[disc]:
                return canon_issuer(self.issuer_cache[disc]), token, auth
        if oidc:
            return canon_issuer(oidc.split("/.well-known/")[0]), token, auth
        if meta:
            head, _, tail = meta.partition("/.well-known/oauth-authorization-server")
            return canon_issuer(head + tail), token, auth
        if token or auth:
            return canon_issuer(origin(token or auth)), token, auth
        return None, token, auth

    def scope(self, issuer, name, description=None, flows=None):
        sid = f"A2A-SCOPE:{issuer}/{name}"
        self.g.node(sid, "A2A_Scope", name=f"{name} @ {issuer}", scope=name, issuer=issuer,
                    description=description, flows=flows)
        self.g.edge("A2A_DefinesScope", f"A2A-AS:{issuer}", sid)
        return sid

    def register_schemes(self, raw_schemes, owner, base):
        if not isinstance(raw_schemes, dict):
            return
        for name, raw in raw_schemes.items():
            sc = self.norm_scheme(raw)
            sid = f"A2A-SEC:{owner}/{name}"
            flows = sc.get("flows") if isinstance(sc.get("flows"), dict) else {}
            issuer, token, auth = (None, None, None)
            if sc["type"] in ("oauth2", "openIdConnect"):
                issuer, token, auth = self.issuer_for(sc, base)
            refresh = next((f.get("refreshUrl") for f in flows.values()
                            if isinstance(f, dict) and f.get("refreshUrl")), None)
            self.g.node(sid, "A2A_SecurityScheme", name=f"{name} ({sc['type']})", schemename=name,
                        type=sc["type"], description=sc.get("description"),
                        **{"in": sc.get("in") or sc.get("location")},
                        keyname=sc.get("name") if sc["type"] == "apiKey" else None,
                        scheme=sc.get("scheme"), bearerformat=sc.get("bearerFormat"),
                        flows=list(flows) or None, tokenurl=token, authorizationurl=auth,
                        refreshurl=refresh, oauth2metadataurl=sc.get("oauth2MetadataUrl"),
                        openidconnecturl=sc.get("openIdConnectUrl"), issuer=issuer, owner=owner)
            if issuer:
                aid = f"A2A-AS:{issuer}"
                self.g.node(aid, "A2A_AuthorizationServer", name=issuer, issuer=issuer,
                            tokenurl=token, authorizationurl=auth)
                self.contains(aid)
                self.g.edge("A2A_IssuesTokensFor", aid, sid)
                self.g.edge("A2A_TrustsIssuer", sid, aid)
                for fname, f in flows.items():
                    if isinstance(f, dict) and isinstance(f.get("scopes"), dict):
                        for sname, desc in f["scopes"].items():
                            self.scope(issuer, sname, desc if isinstance(desc, str) else None, [fname])
            self.schemes[(owner, name)] = {"id": sid, "issuer": issuer, "type": sc["type"]}

    @staticmethod
    def norm_reqs(v1, legacy):
        """None = not specified; [] = explicitly no auth; else list of {scheme: [scopes]} alternatives."""
        raw = v1 if v1 is not None else legacy
        if raw is None:
            return None
        out = []
        for item in raw if isinstance(raw, list) else []:
            if not isinstance(item, dict):
                continue
            m = item["schemes"] if isinstance(item.get("schemes"), dict) else item
            g = {}
            for name, val in m.items():
                if isinstance(val, dict):
                    scopes = val.get("list") or val.get("scopes") or []
                elif isinstance(val, list):
                    scopes = val
                else:
                    scopes = []
                g[str(name)] = [str(x) for x in scopes]
            out.append(g)
        return out

    def apply_reqs(self, target, reqs, owner):
        if not reqs or any(len(g) == 0 for g in reqs):
            reason = "no_security_requirement" if not reqs else "optional_security"
            self.g.edge("A2A_Anonymous", self.public_node(), target, reason=reason)
        for gi, group in enumerate(reqs or []):
            for name, scopes in group.items():
                sc = self.schemes.get((owner, name))
                if not sc:   # referenced but never declared
                    sid = f"A2A-SEC:{owner}/{name}"
                    self.g.node(sid, "A2A_SecurityScheme", name=f"{name} (undeclared)",
                                schemename=name, type="undeclared", owner=owner)
                    sc = self.schemes[(owner, name)] = {"id": sid, "issuer": None, "type": "undeclared"}
                self.g.edge("A2A_ProtectedBy", target, sc["id"], scopes=scopes, requirement_group=[gi])
            if len(group) == 1:
                (name, scopes), = group.items()
                sc = self.schemes[(owner, name)]
                self.g.edge("A2A_AuthenticatesTo", sc["id"], target)
                # one scope alone only satisfies the requirement when it is the only one required
                if sc["issuer"] and len(scopes) == 1:
                    self.g.edge("A2A_GrantsAccessTo", self.scope(sc["issuer"], scopes[0]), target)

    # ---- agent cards
    @staticmethod
    def interfaces(card, url):
        out, seen = [], set()

        def add(u, binding, pv, tenant):
            if not isinstance(u, str) or not u:
                return
            if url and is_http(url) and "://" not in u:
                u = urljoin(url, u)
            key = (binding, norm_url(u), tenant)
            if key not in seen:
                seen.add(key)
                out.append({"url": u, "binding": binding, "pv": pv, "tenant": tenant})

        for i in card.get("supportedInterfaces") or []:
            if isinstance(i, dict):
                add(i.get("url"), i.get("protocolBinding") or i.get("transport") or "JSONRPC",
                    i.get("protocolVersion"), i.get("tenant"))
        if card.get("url"):
            add(card["url"], card.get("preferredTransport") or "JSONRPC", card.get("protocolVersion"), None)
        for i in card.get("additionalInterfaces") or []:
            if isinstance(i, dict):
                add(i.get("url"), i.get("transport") or "JSONRPC", card.get("protocolVersion"), None)
        return out

    def parse_card(self, card, url, extended=False, source=None):
        name = str(card.get("name") or "unnamed-agent")
        version = str(card.get("version") or "")
        ifaces = self.interfaces(card, url)
        card_origin = origin(url) if is_http(url) else (origin(ifaces[0]["url"]) if ifaces else "local")
        aid = f"A2A-AGENT:{card_origin}/{name}@{version}" + ("#extended" if extended else "")
        if aid in self.seen_cards:
            return aid
        self.seen_cards.add(aid)
        log(f"[+] agent card: {name} {version} ({url or source})")
        caps = card.get("capabilities") if isinstance(card.get("capabilities"), dict) else {}
        path = urlsplit(url).path if url else ""
        sigs = [s for s in card.get("signatures") or [] if isinstance(s, dict)]
        self.g.node(
            aid, "A2A_Agent", name=name + (" (extended card)" if extended else ""), displayname=name,
            description=card.get("description"), version=version, iconurl=card.get("iconUrl"),
            documentationurl=card.get("documentationUrl"), cardurl=url or source,
            cardpath="agent.json" if path.endswith("/agent.json") else
                     "agent-card.json" if path.endswith("agent-card.json") else None,
            cardformat="v1" if "supportedInterfaces" in card else "legacy",
            protocolversion=card.get("protocolVersion") or (ifaces[0]["pv"] if ifaces else None),
            defaultinputmodes=card.get("defaultInputModes"), defaultoutputmodes=card.get("defaultOutputModes"),
            streaming=caps.get("streaming"), pushnotifications=caps.get("pushNotifications"),
            extendedcard=caps.get("extendedAgentCard", card.get("supportsAuthenticatedExtendedCard")),
            statetransitionhistory=caps.get("stateTransitionHistory"),
            signed=bool(sigs), extended=extended, skillcount=len(card.get("skills") or []),
        )
        self.contains(aid)

        # provider
        prov = card.get("provider") if isinstance(card.get("provider"), dict) else None
        provider_key = None
        if prov and (prov.get("organization") or prov.get("url")):
            provider_key = (urlsplit(prov["url"]).hostname if is_http(prov.get("url")) else None) \
                or str(prov.get("organization")).lower()
            pid = f"A2A-PROV:{provider_key.lower()}"
            self.g.node(pid, "A2A_Provider", name=prov.get("organization") or provider_key, url=prov.get("url"))
            self.contains(pid)
            self.g.edge("A2A_Publishes", pid, aid)
            self.g.edge("A2A_Contains", pid, aid)

        # interfaces + hosts
        origins = {card_origin} if card_origin != "local" else set()
        for idx, i in enumerate(ifaces):
            iid = f"A2A-IF:{i['binding']}:{norm_url(i['url'])}" + (f":{i['tenant']}" if i["tenant"] else "")
            scheme = urlsplit(i["url"]).scheme.lower() if "://" in i["url"] else "https"
            self.g.node(iid, "A2A_Interface", name=f"{i['binding']} {i['url']}", url=i["url"],
                        protocolbinding=i["binding"], protocolversion=i["pv"], tenant=i["tenant"],
                        preferred=(idx == 0), tls=scheme in ("https", "wss", "grpcs"))
            self.g.edge("A2A_ServesAgent", iid, aid)
            hid = self.host(i["url"])
            if hid:
                self.g.edge("A2A_HostsInterface", hid, iid)
                origins.add(origin(i["url"]))
            if scheme in ("http", "ws"):
                self.g.edge("A2A_Anonymous", self.public_node(), iid, reason="cleartext_interface")
        if card_origin != "local":
            self.host(card_origin)

        # extensions
        for e in caps.get("extensions") or []:
            if isinstance(e, dict) and e.get("uri"):
                eid = f"A2A-EXT:{e['uri']}"
                self.g.node(eid, "A2A_Extension", name=e["uri"], uri=e["uri"], description=e.get("description"))
                self.g.edge("A2A_SupportsExtension", aid, eid, required=bool(e.get("required")),
                            params=json.dumps(e["params"], sort_keys=True) if e.get("params") else None)

        # security
        self.register_schemes(card.get("securitySchemes"), aid, url)
        card_reqs = self.norm_reqs(card.get("securityRequirements"), card.get("security")) or []
        self.apply_reqs(aid, card_reqs, aid)

        # skills
        skills = {}
        for sk in card.get("skills") or []:
            if not isinstance(sk, dict):
                continue
            skid = str(sk.get("id") or sk.get("name") or "skill")
            sid = f"A2A-SKILL:{aid}/{skid}"
            own = self.norm_reqs(sk.get("securityRequirements"), sk.get("security"))
            effective = "own" if own else ("none" if own == [] or not card_reqs else "inherited")
            self.g.node(sid, "A2A_Skill", name=f"{sk.get('name') or skid} ({name})", skillid=skid,
                        skillname=sk.get("name"), description=sk.get("description"), tags=sk.get("tags"),
                        examples=sk.get("examples"),
                        inputmodes=sk.get("inputModes") or card.get("defaultInputModes"),
                        outputmodes=sk.get("outputModes") or card.get("defaultOutputModes"),
                        effectiveauth=effective, agent=name)
            self.g.edge("A2A_HasSkill", aid, sid)
            # Inherited requirements are already modelled on the agent (scheme -> agent -> skill).
            if own is not None:
                self.apply_reqs(sid, own, aid)
            skills[skid] = {"id": sid, "name": sk.get("name"), "tags": sk.get("tags") or []}

        # signatures
        for s in sigs:
            hdr = b64json(s.get("protected")) or {}
            if isinstance(s.get("header"), dict):
                hdr = {**s["header"], **hdr}
            if not (hdr.get("kid") or hdr.get("jku")):
                continue
            kid = f"A2A-KEY:{hdr.get('jku') or card_origin}#{hdr.get('kid') or '?'}"
            self.g.node(kid, "A2A_SigningKey", name=f"{hdr.get('kid') or 'key'} ({hdr.get('alg') or '?'})",
                        kid=hdr.get("kid"), alg=hdr.get("alg"), jku=hdr.get("jku"), typ=hdr.get("typ"))
            self.g.edge("A2A_SignsCard", kid, aid, verified="not_checked")

        links = {card.get("documentationUrl")} | {v for k, v in card.items()
                                                   if k.startswith("x-") and "openapi" in k.lower()
                                                   and isinstance(v, str)}
        links = {urljoin(url, l) if url and is_http(url) else l for l in links if l}
        self.agents.append({"id": aid, "name": name, "version": version, "provider": provider_key,
                            "origins": origins, "links": links, "skills": skills, "extended": extended})

        # follow-ups: linked OpenAPI docs, OpenAPI at interface origins, extended card
        for l in links:
            if is_http(l) and l.lower().split("?")[0].endswith((".json", "api-docs")):
                res = self.fetch.json(l, quiet=True)
                if res and doc_kind(res[1]) == "openapi":
                    self.handle_doc(res[1], res[0])
        if not self.a.no_follow_interfaces and not self.a.no_probe_openapi:
            for o in origins:
                self.probe_openapi(o)
        if self.a.extended and not extended and (caps.get("extendedAgentCard")
                                                 or card.get("supportsAuthenticatedExtendedCard")):
            self.fetch_extended(card, url, ifaces, aid)
        return aid

    def fetch_extended(self, card, url, ifaces, public_id):
        doc = None
        if card.get("supportsAuthenticatedExtendedCard") and is_http(url):
            res = self.fetch.json(urljoin(url, "/agent/authenticatedExtendedCard"), quiet=True)
            doc = res[1] if res and doc_kind(res[1]) == "card" else None
        for i in ifaces:
            if doc:
                break
            if i["binding"].upper() == "JSONRPC" and is_http(i["url"]):
                for m in ("GetExtendedAgentCard", "agent/getAuthenticatedExtendedCard"):
                    res = self.fetch.json(i["url"], "POST", {"jsonrpc": "2.0", "id": 1, "method": m,
                                                             "params": {}}, quiet=True)
                    r = res[1].get("result") if res and isinstance(res[1], dict) else None
                    if doc_kind(r) == "card":
                        doc = r
                        break
            elif i["binding"].upper() == "HTTP+JSON" and is_http(i["url"]):
                for p in ("/extendedAgentCard", "/v1/card"):
                    res = self.fetch.json(i["url"].rstrip("/") + p, quiet=True)
                    if res and doc_kind(res[1]) == "card":
                        doc = res[1]
                        break
        if doc:
            eid = self.parse_card(doc, url, extended=True)
            self.g.edge("A2A_SameAgentAs", eid, public_id, reason="extended_card")
        else:
            log(f"  - extended card for {card.get('name')} not retrieved (needs --header credentials?)")

    # ---- OpenAPI
    @staticmethod
    def servers(doc, url):
        out = []
        if "swagger" in doc:
            p = urlsplit(url) if is_http(url) else None
            host = doc.get("host") or (p.netloc if p else None)
            if host:
                for sch in doc.get("schemes") or [p.scheme if p else "https"]:
                    out.append(f"{sch}://{host}{doc.get('basePath') or ''}")
        else:
            for srv in doc.get("servers") or [{"url": "/"}]:
                if not isinstance(srv, dict):
                    continue
                u = str(srv.get("url") or "/")
                for var, spec in (srv.get("variables") or {}).items():
                    if isinstance(spec, dict) and "default" in spec:
                        u = u.replace("{" + var + "}", str(spec["default"]))
                if "://" not in u and is_http(url):
                    u = urljoin(url, u)
                if "://" in u:
                    out.append(u)
        return list(dict.fromkeys(s.rstrip("/") for s in out))

    def parse_openapi(self, doc, url, source=None):
        key = url or source
        if key in self.specs:
            return
        info = doc.get("info") if isinstance(doc.get("info"), dict) else {}
        spid = f"A2A-OAS:{key}"
        servers = self.servers(doc, url)
        log(f"[+] openapi: {info.get('title') or key} ({len(servers)} server(s))")
        tags = [t.get("name") for t in doc.get("tags") or [] if isinstance(t, dict) and t.get("name")]
        self.g.node(spid, "A2A_APISpec", name=info.get("title") or key, version=info.get("version"),
                    openapiversion=doc.get("openapi") or doc.get("swagger"), description=info.get("description"),
                    contact=info.get("contact"), docsurl=(doc.get("externalDocs") or {}).get("url")
                    if isinstance(doc.get("externalDocs"), dict) else None,
                    tags=tags, servers=servers, sourceurl=key)
        self.contains(spid)
        comps = doc.get("components") if isinstance(doc.get("components"), dict) else {}
        self.register_schemes(comps.get("securitySchemes") or doc.get("securityDefinitions"), spid, url)
        root = self.norm_reqs(None, doc.get("security")) or []
        spec = {"id": spid, "url": key, "origins": {origin(s) for s in servers}, "ops": []}
        for path, item in (doc.get("paths") or {}).items():
            if not isinstance(item, dict):
                continue
            for m in HTTP_METHODS:
                op = item.get(m)
                if not isinstance(op, dict):
                    continue
                reqs = self.norm_reqs(None, op["security"]) if "security" in op else root
                req_types, resp_types = set(), set()
                if isinstance(op.get("requestBody"), dict):
                    req_types |= set((op["requestBody"].get("content") or {}).keys())
                for r in (op.get("responses") or {}).values():
                    if isinstance(r, dict):
                        resp_types |= set((r.get("content") or {}).keys())
                req_types |= set(op.get("consumes") or doc.get("consumes") or []) if "swagger" in doc else set()
                resp_types |= set(op.get("produces") or doc.get("produces") or []) if "swagger" in doc else set()
                xprops = {k: v for k, v in op.items() if k.startswith("x-")}
                for base in servers or [None]:
                    oid = f"A2A-OP:{base or spid} {m.upper()} {path}"
                    self.g.node(oid, "A2A_APIOperation", name=f"{m.upper()} {(base or '') + path}",
                                method=m.upper(), path=path, url=(base + path) if base else None,
                                operationid=op.get("operationId"), summary=op.get("summary"),
                                description=op.get("description"), tags=op.get("tags"),
                                deprecated=bool(op.get("deprecated", False)),
                                requestmediatypes=req_types or None, responsemediatypes=resp_types or None,
                                a2askill=op.get("x-a2a-skill"), xproperties=xprops or None,
                                effectiveauth="none" if not reqs else ("own" if "security" in op else "inherited"))
                    self.g.edge("A2A_DefinesOperation", spid, oid)
                    hid = self.host(base) if base else None
                    if hid:
                        self.g.edge("A2A_HostsOperation", hid, oid)
                    self.apply_reqs(oid, reqs, spid)
                    spec["ops"].append({"id": oid, "op": op, "origin": origin(base) if base else None,
                                        "method": m.upper(), "path": path})
        self.specs[key] = spec

    # ---- correlation
    def correlate(self):
        skill_map = []
        if self.a.skill_map:
            skill_map = json.load(open(self.a.skill_map, encoding="utf-8"))
        for ag in self.agents:
            linked = set()
            for spec in self.specs.values():
                if spec["url"] in ag["links"]:
                    self.g.edge("A2A_DescribedBy", ag["id"], spec["id"], match="explicit")
                    linked.add(spec["url"])
                elif ag["origins"] & spec["origins"]:
                    self.g.edge("A2A_DescribedBy", ag["id"], spec["id"], match="origin")
                    linked.add(spec["url"])
            for skid, sk in ag["skills"].items():
                for spec in self.specs.values():
                    for o in spec["ops"]:
                        conf, how = self.match(ag, skid, sk, spec, o, linked, skill_map)
                        if conf >= self.a.min_confidence:
                            self.g.edge("A2A_BackedBy", sk["id"], o["id"], match=how, confidence=conf)
        # same agent published at several origins
        groups = {}
        for ag in self.agents:
            if not ag["extended"]:
                groups.setdefault((ag["name"], ag["version"], ag["provider"]), []).append(ag["id"])
        for ids in groups.values():
            for other in ids[1:]:
                self.g.edge("A2A_SameAgentAs", other, ids[0], reason="same_card_multiple_origins")

    @staticmethod
    def match(ag, skid, sk, spec, o, linked, skill_map):
        op = o["op"]
        for m in skill_map:
            if m.get("skill") != skid or (m.get("agent") and m["agent"] != ag["name"]):
                continue
            if m.get("operationId") and m["operationId"] == op.get("operationId"):
                return 1.0, "explicit"
            if m.get("path") and m["path"] == o["path"] and m.get("method", o["method"]).upper() == o["method"]:
                return 1.0, "explicit"
        related = spec["url"] in linked or (o["origin"] and o["origin"] in ag["origins"])
        if not related:
            return 0.0, None
        if op.get("x-a2a-skill") in (skid, sk.get("name")):
            return 1.0, "explicit"
        oid = norm_token(op.get("operationId"))
        if oid and oid in (norm_token(skid), norm_token(sk.get("name"))):
            return 0.9, "operationid"
        st = {str(t).lower() for t in sk.get("tags") or []}
        ot = {str(t).lower() for t in op.get("tags") or []}
        if st & ot:
            return 0.5, "tag"
        return 0.0, None

    # ---- enrichment (IdP / deployment data that isn't in cards or specs)
    def enrich(self, data):
        by_name = {}
        for ag in self.agents:
            if not ag["extended"]:
                by_name.setdefault(ag["name"], []).append(ag["id"])
        spec_ids = {k: v["id"] for k, v in self.specs.items()}
        clients = {}
        for c in data.get("clients") or []:
            issuer = canon_issuer(c.get("issuer")) or "local"
            cid = f"A2A-CLIENT:{issuer}/{c['id']}"
            clients[c["id"]] = cid
            self.g.node(cid, "A2A_Client", name=c.get("name") or c["id"], clientid=c["id"],
                        issuer=c.get("issuer"), type=c.get("type"))
            if c.get("issuer"):
                self.g.node(f"A2A-AS:{issuer}", "A2A_AuthorizationServer", name=issuer, issuer=issuer)
                self.contains(f"A2A-AS:{issuer}")
                for s in c.get("scopes") or []:
                    self.g.edge("A2A_HasScope", cid, self.scope(issuer, s))
            for cred in c.get("credentials") or []:
                owners = by_name.get(cred.get("agent"), []) + (
                    [spec_ids[cred["openapi"]]] if cred.get("openapi") in spec_ids else [])
                for owner in owners:
                    sc = self.schemes.get((owner, cred.get("scheme")))
                    if sc:
                        self.g.edge("A2A_HoldsCredential", cid, sc["id"])
        for r in data.get("runs_as") or []:
            for aid in by_name.get(r.get("agent"), []):
                if r.get("client") in clients:
                    self.g.edge("A2A_RunsAs", aid, clients[r["client"]])
        for d in data.get("delegations") or []:
            for a in by_name.get(d.get("from"), []):
                for b in by_name.get(d.get("to"), []):
                    self.g.edge("A2A_CanDelegateTo", a, b, source=d.get("source"))

    # ---- output
    def payload(self):
        nodes = []
        for n in self.g.nodes.values():
            props = {k: clean(v) for k, v in n["properties"].items()}
            props = {k: v for k, v in props.items() if v is not None}
            props.setdefault("name", n["id"])
            props["environmentid"] = self.eco
            nodes.append({"id": n["id"], "kinds": n["kinds"], "properties": props})
        edges = []
        for (kind, s, e), props in self.g.edges.items():
            p = {k: clean(v) for k, v in props.items()}
            edge = {"kind": kind, "start": {"value": s, "match_by": "id"},
                    "end": {"value": e, "match_by": "id"}}
            p = {k: v for k, v in p.items() if v is not None}
            if p:
                edge["properties"] = p
            edges.append(edge)
        return {"metadata": {"source_kind": SOURCE_KIND}, "graph": {"nodes": nodes, "edges": edges}}


def validate(payload):
    ids = {n["id"] for n in payload["graph"]["nodes"]}
    problems = []
    for n in payload["graph"]["nodes"]:
        if not set(n["kinds"]) <= NODE_KINDS:
            problems.append(f"node {n['id']}: unknown kind {n['kinds']}")
    for e in payload["graph"]["edges"]:
        if e["kind"] not in EDGE_KINDS:
            problems.append(f"edge kind {e['kind']} not in schema")
        for end in ("start", "end"):
            if e[end]["value"] not in ids:
                problems.append(f"{e['kind']} {end} {e[end]['value']} has no node")
    return problems


def main():
    ap = argparse.ArgumentParser(description="Collect A2A agent cards + OpenAPI docs into a BloodHound OpenGraph payload.",
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("targets", nargs="*", help="hosts, URLs, or local .json files")
    ap.add_argument("-i", "--input-list", help="file with one target per line")
    ap.add_argument("-o", "--output", default="a2ahound-payload.json")
    ap.add_argument("--ecosystem", default="a2a", help="name of the A2A_Ecosystem (environment) node")
    ap.add_argument("-H", "--header", action="append",
                    help="'Name: value' sent only to the hosts you listed as targets (repeatable)")
    ap.add_argument("--extended", action="store_true", help="also fetch authenticated extended agent cards")
    ap.add_argument("--resolve-issuers", action="store_true", help="fetch OIDC/OAuth discovery docs for exact issuer")
    ap.add_argument("--no-probe-openapi", action="store_true", help="don't probe common OpenAPI paths")
    ap.add_argument("--no-follow-interfaces", action="store_true",
                    help="don't probe OpenAPI paths on interface hosts found in agent cards")
    ap.add_argument("--skill-map", help="JSON list of {agent?, skill, operationId | method+path} links")
    ap.add_argument("--enrich", help="JSON with clients / runs_as / delegations (see FIELD-MAPPING.md)")
    ap.add_argument("--min-confidence", type=float, default=0.8,
                    help="minimum skill-to-operation match confidence (0.5 adds tag matches)")
    ap.add_argument("--timeout", type=float, default=10)
    ap.add_argument("--insecure", action="store_true", help="skip TLS certificate verification")
    a = ap.parse_args()

    targets = list(a.targets)
    if a.input_list:
        with open(a.input_list, encoding="utf-8") as f:
            targets += [l.strip() for l in f if l.strip() and not l.startswith("#")]
    if not targets:
        ap.error("give at least one target")

    c = Collector(a)
    c.run(targets)
    payload = c.payload()
    problems = validate(payload)
    for p in problems:
        log(f"[!] {p}")
    with open(a.output, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    counts = {}
    for n in payload["graph"]["nodes"]:
        counts[n["kinds"][0]] = counts.get(n["kinds"][0], 0) + 1
    log(f"[=] wrote {a.output}: {len(payload['graph']['nodes'])} nodes, {len(payload['graph']['edges'])} edges")
    log("    " + ", ".join(f"{k.replace('A2A_', '')}={v}" for k, v in sorted(counts.items())))
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
