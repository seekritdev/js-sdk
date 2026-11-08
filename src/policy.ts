/**
 * The allowlist — which secret may be injected toward which upstream.
 *
 * This is the same evaluation the proxy performs (`crates/seekrit-core`'s
 * `RuleSet::decide`, mirrored in `packages/core/src/agent-policy.ts`), and the
 * rule shape is the *wire* shape of a signed `ap1.` policy bundle. That is
 * deliberate: the `rules` array out of a bundle can be handed to
 * {@link seekritFetch} unchanged.
 *
 * Default-deny throughout. `allow: []` means no secret may be injected toward
 * that host; empty `methods`/`paths` mean "any", because an empty list as "deny
 * everything" is a shape that only ever arises by mistake.
 *
 * Ports are the exception to "empty means any". A rule naming no ports covers
 * HTTPS on 443 and nothing else, exactly as the proxy reads it: the same name on
 * another port is another service, and cleartext puts the substituted credential
 * on the wire. Listing `https_ports` or `http_ports` replaces that default.
 */

/** One upstream host and what may be injected toward it. */
export interface AllowRule {
  /** Bare hostname, lowercased: no scheme, no port, no path. */
  host: string;
  /**
   * TLS ports this rule covers. **Not** "absent ⇒ any": with `http_ports` also
   * absent the rule covers HTTPS on 443 only, and listing either replaces that
   * default rather than adding to it.
   */
  https_ports?: number[];
  /** Cleartext `http://` ports this rule covers. Absent ⇒ none. */
  http_ports?: number[];
  /** Uppercased HTTP methods. Empty or absent ⇒ any. */
  methods?: string[];
  /** Path globs (`*` within a segment, `**` across). Empty or absent ⇒ any. */
  paths?: string[];
  /** Secret names injectable toward this host. Empty or absent ⇒ none. */
  allow?: string[];
  /** Free-text note. Never used in matching. */
  label?: string;
}

export type PolicyDecision =
  | "allow"
  | "no_rule"
  | "port_not_allowed"
  | "method_not_allowed"
  | "path_not_allowed"
  | "secret_not_allowed";

export interface PolicyVerdict {
  decision: PolicyDecision;
  /** Index of the rule that decided, when one did. */
  ruleIndex: number | null;
}

/** The scheme and port a request dials — what a hostname does not name. */
export interface PolicyTransport {
  scheme: "https" | "http";
  port: number;
}

export interface PolicyQuery {
  host: string;
  /**
   * How the request reaches the host — usually {@link transportOf} its URL.
   * Omit it only where the destination is fixed by the operator rather than by
   * the caller (a route handler's configured upstream), which no port rule
   * narrows. `null` is a scheme no rule can cover, and is refused.
   */
  transport?: PolicyTransport | null;
  method: string;
  path: string;
  /** The secret to be injected. Omit to ask only about the operation. */
  secret?: string;
}

/**
 * Match a request path against a glob: `*` matches within one segment, `**`
 * matches any number of segments (so `/v1/**` covers `/v1`). Case-sensitive,
 * and the query string never participates.
 */
export function matchPath(pattern: string, path: string): boolean {
  const bare = path.split("?")[0] ?? path;
  return matchSegments(pattern.split("/"), bare.split("/"));
}

function matchSegments(pattern: string[], segments: string[]): boolean {
  if (pattern.length === 0) return segments.length === 0;
  const [head, ...rest] = pattern;
  if (head === "**") {
    for (let skip = 0; skip <= segments.length; skip++) {
      if (matchSegments(rest, segments.slice(skip))) return true;
    }
    return false;
  }
  if (segments.length === 0) return false;
  return matchSegment(head as string, segments[0] as string) && matchSegments(rest, segments.slice(1));
}

function matchSegment(pattern: string, segment: string): boolean {
  if (!pattern.includes("*")) return pattern === segment;
  const parts = pattern.split("*");
  let rest = segment;
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i] as string;
    if (part === "") continue;
    if (i === 0) {
      if (!rest.startsWith(part)) return false;
      rest = rest.slice(part.length);
    } else if (i === parts.length - 1) {
      return rest.length >= part.length && rest.endsWith(part);
    } else {
      const at = rest.indexOf(part);
      if (at === -1) return false;
      rest = rest.slice(at + part.length);
    }
  }
  return true;
}

function coversMethod(rule: AllowRule, method: string): boolean {
  const methods = rule.methods ?? [];
  if (methods.length === 0) return true;
  const wanted = method.trim().toUpperCase();
  return methods.some((m) => m.trim().toUpperCase() === wanted);
}

function coversPath(rule: AllowRule, path: string): boolean {
  const paths = rule.paths ?? [];
  if (paths.length === 0) return true;
  return paths.some((p) => matchPath(p, path));
}

/**
 * Set on the options of the `seekritFetch` that `seekritRoute` builds, whose
 * upstream the operator wrote rather than the caller: a fixed destination has
 * no port for a rule to narrow — the same exemption `apps/proxy` makes on its
 * reverse plane. A symbol in a module no entry point exports, so a caller of
 * `seekritFetch` cannot switch the port check off.
 *
 * @internal
 */
export const OPERATOR_FIXED_DESTINATION: unique symbol = Symbol("seekrit.operatorFixedDestination");

/** The port a rule covers when it names none. */
export const DEFAULT_HTTPS_PORT = 443;

/** The ports a rule covers, with the HTTPS-on-443 default applied. */
export function rulePorts(rule: Pick<AllowRule, "https_ports" | "http_ports">): {
  https: number[];
  http: number[];
} {
  const https = [...new Set(rule.https_ports ?? [])].sort((a, b) => a - b);
  const http = [...new Set(rule.http_ports ?? [])].sort((a, b) => a - b);
  if (https.length === 0 && http.length === 0) return { https: [DEFAULT_HTTPS_PORT], http: [] };
  return { https, http };
}

/**
 * The scheme and port a URL dials, with the scheme's own port filled in — or
 * `null` for anything but `http:`/`https:`, which no rule can cover.
 */
export function transportOf(url: URL): PolicyTransport | null {
  const scheme = url.protocol === "https:" ? "https" : url.protocol === "http:" ? "http" : null;
  if (scheme === null) return null;
  const port = url.port === "" ? (scheme === "https" ? 443 : 80) : Number(url.port);
  return { scheme, port };
}

function reaches(rule: AllowRule, transport: PolicyTransport | null | undefined): boolean {
  if (transport === undefined) return true;
  if (transport === null) return false;
  const ports = rulePorts(rule);
  return (transport.scheme === "https" ? ports.https : ports.http).includes(transport.port);
}

/**
 * Decide one query against an ordered rule set — first match wins, and a
 * refusal says *which* constraint refused. Naming the constraint matters: a
 * default-deny rule set fails in exactly the confusing direction.
 */
export function evaluate(rules: AllowRule[], query: PolicyQuery): PolicyVerdict {
  const host = query.host.trim().toLowerCase();
  let hostMatched = false;
  let portMatched = false;
  let pathMatchedIndex: number | null = null;

  for (let i = 0; i < rules.length; i++) {
    const rule = rules[i] as AllowRule;
    if (rule.host.trim().toLowerCase() !== host) continue;
    hostMatched = true;
    // A rule on another port is skipped like a rule on another host — another
    // port is another service — but the refusal still says the host was ruled.
    if (!reaches(rule, query.transport)) continue;
    portMatched = true;
    const pathsOk = coversPath(rule, query.path);
    if (pathsOk && coversMethod(rule, query.method)) {
      if (query.secret !== undefined && !(rule.allow ?? []).includes(query.secret)) {
        return { decision: "secret_not_allowed", ruleIndex: i };
      }
      return { decision: "allow", ruleIndex: i };
    }
    if (pathsOk && pathMatchedIndex === null) pathMatchedIndex = i;
  }

  if (pathMatchedIndex !== null) {
    return { decision: "method_not_allowed", ruleIndex: pathMatchedIndex };
  }
  if (!hostMatched) return { decision: "no_rule", ruleIndex: null };
  return { decision: portMatched ? "path_not_allowed" : "port_not_allowed", ruleIndex: null };
}

/**
 * Expand the `{ host: [names] }` shorthand into rules that permit any operation
 * — on HTTPS port 443, like any rule naming no ports. For another port or for
 * cleartext, write the rule out with `https_ports` / `http_ports`.
 */
export function rulesFromAllow(allow: Record<string, string[]>): AllowRule[] {
  return Object.entries(allow).map(([host, names]) => ({
    host,
    methods: [],
    paths: [],
    allow: names,
  }));
}
