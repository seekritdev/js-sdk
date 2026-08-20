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
 */

/** One upstream host and what may be injected toward it. */
export interface AllowRule {
  /** Bare hostname, lowercased: no scheme, no port, no path. */
  host: string;
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
  | "method_not_allowed"
  | "path_not_allowed"
  | "secret_not_allowed";

export interface PolicyVerdict {
  decision: PolicyDecision;
  /** Index of the rule that decided, when one did. */
  ruleIndex: number | null;
}

export interface PolicyQuery {
  host: string;
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
 * Decide one query against an ordered rule set — first match wins, and a
 * refusal says *which* constraint refused. Naming the constraint matters: a
 * default-deny rule set fails in exactly the confusing direction.
 */
export function evaluate(rules: AllowRule[], query: PolicyQuery): PolicyVerdict {
  const host = query.host.trim().toLowerCase();
  let hostMatched = false;
  let pathMatchedIndex: number | null = null;

  for (let i = 0; i < rules.length; i++) {
    const rule = rules[i] as AllowRule;
    if (rule.host.trim().toLowerCase() !== host) continue;
    hostMatched = true;
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
  return { decision: hostMatched ? "path_not_allowed" : "no_rule", ruleIndex: null };
}

/** Expand the `{ host: [names] }` shorthand into rules that permit any operation. */
export function rulesFromAllow(allow: Record<string, string[]>): AllowRule[] {
  return Object.entries(allow).map(([host, names]) => ({
    host,
    methods: [],
    paths: [],
    allow: names,
  }));
}
