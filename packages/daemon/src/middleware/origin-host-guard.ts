// S4c — cross-origin write guard for /api/*.
//
// The daemon has no CORS policy and several write routes parse the body as JSON regardless of
// Content-Type, so a foreign web page could drive seats with a "simple request" (text/plain, no
// preflight). This middleware rejects any browser-originated write whose Origin OR Host is not
// one of the daemon's own names:
//   - Origin allowlisted: blocks ordinary cross-site requests.
//   - Host allowlisted: blocks DNS rebinding, where Origin and Host are BOTH the attacker's name
//     (the gap terminal-ws.ts's Origin-equals-Host check leaves open).
//   - Origin port equals the Host port: blocks other web apps on this machine's loopback.
// Writes with NO Origin header (CLI, relays, activity hooks — non-browser clients) pass
// unchanged: browsers always send Origin on non-GET requests and WebSocket upgrades, so its
// absence is not a browser attack path. WebSocket upgrades are guarded because the terminal
// socket accepts keystrokes.
//
// Plain GET/HEAD/OPTIONS reads get the Host check only, always. A cross-origin page cannot read
// a response (no CORS headers), but a DNS-rebinding page is same-origin with the daemon: its GET
// carries no Origin, and no Sec-Fetch-* either (Fetch Metadata is only sent to potentially
// trustworthy URLs, and http://<attacker-name> is not one). Its Host header is the attacker's name,
// which page script can neither set nor omit. A non-browser client that reaches the daemon by some
// other name must list it in OPENRIG_ALLOWED_HOSTS.
//
// Hand-rolled rather than Hono's csrf() so the no-Origin pass-through and the Host check are
// explicit and pinned by tests.

import { execFile } from "node:child_process";
import { hostname as osHostname, networkInterfaces } from "node:os";
import type { MiddlewareHandler } from "hono";
import { isLoopbackBind, isTailscaleBind } from "./auth-bearer-token.js";

const READ_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);
const WILDCARD_BINDS = new Set(["0.0.0.0", "::", "[::]"]);
const UNSPECIFIED_HOSTS = new Set(["0.0.0.0", "[::]"]);
const LOOPBACK_IPV4 = /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
const DEFAULT_PORTS: Record<string, string> = { "http:": "80", "https:": "443" };

/** Port a Host header names; `defaultPort` if it names none. Null if unparseable. */
function requestPort(hostOrHostPort: string, defaultPort: string): string | null {
  try {
    // Non-special scheme: an http: URL would erase an explicit ":80", making it read as the default.
    return new URL(`x://${hostOrHostPort.trim()}`).port || defaultPort;
  } catch {
    return null;
  }
}

/** Canonical comparison form: lowercase, IPv6 bracketed, no trailing dot. Null if unparseable. */
function canonicalHostname(hostOrHostPort: string): string | null {
  let h = hostOrHostPort.trim();
  if (!h) return null;
  // A bare IPv6 literal (bind config / interface address) must be bracketed for URL parsing.
  if (h.includes(":") && !h.startsWith("[") && h.indexOf(":") !== h.lastIndexOf(":")) h = `[${h}]`;
  try {
    const hostname = new URL(`http://${h}`).hostname.toLowerCase().replace(/\.$/, "");
    return hostname || null;
  } catch {
    return null;
  }
}

/** Strict loopback: `localhost`, `[::1]`, or a 127/8 IPv4 literal — never a name like 127.evil.com. */
function isLoopbackHostname(hostname: string): boolean {
  return hostname === "localhost" || hostname === "[::1]" || LOOPBACK_IPV4.test(hostname);
}

/** True when the bind plan includes an unspecified (wildcard) address: 0.0.0.0, ::, or [::]. */
export function hasWildcardBind(bindHosts: readonly string[]): boolean {
  return bindHosts.some((h) => WILDCARD_BINDS.has(h.trim()));
}

function defaultInterfaceAddresses(): string[] {
  return Object.values(networkInterfaces()).flatMap((addrs) => (addrs ?? []).map((a) => a.address));
}

/**
 * The set of hostnames a legitimate browser request to this daemon can carry in Origin/Host:
 * loopback, every bound host, and operator/discovered extras (e.g. the tailnet MagicDNS name).
 * A wildcard bind (0.0.0.0 / ::) is reachable on every interface, so it admits every local
 * interface address plus the machine hostname.
 */
export function buildAllowedHosts(input: {
  bindHosts: readonly string[];
  extraHosts?: readonly string[];
  interfaceAddresses?: () => string[];
  hostname?: () => string;
}): Set<string> {
  const raw = ["localhost", "127.0.0.1", "::1", ...input.bindHosts, ...(input.extraHosts ?? [])];
  if (hasWildcardBind(input.bindHosts)) {
    raw.push(...(input.interfaceAddresses ?? defaultInterfaceAddresses)());
    raw.push((input.hostname ?? osHostname)());
  }
  const allowed = new Set<string>();
  for (const h of raw) {
    if (WILDCARD_BINDS.has(h.trim())) continue;
    const canonical = canonicalHostname(h);
    if (canonical) allowed.add(canonical);
  }
  return allowed;
}

function originRejected(what: string, kind: "write" | "read" = "write") {
  return {
    error: "origin_rejected" as const,
    message: `Cross-origin ${kind} refused: ${what}`,
    what_failed: what,
    why_it_matters:
      "A web page on another origin (or a DNS-rebinding page) must not be able to drive seats, approve permission prompts, or read transcripts, logs, or files through this daemon.",
    what_to_do:
      "Open the UI via a host the daemon is bound to (loopback, its tailnet IP, or its MagicDNS name). To admit another hostname, list it in OPENRIG_ALLOWED_HOSTS (comma-separated) and restart the daemon.",
  };
}

/**
 * `wildcardBound` must be `hasWildcardBind(<the daemon's bind hosts>)`: true only when the daemon
 * actually listens on 0.0.0.0 / ::. It is the sole condition under which a read with
 * `Host: 0.0.0.0` or `Host: [::]` is admitted. Defaults to false (fail closed).
 */
export function originHostGuard(allowed: ReadonlySet<string>, wildcardBound = false): MiddlewareHandler {
  const isAllowed = (hostname: string | null) =>
    hostname !== null && (allowed.has(hostname) || isLoopbackHostname(hostname));
  return async (c, next) => {
    const isWebSocketUpgrade = c.req.header("Upgrade")?.toLowerCase() === "websocket";
    if (READ_METHODS.has(c.req.method) && !isWebSocketUpgrade) {
      const hostHeader = c.req.header("Host") ?? new URL(c.req.url).host;
      const readHost = canonicalHostname(hostHeader);
      // The CLI dials a wildcard-bound daemon at its persisted bind host (http://0.0.0.0:<port>),
      // so Host 0.0.0.0 / [::] is admitted ONLY when this daemon is actually wildcard-bound. Never
      // unconditionally: a browser page can reach a loopback-bound daemon via http://0.0.0.0:<port>
      // ("0.0.0.0 Day", Oligo 2024) and then sends exactly that Host.
      const unspecifiedHostAdmitted = wildcardBound && readHost !== null && UNSPECIFIED_HOSTS.has(readHost);
      if (!isAllowed(readHost) && !unspecifiedHostAdmitted) {
        return c.json(originRejected(`Host '${hostHeader}' is not a host this daemon serves`, "read"), 403);
      }
      return next();
    }
    const origin = c.req.header("Origin");
    if (origin === undefined) return next();

    let originHost: string | null = null;
    let originPort = "";
    try {
      const url = new URL(origin);
      if (url.protocol === "http:" || url.protocol === "https:") {
        originHost = canonicalHostname(url.host);
        originPort = url.port || DEFAULT_PORTS[url.protocol]!;
      }
    } catch {
      originHost = null;
    }
    if (!isAllowed(originHost)) return c.json(originRejected(`Origin '${origin}' is not a host this daemon serves`), 403);

    const hostHeader = c.req.header("Host") ?? new URL(c.req.url).host;
    if (!isAllowed(canonicalHostname(hostHeader))) {
      return c.json(originRejected(`Host '${hostHeader}' is not a host this daemon serves`), 403);
    }
    // The UI is served by the daemon itself, so a legitimate Origin's port is the port the request
    // was sent to. Loopback is admitted under any name, so without this check another web app on
    // this machine's loopback (http://localhost:<other port>) would pass. A Host with no port means
    // the Origin scheme's default port.
    if (originPort !== requestPort(hostHeader, originPort)) {
      return c.json(originRejected(`Origin '${origin}' is on a different port than this daemon`), 403);
    }
    return next();
  };
}

/** The daemon's own MagicDNS names ([fqdn, short]) from `tailscale status --json`; [] on any failure. */
function discoverTailnetNames(timeoutMs: number): Promise<string[]> {
  return new Promise((resolve) => {
    execFile("tailscale", ["status", "--json"], { timeout: timeoutMs, windowsHide: true }, (err, stdout) => {
      if (err) return resolve([]);
      try {
        const dnsName = String(JSON.parse(stdout)?.Self?.DNSName ?? "").replace(/\.$/, "");
        resolve(dnsName ? [dnsName, dnsName.split(".")[0]!] : []);
      } catch {
        resolve([]);
      }
    });
  });
}

/**
 * Extra hostnames beyond the bound hosts: OPENRIG_ALLOWED_HOSTS (comma-separated) plus, when the
 * daemon listens on a tailnet address, its MagicDNS names — browsers on the tailnet address the
 * daemon by name (http://box.tailXXXX.ts.net:7433), not by its 100.x IP. Exact names only: a
 * `*.ts.net` suffix rule would admit anyone's public Funnel page.
 */
export async function resolveExtraAllowedHosts(opts: {
  bindHosts: readonly string[];
  tailscaleDetected: boolean;
  envValue: string | undefined;
  discover?: (timeoutMs: number) => Promise<string[]>;
}): Promise<string[]> {
  const extras = (opts.envValue ?? "").split(",").map((h) => h.trim()).filter(Boolean);
  const listensOnTailnet = opts.bindHosts.some(
    (h) => isTailscaleBind(h) || (opts.tailscaleDetected && !isLoopbackBind(h)),
  );
  if (listensOnTailnet) {
    const names = await (opts.discover ?? discoverTailnetNames)(3000);
    if (names.length === 0) {
      console.error(
        "[origin-guard] daemon listens on a tailnet address but its MagicDNS name could not be discovered " +
          "(`tailscale status --json` failed). Browser writes via the MagicDNS name will be refused; " +
          "set OPENRIG_ALLOWED_HOSTS=<name>.<tailnet>.ts.net to admit it.",
      );
    }
    extras.push(...names);
  }
  return extras;
}
