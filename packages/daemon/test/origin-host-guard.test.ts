import { describe, it, expect, vi } from "vitest";
import { Hono } from "hono";
import { buildAllowedHosts, originHostGuard, resolveExtraAllowedHosts } from "../src/middleware/origin-host-guard.js";

function guardedApp(allowed: ReadonlySet<string>): Hono {
  const app = new Hono();
  app.use("/api/*", originHostGuard(allowed));
  app.post("/api/write", async (c) => c.json({ ok: true, body: await c.req.text() }));
  app.get("/api/read", (c) => c.json({ ok: true }));
  return app;
}

function post(app: Hono, url: string, headers: Record<string, string>) {
  return app.request(url, { method: "POST", headers: { "Content-Type": "text/plain", ...headers }, body: "{}" });
}

describe("buildAllowedHosts", () => {
  it("always admits loopback, even with no bind plan", () => {
    const hosts = buildAllowedHosts({ bindHosts: [] });
    expect(hosts.has("localhost")).toBe(true);
    expect(hosts.has("127.0.0.1")).toBe(true);
    expect(hosts.has("[::1]")).toBe(true);
  });

  it("admits every bound host, normalized (case, trailing dot, bare IPv6 literal)", () => {
    const hosts = buildAllowedHosts({
      bindHosts: ["127.0.0.1", "100.101.102.103", "FD7A:115C:A1E0::1"],
      extraHosts: ["Box.Tail1234.TS.NET."],
    });
    expect(hosts.has("100.101.102.103")).toBe(true);
    expect(hosts.has("[fd7a:115c:a1e0::1]")).toBe(true);
    expect(hosts.has("box.tail1234.ts.net")).toBe(true);
  });

  it("a wildcard bind admits every local interface address plus the machine hostname", () => {
    const hosts = buildAllowedHosts({
      bindHosts: ["0.0.0.0"],
      interfaceAddresses: () => ["192.168.1.50", "fe80::1%eth0", "100.101.102.103"],
      hostname: () => "MyBox",
    });
    expect(hosts.has("192.168.1.50")).toBe(true);
    expect(hosts.has("100.101.102.103")).toBe(true);
    expect(hosts.has("mybox")).toBe(true);
    expect(hosts.has("0.0.0.0")).toBe(false);
  });
});

describe("originHostGuard", () => {
  const loopbackOnly = buildAllowedHosts({ bindHosts: ["127.0.0.1"] });

  it("passes a write with no Origin header (CLI, relays, hooks)", async () => {
    const res = await post(guardedApp(loopbackOnly), "http://127.0.0.1:7433/api/write", {});
    expect(res.status).toBe(200);
  });

  it("passes a loopback Origin on any port (the Vite dev UI on :5173 proxies to the daemon)", async () => {
    const app = guardedApp(loopbackOnly);
    for (const origin of ["http://127.0.0.1:7433", "http://localhost:5173", "http://[::1]:7433"]) {
      const res = await post(app, "http://127.0.0.1:7433/api/write", { Origin: origin, Host: "127.0.0.1:7433" });
      expect(res.status, origin).toBe(200);
    }
  });

  it("rejects a cross-origin write with 403 origin_rejected", async () => {
    const res = await post(guardedApp(loopbackOnly), "http://127.0.0.1:7433/api/write", {
      Origin: "http://evil.example.com",
      Host: "127.0.0.1:7433",
    });
    expect(res.status).toBe(403);
    expect((await res.json()).error).toBe("origin_rejected");
  });

  it("rejects opaque and malformed Origins (sandboxed iframe / data: URL send \"null\")", async () => {
    const app = guardedApp(loopbackOnly);
    for (const origin of ["null", "", "not a url", "file://", "chrome-extension://abcdef"]) {
      const res = await post(app, "http://127.0.0.1:7433/api/write", { Origin: origin, Host: "127.0.0.1:7433" });
      expect(res.status, JSON.stringify(origin)).toBe(403);
    }
  });

  it("rejects loopback lookalike hostnames (127.evil.example.com is a DNS name, not 127/8)", async () => {
    const res = await post(guardedApp(loopbackOnly), "http://127.0.0.1:7433/api/write", {
      Origin: "http://127.evil.example.com",
      Host: "127.0.0.1:7433",
    });
    expect(res.status).toBe(403);
  });

  it("rejects a DNS-rebinding request (Origin and Host both the attacker's name)", async () => {
    const res = await post(guardedApp(loopbackOnly), "http://rebind.evil.example.com:7433/api/write", {
      Origin: "http://rebind.evil.example.com:7433",
      Host: "rebind.evil.example.com:7433",
    });
    expect(res.status).toBe(403);
  });

  it("rejects when the Origin is allowed but the Host header is not (Host is checked independently)", async () => {
    const res = await post(guardedApp(loopbackOnly), "http://rebind.evil.example.com:7433/api/write", {
      Origin: "http://127.0.0.1:7433",
      Host: "rebind.evil.example.com:7433",
    });
    expect(res.status).toBe(403);
  });

  it("guards WebSocket upgrades (GET) the same way — the terminal socket accepts input", async () => {
    const res = await guardedApp(loopbackOnly).request("http://rebind.evil.example.com:7433/api/read", {
      headers: { Upgrade: "websocket", Origin: "http://rebind.evil.example.com:7433", Host: "rebind.evil.example.com:7433" },
    });
    expect(res.status).toBe(403);
  });

  it("leaves plain reads alone (GET without Upgrade is out of this guard's scope)", async () => {
    const res = await guardedApp(loopbackOnly).request("http://127.0.0.1:7433/api/read", {
      headers: { Origin: "http://evil.example.com", Host: "127.0.0.1:7433" },
    });
    expect(res.status).toBe(200);
  });

  it("tailnet: admits the exact MagicDNS name, rejects any other *.ts.net name", async () => {
    const app = guardedApp(buildAllowedHosts({
      bindHosts: ["127.0.0.1", "100.101.102.103"],
      extraHosts: ["box.tail1234.ts.net", "box"],
    }));
    const ok = await post(app, "http://box.tail1234.ts.net:7433/api/write", {
      Origin: "http://box.tail1234.ts.net:7433",
      Host: "box.tail1234.ts.net:7433",
    });
    expect(ok.status).toBe(200);
    const funnel = await post(app, "http://box.tail1234.ts.net:7433/api/write", {
      Origin: "https://attacker.tail9999.ts.net",
      Host: "box.tail1234.ts.net:7433",
    });
    expect(funnel.status).toBe(403);
  });
});

describe("resolveExtraAllowedHosts", () => {
  it("parses OPENRIG_ALLOWED_HOSTS and skips tailnet discovery for a loopback-only bind", async () => {
    const discover = vi.fn(async () => ["box.tail1234.ts.net", "box"]);
    const extras = await resolveExtraAllowedHosts({
      bindHosts: ["127.0.0.1"], tailscaleDetected: false, envValue: " ui.lan , other.lan,", discover,
    });
    expect(extras).toEqual(["ui.lan", "other.lan"]);
    expect(discover).not.toHaveBeenCalled();
  });

  it("adds the discovered MagicDNS names when the daemon listens on a tailnet IP (default bind plan)", async () => {
    const extras = await resolveExtraAllowedHosts({
      bindHosts: ["127.0.0.1", "100.101.102.103"], tailscaleDetected: true, envValue: undefined,
      discover: async () => ["box.tail1234.ts.net", "box"],
    });
    expect(extras).toEqual(["box.tail1234.ts.net", "box"]);
  });

  it("adds them for a wildcard bind when tailscale is up", async () => {
    const extras = await resolveExtraAllowedHosts({
      bindHosts: ["0.0.0.0"], tailscaleDetected: true, envValue: undefined,
      discover: async () => ["box.tail1234.ts.net", "box"],
    });
    expect(extras).toContain("box.tail1234.ts.net");
  });

  it("warns loudly (never silently) when tailnet discovery fails", async () => {
    const err = vi.spyOn(console, "error").mockImplementation(() => {});
    const extras = await resolveExtraAllowedHosts({
      bindHosts: ["127.0.0.1", "100.101.102.103"], tailscaleDetected: true, envValue: undefined,
      discover: async () => [],
    });
    expect(extras).toEqual([]);
    expect(err.mock.calls.some((c) => String(c[0]).includes("OPENRIG_ALLOWED_HOSTS"))).toBe(true);
    err.mockRestore();
  });
});
