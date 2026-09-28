import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const serveMock = vi.fn();
const createDaemonMock = vi.fn();

vi.mock("@hono/node-server", () => ({
  serve: serveMock,
}));

vi.mock("../src/startup.js", () => ({
  createDaemon: createDaemonMock,
}));

describe("daemon startServer", () => {
  beforeEach(() => {
    serveMock.mockReset();
    createDaemonMock.mockReset();
    createDaemonMock.mockResolvedValue({
      app: { fetch: vi.fn() },
      contextMonitor: { start: vi.fn(), stop: vi.fn() },
      deps: {},
      injectWebSocket: vi.fn(),
    });
    delete process.env.OPENRIG_HOST;
    delete process.env.RIGGED_HOST;
    delete process.env.OPENRIG_BIND_HOST;
    delete process.env.OPENRIG_AUTH_BEARER_TOKEN;
    delete process.env.OPENRIG_TERMINAL_BEARER_TOKEN;
  });

  afterEach(() => {
    delete process.env.OPENRIG_HOST;
    delete process.env.RIGGED_HOST;
    delete process.env.OPENRIG_BIND_HOST;
    delete process.env.OPENRIG_AUTH_BEARER_TOKEN;
    delete process.env.OPENRIG_TERMINAL_BEARER_TOKEN;
  });

  it("binds the daemon to loopback", async () => {
    const { startServer } = await import("../src/index.js");

    await startServer(7441);

    expect(serveMock).toHaveBeenCalledWith(
      expect.objectContaining({ port: 7441, hostname: "127.0.0.1" }),
      expect.any(Function)
    );
  });

  it("does not require a terminal bearer token for the default loopback bind", async () => {
    const { startServer } = await import("../src/index.js");

    await startServer(7441);

    expect(createDaemonMock).toHaveBeenCalledWith(
      expect.objectContaining({ terminalBearerToken: null }),
    );
  });

  it("uses the daemon bearer token for terminal routes on explicit public binds", async () => {
    process.env.OPENRIG_BIND_HOST = "0.0.0.0";
    process.env.OPENRIG_AUTH_BEARER_TOKEN = "daemon-token";
    const { startServer } = await import("../src/index.js");

    await startServer(7441);

    expect(createDaemonMock).toHaveBeenCalledWith(
      expect.objectContaining({
        bearerToken: "daemon-token",
        terminalBearerToken: "daemon-token",
      }),
    );
  });
});

describe("isMainModule (startup gate)", () => {
  it("the old naive `file://${argv1}` comparison fails on a real Windows-shaped case (pre-fix bug)", () => {
    // Realistic values as Node actually produces them on Windows: argv[1] is
    // a raw backslash path, import.meta.url is a properly encoded file URL.
    // This is the exact comparison the daemon used before the fix — asserted
    // here as a standalone regression guard (not exercised via src/index.ts,
    // since the buggy line no longer exists there).
    const argv1 = "C:\\foo\\bar\\index.js";
    const importMetaUrl = "file:///C:/foo/bar/index.js";
    const naiveComparison = importMetaUrl === `file://${argv1}`;
    expect(naiveComparison).toBe(false);
  });

  it("matches on a Windows-shaped argv[1] path", async () => {
    const { isMainModule } = await import("../src/index.js");
    const path = (await import("node:path")).default;
    const { pathToFileURL } = await import("node:url");
    const argv1 = "C:\\foo\\bar\\index.js";
    // Built via the same primitives the fix uses, so this proves isMainModule
    // correctly implements pathToFileURL(resolve(argv1)).href — the RED case
    // above shows the old string-concat comparison rejects this same pairing.
    const importMetaUrl = pathToFileURL(path.resolve(argv1)).href;

    expect(isMainModule(importMetaUrl, argv1)).toBe(true);
  });

  it("matches on a POSIX-shaped argv[1] path", async () => {
    const { isMainModule } = await import("../src/index.js");
    const path = (await import("node:path")).default;
    const { pathToFileURL } = await import("node:url");
    const argv1 = "/home/user/index.js";
    const importMetaUrl = pathToFileURL(path.resolve(argv1)).href;

    expect(isMainModule(importMetaUrl, argv1)).toBe(true);
  });

  it("returns false when argv[1] is missing", async () => {
    const { isMainModule } = await import("../src/index.js");

    expect(isMainModule("file:///home/user/index.js", undefined)).toBe(false);
  });

  it("returns false when the file differs (imported, not the entry point)", async () => {
    const { isMainModule } = await import("../src/index.js");
    const argv1 = "C:\\foo\\bar\\index.js";
    const importMetaUrl = "file:///C:/foo/other.js";

    expect(isMainModule(importMetaUrl, argv1)).toBe(false);
  });
});
