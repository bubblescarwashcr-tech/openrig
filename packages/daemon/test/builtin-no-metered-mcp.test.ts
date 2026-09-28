import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { ClaudeCodeAdapter, type ClaudeAdapterFsOps } from "../src/adapters/claude-code-adapter.js";
import type { TmuxAdapter } from "../src/adapters/tmux.js";
import { resolveAgentRef } from "../src/domain/agent-resolver.js";
import { resolveNodeConfig } from "../src/domain/profile-resolver.js";
import { planProjection } from "../src/domain/projection-planner.js";
import { RigSpecSchema } from "../src/domain/rigspec-schema.js";

// Fork-local (bubbles/stable): the shipped shared runtime fragments must not pre-configure or
// pre-approve a metered/paid MCP vendor (exa). `rig grow` seats resolve the builtin orchestrator
// (cli topology-default-agent.ts → path:<builtin orchestrator dir>), which imports these fragments.
const SPECS = resolve(import.meta.dirname, "../specs");
const ORCHESTRATOR_DIR = join(SPECS, "agents/orchestration/orchestrator");
const METERED = /\bexa\b|mcp\.exa\.ai/i;
const diskFs = { readFile: (p: string) => readFileSync(p, "utf8"), exists: existsSync };

function growSeatConfig(runtime: "claude-code" | "codex") {
  // Same agent_ref shape `rig grow` sends: path:<dirname(builtin orchestrator sourcePath)>.
  const agentRef = `path:${ORCHESTRATOR_DIR}`;
  const result = resolveAgentRef(agentRef, SPECS, diskFs);
  if (!result.ok) throw new Error(JSON.stringify(result));
  const rig = RigSpecSchema.normalize({
    version: "0.2", name: "grow-fixture",
    pods: [{ id: "work", members: [{ id: "seat", agent_ref: agentRef, profile: "default", runtime, cwd: "/grow-seat" }] }],
  });
  const pod = rig.pods[0]!;
  const config = resolveNodeConfig({
    baseSpec: result.resolved, importedSpecs: result.imports, collisions: result.collisions,
    profileName: "default", member: pod.members[0]!, pod, rig,
    homedir: "/grow-home", skillsRoot: "/grow-catalog",
  });
  if (!config.ok) throw new Error(config.errors.join("\n"));
  const plan = planProjection({ config: config.config, collisions: result.collisions, fsOps: diskFs });
  if (!plan.ok) throw new Error(plan.errors.join("\n"));
  return plan.plan;
}

function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    return statSync(p).isDirectory() ? walk(p) : [p];
  });
}

describe("fork: builtin seats never pre-approve a metered MCP server (exa)", () => {
  it("a `rig grow` Claude seat's projected .mcp.json and settings.local.json carry no exa", async () => {
    const plan = growSeatConfig("claude-code");
    const runtimeEntries = plan.entries.filter((e) => e.category === "runtime_resource");
    // Guard against a vacuous pass: the grow seat really does pull the shared MCP + settings fragments.
    expect(runtimeEntries.map((e) => e.resourceType)).toEqual(
      expect.arrayContaining(["claude_mcp_fragment", "claude_settings_fragment"]),
    );

    // In-memory seat cwd; source fragments are read from the real shipped files on disk.
    const store: Record<string, string> = {};
    const fsOps = {
      readFile: (p: string) => (p in store ? store[p]! : readFileSync(p, "utf8")),
      writeFile: (p: string, c: string) => { store[p] = c; },
      exists: (p: string) => p in store || existsSync(p),
      mkdirp: () => {},
      copyFile: () => {},
      listFiles: () => [],
    } as unknown as ClaudeAdapterFsOps;
    const tmux = { sendText: vi.fn(async () => ({ ok: true })) } as unknown as TmuxAdapter;
    const adapter = new ClaudeCodeAdapter({ tmux, fsOps });
    const binding = {
      id: "b1", nodeId: "n1", tmuxSession: "work-seat@grow-fixture", tmuxWindow: null, tmuxPane: null,
      cmuxWorkspace: null, cmuxSurface: null, updatedAt: "", cwd: "/grow-seat",
    };
    const result = await adapter.project({ ...plan, entries: runtimeEntries }, binding);
    expect(result.failed).toEqual([]);

    // Adapter builds targets with node:path, so key the store the same way (win32-safe).
    const mcp = JSON.parse(store[join("/grow-seat", ".mcp.json")]!);
    const settings = JSON.parse(store[join("/grow-seat", ".claude", "settings.local.json")]!);
    expect(Object.keys(mcp.mcpServers)).not.toContain("exa");
    expect(settings.enabledMcpjsonServers ?? []).not.toContain("exa");
    // Everything else about the seat default is unchanged.
    expect(mcp.mcpServers.context7.url).toBe("https://mcp.context7.com/mcp");
    expect(settings.enabledMcpjsonServers).toEqual(["context7"]);
    expect(settings.permissions.defaultMode).toBe("acceptEdits");
  });

  it("a `rig grow --runtime codex` seat's managed config fragment carries no exa", () => {
    const plan = growSeatConfig("codex");
    const codexFragments = plan.entries.filter((e) => e.resourceType === "codex_config_fragment");
    expect(codexFragments.length).toBeGreaterThan(0);
    for (const entry of codexFragments) {
      const toml = readFileSync(entry.absolutePath, "utf8");
      expect(toml).not.toMatch(METERED);
      expect(toml).toContain("[mcp_servers.context7]");
    }
  });

  it("no shipped runtime fragment anywhere under specs/ configures exa", () => {
    const fragments = walk(SPECS).filter((p) => /\.fragment\.(json|toml)$/.test(p) || /[\\/]runtime[\\/][^\\/]+\.(json|toml)$/.test(p));
    expect(fragments.length).toBeGreaterThan(0);
    for (const file of fragments) {
      expect(readFileSync(file, "utf8"), file).not.toMatch(METERED);
    }
  });
});
