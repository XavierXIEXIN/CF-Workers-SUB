import { Buffer } from "node:buffer";
import fs from "node:fs";

const fixedNodesB64 = process.env.FIXED_NODES_B64 || "";
const linkText = fs.readFileSync("LINK.txt", "utf8");

function decodeFixedNodes() {
  if (!fixedNodesB64.trim()) return "";
  try {
    return Buffer.from(fixedNodesB64.trim(), "base64").toString("utf8");
  } catch (error) {
    console.warn(`FIXED_NODES_B64 could not be decoded: ${error.message}`);
    return "";
  }
}

function uniqueLines(...blocks) {
  const seen = new Set();
  const lines = [];
  for (const block of blocks) {
    for (const rawLine of String(block || "").split("\n")) {
      const line = rawLine.trim();
      if (!line || seen.has(line)) continue;
      seen.add(line);
      lines.push(line);
    }
  }
  return lines;
}

function firstValue(params, key, fallback = "") {
  return params.get(key) || fallback;
}

function parseVless(line) {
  const parsed = new URL(line);
  if (parsed.protocol !== "vless:" || !parsed.username || !parsed.hostname) {
    throw new Error("unsupported node URI");
  }

  const params = parsed.searchParams;
  const security = firstValue(params, "security", "none");
  const network = firstValue(params, "type", "tcp");
  const proxy = {
    name: decodeURIComponent(parsed.hash ? parsed.hash.slice(1) : `${parsed.hostname}:${parsed.port}`),
    type: "vless",
    server: parsed.hostname,
    port: Number.parseInt(parsed.port, 10),
    uuid: parsed.username,
    network,
    udp: true,
    tls: security === "tls" || security === "reality",
  };

  const sni = firstValue(params, "sni");
  const fingerprint = firstValue(params, "fp");
  const flow = firstValue(params, "flow");
  if (sni) proxy.servername = sni;
  if (fingerprint) proxy["client-fingerprint"] = fingerprint;
  if (flow) proxy.flow = flow;
  if (firstValue(params, "allowInsecure") === "1") proxy["skip-cert-verify"] = true;

  if (security === "reality") {
    proxy["reality-opts"] = {
      "public-key": firstValue(params, "pbk"),
      "short-id": firstValue(params, "sid"),
    };
  }

  if (network === "ws") {
    const host = firstValue(params, "host");
    proxy["ws-opts"] = {
      path: firstValue(params, "path", "/") || "/",
    };
    if (host) proxy["ws-opts"].headers = { Host: host };
  }

  return proxy;
}

function scalar(value) {
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") return String(value);
  if (value === null || value === undefined) return "null";
  return JSON.stringify(String(value));
}

function emitMapping(lines, object, indent = 0) {
  const prefix = " ".repeat(indent);
  for (const [key, value] of Object.entries(object)) {
    if (value === undefined || value === null) continue;
    if (Array.isArray(value)) {
      lines.push(`${prefix}${key}:`);
      for (const item of value) {
        if (typeof item === "object" && item !== null) {
          lines.push(`${prefix}  -`);
          emitMapping(lines, item, indent + 4);
        } else {
          lines.push(`${prefix}  - ${scalar(item)}`);
        }
      }
    } else if (typeof value === "object") {
      if (Object.keys(value).length === 0) continue;
      lines.push(`${prefix}${key}:`);
      emitMapping(lines, value, indent + 2);
    } else {
      lines.push(`${prefix}${key}: ${scalar(value)}`);
    }
  }
}

function buildClash(proxies) {
  const names = proxies.map((proxy) => proxy.name);
  const lines = [
    "mixed-port: 7890",
    "allow-lan: false",
    "mode: rule",
    "log-level: info",
    "ipv6: true",
    "",
    "proxies:",
  ];

  for (const proxy of proxies) {
    lines.push("  -");
    emitMapping(lines, proxy, 4);
  }

  const groups = [
    { name: "🚀 节点选择", type: "select", proxies: ["🏠 自建优先", "☑️ 手动切换", "♻️ 自动选择", "DIRECT"] },
    { name: "🏠 自建优先", type: "fallback", url: "http://www.gstatic.com/generate_204", interval: 600, proxies: names },
    { name: "☑️ 手动切换", type: "select", proxies: names },
    { name: "♻️ 自动选择", type: "url-test", url: "http://www.gstatic.com/generate_204", interval: 600, tolerance: 50, proxies: names },
  ];

  lines.push("", "proxy-groups:");
  for (const group of groups) {
    lines.push("  -");
    emitMapping(lines, group, 4);
  }
  lines.push("", "rules:", "  - MATCH,🚀 节点选择", "");
  return lines.join("\n");
}

const fixedLines = uniqueLines(decodeFixedNodes());
const allLines = uniqueLines(fixedLines.join("\n"), linkText);
const proxies = allLines.filter((line) => line.startsWith("vless://")).map(parseVless);
const rawText = `${allLines.join("\n")}\n`;
const clashText = buildClash(proxies);

fs.writeFileSync("be", clashText, "utf8");
fs.writeFileSync("be.yaml", clashText, "utf8");
fs.writeFileSync("be.txt", rawText, "utf8");
fs.writeFileSync("be.b64", `${Buffer.from(rawText, "utf8").toString("base64")}\n`, "utf8");
fs.writeFileSync("_routes.json", `${JSON.stringify({
  version: 1,
  include: ["/*"],
  exclude: ["/be", "/be.yaml", "/be.txt", "/be.b64"],
}, null, 2)}\n`, "utf8");
fs.writeFileSync("_headers", `/be
  Content-Type: text/yaml; charset=utf-8
  Cache-Control: no-store
/be.yaml
  Content-Type: text/yaml; charset=utf-8
  Cache-Control: no-store
/be.txt
  Content-Type: text/plain; charset=utf-8
  Cache-Control: no-store
/be.b64
  Content-Type: text/plain; charset=utf-8
  Cache-Control: no-store
`, "utf8");

console.log(`Generated static subscription fallback: nodes=${allLines.length}, fixed=${fixedLines.length}, proxies=${proxies.length}`);
