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

function decodeBase64Loose(value) {
  const normalized = decodeURIComponent(value).replaceAll("-", "+").replaceAll("_", "/");
  const padding = "=".repeat((4 - (normalized.length % 4)) % 4);
  return Buffer.from(`${normalized}${padding}`, "base64").toString("utf8");
}

function maybeBase64Decode(value) {
  const decoded = decodeBase64Loose(value);
  return decoded.includes(":") ? decoded : decodeURIComponent(value);
}

function splitServerPort(value) {
  const index = value.lastIndexOf(":");
  if (index <= 0) throw new Error("missing server port");
  return [value.slice(0, index), Number.parseInt(value.slice(index + 1), 10)];
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

function parsePluginOptions(params) {
  const encodedV2rayPlugin = params.get("v2ray-plugin");
  if (encodedV2rayPlugin) {
    const options = JSON.parse(decodeBase64Loose(encodedV2rayPlugin));
    const pluginOptions = {};
    if (options.mode) pluginOptions.mode = options.mode;
    if (options.host) pluginOptions.host = options.host;
    if (options.path) pluginOptions.path = options.path;
    if (options.tls !== undefined) pluginOptions.tls = Boolean(options.tls);
    if (options.mux !== undefined) pluginOptions.mux = Boolean(options.mux);
    if (options.allowInsecure !== undefined) pluginOptions["skip-cert-verify"] = Boolean(options.allowInsecure);
    return { plugin: "v2ray-plugin", pluginOptions };
  }

  const plugin = params.get("plugin");
  if (!plugin) return {};

  const [pluginName, ...rawOptions] = decodeURIComponent(plugin).split(";");
  const pluginOptions = {};
  for (const item of rawOptions) {
    if (!item) continue;
    if (item === "tls") {
      pluginOptions.tls = true;
      continue;
    }
    const [key, ...valueParts] = item.split("=");
    pluginOptions[key] = valueParts.length ? valueParts.join("=") : true;
  }
  return { plugin: pluginName, pluginOptions };
}

function parseShadowsocks(line) {
  const parsed = new URL(line);
  if (parsed.protocol !== "ss:") throw new Error("unsupported node URI");

  let userInfo = "";
  let server = "";
  let port = 0;
  if (parsed.username && parsed.hostname) {
    userInfo = maybeBase64Decode(parsed.username);
    server = parsed.hostname;
    port = Number.parseInt(parsed.port, 10);
  } else {
    const decoded = decodeBase64Loose(parsed.hostname || parsed.pathname.replace(/^\//, ""));
    const atIndex = decoded.lastIndexOf("@");
    if (atIndex <= 0) throw new Error("invalid shadowsocks payload");
    userInfo = decoded.slice(0, atIndex);
    [server, port] = splitServerPort(decoded.slice(atIndex + 1));
  }

  const separator = userInfo.indexOf(":");
  if (separator <= 0) throw new Error("invalid shadowsocks user info");
  const plugin = parsePluginOptions(parsed.searchParams);
  const proxy = {
    name: decodeURIComponent(parsed.hash ? parsed.hash.slice(1) : `${server}:${port}`),
    type: "ss",
    server,
    port,
    cipher: userInfo.slice(0, separator),
    password: userInfo.slice(separator + 1),
    udp: true,
  };
  if (plugin.plugin) {
    proxy.plugin = plugin.plugin;
    proxy["plugin-opts"] = plugin.pluginOptions;
  }
  return proxy;
}

function parseProxy(line) {
  if (line.startsWith("vless://")) return parseVless(line);
  if (line.startsWith("ss://")) return parseShadowsocks(line);
  return null;
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
const proxies = allLines.map(parseProxy).filter(Boolean);
const rawText = `${allLines.join("\n")}\n`;
const clashText = buildClash(proxies);

fs.writeFileSync("be", clashText, "utf8");
fs.writeFileSync("be.yaml", clashText, "utf8");
fs.writeFileSync("be.txt", rawText, "utf8");
fs.writeFileSync("be.b64", `${Buffer.from(rawText, "utf8").toString("base64")}\n`, "utf8");
fs.writeFileSync("_routes.json", `${JSON.stringify({
  version: 1,
  include: ["/*"],
  exclude: ["/be", "/be.yaml", "/be.txt", "/be.b64", "/LINK.txt"],
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
/LINK.txt
  Content-Type: text/plain; charset=utf-8
  Cache-Control: no-store
`, "utf8");

console.log(`Generated static subscription fallback: nodes=${allLines.length}, fixed=${fixedLines.length}, proxies=${proxies.length}`);
