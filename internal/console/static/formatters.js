(() => {
  "use strict";

  const jsonlTypes = new Set(["application/jsonl", "application/jsonlines", "application/ndjson", "application/x-ndjson"]);
  const readableStringLength = 160;
  const maxReadableStringPreviews = 24;
  const plugins = [
    {
      label: "Formatted Form Data",
      language: "form",
      matches: (mediaType, raw) => mediaType === "application/x-www-form-urlencoded" || looksLikeFormURLEncoded(raw),
      format: prettyFormURLEncoded
    },
    {
      label: "Formatted SSE",
      language: "sse",
      matches: (mediaType, raw) => mediaType === "text/event-stream" || looksLikeSSE(raw),
      format: prettySSE
    },
    {
      label: "Formatted JSONL",
      language: "json",
      jsonLines: true,
      matches: (mediaType, raw) => jsonlTypes.has(mediaType) || looksLikeJSONL(raw.trim()),
      format: prettyJSONL
    },
    {
      label: "Formatted JSON",
      language: "json",
      matches: (mediaType, raw) => mediaType === "application/json" || mediaType.endsWith("+json") || raw.trim().startsWith("{") || raw.trim().startsWith("["),
      format: prettyJSON
    },
    {
      label: "Formatted HTML",
      language: "html",
      matches: (mediaType, raw) => mediaType === "text/html" || mediaType === "application/xhtml+xml" || /^\s*(?:<!doctype\s+html|<html[\s>])/i.test(raw),
      format: prettyHTML
    }
  ];

  function format(contentType, raw) {
    if (!raw) return null;
    const mediaType = (contentType || "").split(";", 1)[0].trim().toLowerCase();
    for (const plugin of plugins) {
      if (!plugin.matches(mediaType, raw)) continue;
      try {
        const result = {label: plugin.label, language: plugin.language, text: plugin.format(raw)};
        if (plugin.language === "json") result.previews = readableJSONStrings(raw, plugin.jsonLines);
        return result;
      } catch {
        return null;
      }
    }
    return null;
  }

  function readableJSONStrings(raw, jsonLines) {
    const sources = jsonLines
      ? raw.split(/\r?\n/).map((line, index) => line.trim() ? {text: line, path: `line ${index + 1}`} : null).filter(Boolean)
      : [{text: raw, path: "$"}];
    const previews = [];
    for (const source of sources) {
      let value;
      try {
        value = JSON.parse(source.text);
      } catch {
        continue;
      }
      collectReadableJSONStrings(value, source.path, previews);
      if (previews.length >= maxReadableStringPreviews) break;
    }
    return previews;
  }

  function collectReadableJSONStrings(value, path, previews, depth = 0) {
    if (previews.length >= maxReadableStringPreviews || depth > 64) return;
    if (typeof value === "string") {
      const lines = value.split(/\r\n|\r|\n/).length;
      if (lines > 1 || value.length >= readableStringLength) previews.push({path, text: value, lines});
      return;
    }
    if (Array.isArray(value)) {
      value.forEach((child, index) => collectReadableJSONStrings(child, `${path}[${index}]`, previews, depth + 1));
      return;
    }
    if (!value || typeof value !== "object") return;
    for (const [key, child] of Object.entries(value)) {
      collectReadableJSONStrings(child, jsonPath(path, key), previews, depth + 1);
      if (previews.length >= maxReadableStringPreviews) return;
    }
  }

  function jsonPath(parent, key) {
    return /^[A-Za-z_$][\w$]*$/.test(key) ? `${parent}.${key}` : `${parent}[${JSON.stringify(key)}]`;
  }

  function looksLikeJSONL(raw) {
    const lines = raw.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
    if (lines.length < 2) return false;
    return lines.every(line => {
      if (!line.startsWith("{") && !line.startsWith("[")) return false;
      try {
        JSON.parse(line);
        return true;
      } catch {
        return false;
      }
    });
  }

  function prettyJSONL(raw) {
    return raw.split(/\r?\n/).filter(line => line.trim()).map(line => prettyJSON(line)).join("\n");
  }

  // This lexical formatter keeps working for bounded captures that end in the
  // middle of a JSON value. It emits the original number and string tokens,
  // avoiding JavaScript numeric reserialization while retaining formatting and
  // highlighting for truncated JSON.
  function prettyJSON(raw) {
    let output = "";
    let depth = 0;
    let inString = false;
    let escaped = false;
    const indentation = () => "  ".repeat(depth);
    const nextNonSpace = start => {
      for (let i = start; i < raw.length; i++) {
        if (!/\s/.test(raw[i])) return {character: raw[i], index: i};
      }
      return {character: "", index: raw.length};
    };
    for (let i = 0; i < raw.length; i++) {
      const character = raw[i];
      if (inString) {
        output += character;
        if (escaped) escaped = false;
        else if (character === "\\") escaped = true;
        else if (character === "\"") inString = false;
        continue;
      }
      if (character === "\"") {
        inString = true;
        output += character;
      } else if (character === "{" || character === "[") {
        const next = nextNonSpace(i + 1);
        const closing = character === "{" ? "}" : "]";
        if (next.character === closing) {
          output += character + closing;
          i = next.index;
        } else {
          depth++;
          output += character + "\n" + indentation();
        }
      } else if (character === "}" || character === "]") {
        depth = Math.max(0, depth - 1);
        output += "\n" + indentation() + character;
      } else if (character === ",") {
        output += ",\n" + indentation();
      } else if (character === ":") {
        output += ": ";
      } else if (!/\s/.test(character)) {
        output += character;
      }
    }
    return output;
  }

  function prettyHTML(raw) {
    const documentValue = new DOMParser().parseFromString(raw, "text/html");
    const fullDocument = /^\s*(?:<!doctype|<html[\s>])/i.test(raw);
    const nodes = fullDocument ? [...documentValue.childNodes] : [...documentValue.head.childNodes, ...documentValue.body.childNodes];
    return nodes.map(node => formatHTMLNode(node, 0)).filter(Boolean).join("\n");
  }

  function formatHTMLNode(node, depth) {
    const indent = "  ".repeat(depth);
    if (node.nodeType === Node.DOCUMENT_TYPE_NODE) return `${indent}<!DOCTYPE ${node.name}>`;
    if (node.nodeType === Node.COMMENT_NODE) return `${indent}<!--${node.data}-->`;
    if (node.nodeType === Node.TEXT_NODE) {
      const value = node.textContent.trim();
      return value ? `${indent}${escapeHTMLText(value)}` : "";
    }
    if (node.nodeType !== Node.ELEMENT_NODE) return "";
    const tag = node.tagName.toLowerCase();
    const attributes = [...node.attributes].map(attribute => ` ${attribute.name}="${escapeHTMLAttribute(attribute.value)}"`).join("");
    const opening = `${indent}<${tag}${attributes}>`;
    const voidElements = new Set(["area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"]);
    if (voidElements.has(tag)) return opening;
    const children = [...node.childNodes].map(child => formatHTMLNode(child, depth + 1)).filter(Boolean);
    if (!children.length) return `${opening}</${tag}>`;
    return `${opening}\n${children.join("\n")}\n${indent}</${tag}>`;
  }

  function escapeHTMLText(value) {
    return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
  }

  function escapeHTMLAttribute(value) {
    return escapeHTMLText(value).replaceAll("\"", "&quot;");
  }

  function looksLikeFormURLEncoded(raw) {
    const trimmed = raw.trim();
    if (!trimmed || trimmed.startsWith("{") || trimmed.startsWith("<") || trimmed.startsWith("[")) return false;
    const pairs = trimmed.split("&");
    if (pairs.length < 2) return false;
    return pairs.every(pair => pair.includes("="));
  }

  function prettyFormURLEncoded(raw) {
    const pairs = raw.trim().split("&");
    return pairs.map(pair => {
      const idx = pair.indexOf("=");
      if (idx === -1) return pair;
      const rawKey = pair.slice(0, idx);
      const rawVal = pair.slice(idx + 1);
      let key = rawKey;
      let val = rawVal;
      try { key = decodeURIComponent(rawKey.replace(/\+/g, " ")); } catch {}
      try { val = decodeURIComponent(rawVal.replace(/\+/g, " ")); } catch {}
      return `${key} = ${val}`;
    }).join("\n");
  }

  function looksLikeSSE(raw) {
    const lines = raw.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
    if (lines.length === 0) return false;
    let sseLineCount = 0;
    for (const line of lines) {
      if (/^(?:data|event|id|retry)\s*:/i.test(line) || line.startsWith(":")) {
        sseLineCount++;
      }
    }
    return sseLineCount > 0 && sseLineCount >= Math.min(lines.length, 2);
  }

  function prettySSE(raw) {
    const lines = raw.split(/\r?\n/);
    const result = [];
    for (const line of lines) {
      if (!line.trim()) {
        result.push("");
        continue;
      }
      if (line.startsWith(":")) {
        result.push(`: ${line.slice(1).trim()}`);
        continue;
      }
      const match = line.match(/^([A-Za-z_-]+)\s*:\s*(.*)$/);
      if (match) {
        const [, field, val] = match;
        if (field.toLowerCase() === "data") {
          try {
            const formattedJSON = prettyJSON(val.trim());
            const jsonLines = formattedJSON.split("\n");
            if (jsonLines.length > 1) {
              result.push(jsonLines.map(jl => `data: ${jl}`).join("\n"));
            } else {
              result.push(`data: ${formattedJSON}`);
            }
          } catch {
            result.push(`data: ${val}`);
          }
        } else {
          result.push(`${field}: ${val}`);
        }
      } else {
        result.push(line);
      }
    }
    return result.join("\n");
  }

  function highlight(text, language) {
    if (language === "json") return highlightJSON(text);
    if (language === "html") return highlightHTML(text);
    if (language === "sse") return highlightSSE(text);
    if (language === "form") return highlightFormURLEncoded(text);
    return [{type: "", text}];
  }

  function highlightJSON(text) {
    const tokens = [];
    for (let offset = 0; offset < text.length;) {
      const rest = text.slice(offset);
      const whitespace = rest.match(/^\s+/);
      if (whitespace) {
        tokens.push({type: "", text: whitespace[0]});
        offset += whitespace[0].length;
        continue;
      }
      if (text[offset] === "\"") {
        let end = offset + 1;
        let escaped = false;
        for (; end < text.length; end++) {
          const character = text[end];
          if (escaped) escaped = false;
          else if (character === "\\") escaped = true;
          else if (character === "\"") { end++; break; }
        }
        const value = text.slice(offset, end);
        const following = text.slice(end).match(/^\s*/)[0].length;
        const type = text[end + following] === ":" ? "key" : "string";
        tokens.push({type, text: value});
        offset = end;
        continue;
      }
      const number = rest.match(/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/);
      if (number) {
        tokens.push({type: "number", text: number[0]});
        offset += number[0].length;
        continue;
      }
      const literal = rest.match(/^(?:true|false|null)\b/);
      if (literal) {
        tokens.push({type: "literal", text: literal[0]});
        offset += literal[0].length;
        continue;
      }
      tokens.push({type: "markup", text: text[offset]});
      offset++;
    }
    return tokens;
  }

  function highlightHTML(text) {
    const tokens = [];
    const pattern = /<!--[\s\S]*?-->|<![^>]*>|<\/?[A-Za-z][^>]*>/g;
    let offset = 0;
    for (const match of text.matchAll(pattern)) {
      if (match.index > offset) tokens.push({type: "", text: text.slice(offset, match.index)});
      tokens.push(...highlightHTMLTag(match[0]));
      offset = match.index + match[0].length;
    }
    if (offset < text.length) tokens.push({type: "", text: text.slice(offset)});
    return tokens;
  }

  function highlightHTMLTag(tag) {
    if (tag.startsWith("<!--") || /^<!doctype/i.test(tag)) return [{type: "markup", text: tag}];
    const tokens = [];
    const pattern = /(\"[^\"]*\"|'[^']*')|([A-Za-z_:][\w:.-]*)(?=\s*=)|(<\/?|\/?>)|([A-Za-z][\w:.-]*)/g;
    let offset = 0;
    let tagNameSeen = false;
    for (const match of tag.matchAll(pattern)) {
      if (match.index > offset) tokens.push({type: "", text: tag.slice(offset, match.index)});
      let type = "";
      if (match[1]) type = "string";
      else if (match[2]) type = "key";
      else if (match[3]) type = "markup";
      else if (match[4] && !tagNameSeen) { type = "markup"; tagNameSeen = true; }
      tokens.push({type, text: match[0]});
      offset = match.index + match[0].length;
    }
    if (offset < tag.length) tokens.push({type: "", text: tag.slice(offset)});
    return tokens;
  }

  function highlightSSE(text) {
    const tokens = [];
    const lines = text.split("\n");
    for (let i = 0; i < lines.length; i++) {
      if (i > 0) tokens.push({type: "", text: "\n"});
      const line = lines[i];
      if (!line) continue;
      if (line.startsWith(":")) {
        tokens.push({type: "string", text: line});
        continue;
      }
      const match = line.match(/^([A-Za-z_-]+)(\s*:\s*)(.*)$/);
      if (!match) {
        tokens.push({type: "", text: line});
        continue;
      }
      const [, field, sep, val] = match;
      tokens.push({type: "key", text: field});
      tokens.push({type: "markup", text: sep});
      if (!val) continue;

      const lowerField = field.toLowerCase();
      if ((lowerField === "retry" || lowerField === "id") && /^\d+$/.test(val)) {
        tokens.push({type: "number", text: val});
      } else if (val === "[DONE]" || val === "true" || val === "false" || val === "null") {
        tokens.push({type: "literal", text: val});
      } else if (val.startsWith("{") || val.startsWith("[") || val.startsWith("\"") || /^-?\d/.test(val)) {
        try {
          tokens.push(...highlightJSON(val));
        } catch {
          tokens.push({type: "string", text: val});
        }
      } else {
        tokens.push({type: "string", text: val});
      }
    }
    return tokens;
  }

  function highlightFormURLEncoded(text) {
    const tokens = [];
    const lines = text.split("\n");
    for (let i = 0; i < lines.length; i++) {
      if (i > 0) tokens.push({type: "", text: "\n"});
      const line = lines[i];
      if (!line) continue;
      const idx = line.indexOf("=");
      if (idx === -1) {
        tokens.push({type: "", text: line});
        continue;
      }
      const key = line.slice(0, idx);
      const val = line.slice(idx + 1);
      tokens.push({type: "key", text: key});
      tokens.push({type: "markup", text: "="});

      const trimmedVal = val.trim();
      if (/^-?\d+(?:\.\d+)?$/.test(trimmedVal)) {
        const leading = val.slice(0, val.indexOf(trimmedVal));
        if (leading) tokens.push({type: "", text: leading});
        tokens.push({type: "number", text: trimmedVal});
      } else if (trimmedVal === "true" || trimmedVal === "false" || trimmedVal === "null" || trimmedVal === "[redacted]" || /^\[secret:[^\]]+\]$/.test(trimmedVal)) {
        const leading = val.slice(0, val.indexOf(trimmedVal));
        if (leading) tokens.push({type: "", text: leading});
        tokens.push({type: "literal", text: trimmedVal});
      } else {
        tokens.push({type: "string", text: val});
      }
    }
    return tokens;
  }

  globalThis.VeilgateCaptureFormatters = Object.freeze({format, highlight, prettyJSON, prettyJSONL, prettySSE, prettyFormURLEncoded, readableJSONStrings});
})();
