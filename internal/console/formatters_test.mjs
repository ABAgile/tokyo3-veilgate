import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import test from "node:test";
import vm from "node:vm";

const context = {globalThis: {}};
vm.runInNewContext(
  readFileSync(new URL("static/formatters.js", import.meta.url), "utf8"),
  context,
);
const formatters = context.globalThis.VeilgateCaptureFormatters;

test("formats application/json with syntax tokens", () => {
  const formatted = formatters.format(
    "application/json; charset=utf-8",
    '{"name":"Ada","count":42,"enabled":true}',
  );

  assert.equal(formatted.language, "json");
  assert.equal(formatted.text, '{\n  "name": "Ada",\n  "count": 42,\n  "enabled": true\n}');
  assert.deepEqual(
    Array.from(formatters.highlight(formatted.text, formatted.language), token => token.type)
      .filter(Boolean),
    ["markup", "key", "markup", "string", "markup", "key", "markup", "number", "markup", "key", "markup", "literal", "markup"],
  );
});

test("formats and highlights truncated JSON captures", () => {
  const formatted = formatters.format("application/json", '{"items":[1,2');

  assert.equal(formatted.language, "json");
  assert.equal(formatted.text, '{\n  "items": [\n    1,\n    2');
  assert.ok(formatters.highlight(formatted.text, formatted.language).some(token => token.type === "key"));
});

test("extracts readable previews without changing JSON tokens", () => {
  const formatted = formatters.format("application/json", JSON.stringify({
    instructions: "first line\nsecond line",
    nested: {long_value: "x".repeat(160)},
  }));

  assert.equal(formatted.text.includes("first line\\nsecond line"), true);
  assert.deepEqual(
    Array.from(formatted.previews, preview => [preview.path, preview.text, preview.lines]),
    [
      ["$.instructions", "first line\nsecond line", 2],
      ["$.nested.long_value", "x".repeat(160), 1],
    ],
  );
});

test("bounds readable previews while traversing large arrays", () => {
  const formatted = formatters.format("application/json", JSON.stringify(Array.from({length: 100}, () => "x".repeat(160))));

  assert.equal(formatted.previews.length, 24);
  assert.equal(formatted.previews[23].path, "$[23]");
});

test("extracts readable previews from JSON in SSE data fields", () => {
  const formatted = formatters.format("text/event-stream", [
    "event: message",
    `data: ${JSON.stringify({message: "first line\nsecond line", nested: {prompt: "p".repeat(160)}})}`,
    "",
    `data: ${JSON.stringify({message: "third line\nfourth line"})}`,
    "",
  ].join("\n"));

  assert.equal(formatted.language, "sse");
  assert.deepEqual(
    Array.from(formatted.previews, preview => [preview.path, preview.text, preview.lines]),
    [
      ["event 1.message", "first line\nsecond line", 2],
      ["event 1.nested.prompt", "p".repeat(160), 1],
      ["event 2.message", "third line\nfourth line", 2],
    ],
  );
});

test("skips encrypted content from readable previews without changing JSON", () => {
  const raw = JSON.stringify({
    encrypted_content: "ciphertext".repeat(40),
    readable: "operator-visible text".repeat(12),
    nested: {ENCRYPTED_CONTENT: "more ciphertext".repeat(20)},
  });
  const formatted = formatters.format("application/json", raw);

  assert.match(formatted.text, /encrypted_content/);
  assert.match(formatted.text, /ciphertext/);
  assert.deepEqual(
    Array.from(formatted.previews, preview => preview.path),
    ["$.readable"],
  );
});
