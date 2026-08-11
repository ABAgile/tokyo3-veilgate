---
version: alpha
name: Veilgate Traffic Console
description: A restrained, security-oriented egress operations console with warm neutral surfaces and precise cyan interaction cues.
colors:
  primary: "#087F8C"
  primary-hover: "#066E79"
  primary-active: "#055A64"
  on-primary: "#FFFFFF"
  surface: "#F5F5F3"
  surface-subtle: "#F0F1EE"
  surface-card: "#FBFAF8"
  secondary-action: "#F3F4F1"
  secondary-action-hover: "#F0F1EE"
  dark-secondary-action: "#303631"
  dark-secondary-action-hover: "#3A423B"
  dark-surface: "#151714"
  dark-surface-subtle: "#242823"
  dark-surface-card: "#1B1E1A"
  dark-on-surface: "#F0F2ED"
  dark-on-surface-muted: "#AEB4AA"
  dark-placeholder: "#777E75"
  surface-selected: "#E8F6F6"
  on-surface: "#20231F"
  on-surface-subtle: "#363A35"
  on-surface-muted: "#5F635D"
  outline: "#EEEEEB"
  outline-strong: "#D1D3CE"
  success: "#18794E"
  success-container: "#EDF8F2"
  warning: "#8F4F00"
  warning-container: "#FFF7E6"
  error: "#B4232C"
  error-container: "#FFF0F1"
  info: "#245EA8"
  info-container: "#EEF6FF"
  syntax-key: "#7A3E00"
  syntax-string: "#176B5B"
  syntax-number: "#6B4FA1"
  syntax-literal: "#A33A4A"
  syntax-markup: "#245EA8"
  dark-syntax-key: "#F0B36A"
  dark-syntax-string: "#76C7B7"
  dark-syntax-number: "#C2A7E8"
  dark-syntax-literal: "#F19AA6"
  dark-syntax-markup: "#8CBDF1"
typography:
  page-title:
    fontFamily: "system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: 22px
    fontWeight: 650
    lineHeight: 1.25
    letterSpacing: -0.02em
  section-title:
    fontFamily: "system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: 18px
    fontWeight: 650
    lineHeight: 1.25
  card-title:
    fontFamily: "system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: 15px
    fontWeight: 650
    lineHeight: 1.3
  body:
    fontFamily: "system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: 15px
    fontWeight: 400
    lineHeight: 1.5
  control:
    fontFamily: "system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: 14px
    fontWeight: 600
    lineHeight: 1.2
  metadata:
    fontFamily: "system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: 14px
    fontWeight: 400
    lineHeight: 1.5
  label-caps:
    fontFamily: "system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: 11px
    fontWeight: 700
    lineHeight: 1.25
    letterSpacing: 0.08em
  code:
    fontFamily: "SFMono-Regular, Cascadia Code, Consolas, monospace"
    fontSize: 12px
    fontWeight: 400
    lineHeight: 1.5
rounded:
  sm: 4px
  md: 6px
  lg: 10px
  full: 999px
spacing:
  xs: 4px
  sm: 8px
  md: 12px
  base: 16px
  lg: 20px
  xl: 24px
  2xl: 32px
  3xl: 40px
  4xl: 48px
  sidebar-width: 240px
  content-max: 1280px
components:
  button-primary:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.on-primary}"
    typography: "{typography.control}"
    rounded: "{rounded.md}"
    padding: 8px 16px
    height: 38px
  button-primary-hover:
    backgroundColor: "{colors.primary-hover}"
    textColor: "{colors.on-primary}"
  button-primary-active:
    backgroundColor: "{colors.primary-active}"
    textColor: "{colors.on-primary}"
  button-secondary:
    backgroundColor: "{colors.secondary-action}"
    textColor: "{colors.on-surface-subtle}"
    typography: "{typography.control}"
    rounded: "{rounded.md}"
    padding: 8px 12px
    height: 38px
  button-secondary-hover:
    backgroundColor: "{colors.secondary-action-hover}"
  button-secondary-dark:
    backgroundColor: "{colors.dark-secondary-action}"
    textColor: "{colors.dark-on-surface}"
  button-secondary-dark-hover:
    backgroundColor: "{colors.dark-secondary-action-hover}"
  card:
    backgroundColor: "{colors.surface-card}"
    textColor: "{colors.on-surface}"
    rounded: "{rounded.lg}"
    padding: "{spacing.lg}"
  navigation-active:
    backgroundColor: "{colors.surface-selected}"
    textColor: "{colors.primary-active}"
    rounded: "{rounded.md}"
    padding: 8px 12px
  badge-success:
    backgroundColor: "{colors.success-container}"
    textColor: "{colors.success}"
    rounded: "{rounded.full}"
    padding: 2px 8px
  badge-warning:
    backgroundColor: "{colors.warning-container}"
    textColor: "{colors.warning}"
    rounded: "{rounded.full}"
    padding: 2px 8px
  badge-danger:
    backgroundColor: "{colors.error-container}"
    textColor: "{colors.error}"
    rounded: "{rounded.full}"
    padding: 2px 8px
  badge-info:
    backgroundColor: "{colors.info-container}"
    textColor: "{colors.info}"
    rounded: "{rounded.full}"
    padding: 2px 8px
  table-heading:
    textColor: "{colors.on-surface-muted}"
    typography: "{typography.label-caps}"
  control-outline:
    backgroundColor: "{colors.outline-strong}"
    size: 1px
  page-canvas:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.on-surface}"
  page-canvas-dark:
    backgroundColor: "{colors.dark-surface}"
    textColor: "{colors.dark-on-surface}"
  card-dark:
    backgroundColor: "{colors.dark-surface-card}"
    textColor: "{colors.dark-on-surface}"
    rounded: "{rounded.lg}"
    padding: "{spacing.lg}"
  status-strip-dark:
    backgroundColor: "{colors.dark-surface-subtle}"
    textColor: "{colors.dark-on-surface-muted}"
  placeholder-dark:
    textColor: "{colors.dark-placeholder}"
    typography: "{typography.body}"
  syntax-key:
    textColor: "{colors.syntax-key}"
    typography: "{typography.code}"
  syntax-string:
    textColor: "{colors.syntax-string}"
    typography: "{typography.code}"
  syntax-number:
    textColor: "{colors.syntax-number}"
    typography: "{typography.code}"
  syntax-literal:
    textColor: "{colors.syntax-literal}"
    typography: "{typography.code}"
  syntax-markup:
    textColor: "{colors.syntax-markup}"
    typography: "{typography.code}"
  syntax-key-dark:
    textColor: "{colors.dark-syntax-key}"
    typography: "{typography.code}"
  syntax-string-dark:
    textColor: "{colors.dark-syntax-string}"
    typography: "{typography.code}"
  syntax-number-dark:
    textColor: "{colors.dark-syntax-number}"
    typography: "{typography.code}"
  syntax-literal-dark:
    textColor: "{colors.dark-syntax-literal}"
    typography: "{typography.code}"
  syntax-markup-dark:
    textColor: "{colors.dark-syntax-markup}"
    typography: "{typography.code}"
---

# Veilgate Design System

## Overview

Veilgate copies the Tokyo3 operations-console foundation used by Tokyo3 Auth:
a well-kept control-room logbook translated into a modern interface. It keeps
the shared warm surfaces, compact typography, spacing, and shape language, but
uses **deep cyan** interaction cues so operators can distinguish the traffic
console immediately from Auth's indigo and CA's plum.

The console is a read-only examination surface for security-relevant egress
flows. It should make the client identity, destination, policy decision,
timing, denial reason, and bounded sanitized application traffic easy to
inspect without implying that captured traffic can be replayed or modified.

- Warm off-white canvas and quiet cards in light mode.
- Charcoal canvas by default in dark mode.
- Cyan only for links, focus, selection, and active controls.
- Semantic green, amber, red, and blue remain reserved for status.
- Compact flow tables with complete, plain-language empty states.
- No decorative charts, gradients, glass effects, or hero metrics.

## Colors

The primary cyan (`{colors.primary}`) identifies interaction, never traffic
health. Allowed and denied decisions use the semantic success and error colors
and always include text. The selected-flow surface uses
`{colors.surface-selected}`. Light surfaces and semantic colors remain aligned
with the wider Tokyo3 family.

Dark mode uses `#151714`, `#1B1E1A`, and `#242823` for its three surface levels.
Cyan controls use `#0A6972`, hover `#0D7983`, active `#168D98`, links `#63CDD2`,
and focus `#82E0E3`; the dark selected surface is `#17383A`. These values are
part of this design decision and must remain synchronized with the CSS.

Never communicate policy state through color alone. “Allowed” and “Denied”
must remain visible text even where a colored status dot or badge is present.

## Typography

Use the native system sans-serif stack and the token sizes above. Technical
values—flow IDs, client identities, hostnames, destination addresses, methods,
and durations—use the monospace stack where comparison benefits from fixed
width. Use sentence case. Table labels alone may use compact uppercase styling.

## Layout

The console has a `{spacing.sidebar-width}` navigation rail and a content region
capped at `{spacing.content-max}`. The initial navigation contains only Traffic;
do not add destinations for policy editing, secrets, certificates, or settings
until those routes exist.

The flow list is the primary working surface and always fills the available page
workspace below the header; it keeps its full height whether or not a flow is
selected. A compact filter toolbar above it supports client, host, decision, and
mediation-mode filtering; filters apply explicitly and can be reset as one
operation. CONNECT sessions form collapsible parent rows with their intercepted
HTTP or WebSocket requests ordered beneath them; standalone HTTP remains
ungrouped. Group state and table position remain stable while live events
arrive. This preserves table position while examining long captures.

The list is paginated newest-first. It requests a bounded page of recent flows
rather than the entire retained history, and reveals older flows progressively:
a sentinel at the end of the list loads the next older page as it approaches the
viewport, and an always-present, keyboard-focusable "Load older flows" control
performs the same action explicitly for keyboard and screen-reader operators. A
plain-text end-of-history state states when no older flows remain. Live arrivals
prepend without disturbing the operator's scroll position or an open selection,
except when the operator is resting at the top of the list: within a 40px
tolerance of the top, and with no flow selected, the list follows the feed,
letting new rows appear in place and snapping back to the exact top so the
newest row is not left behind the sticky column header.

Selecting a flow opens an inline detail drawer as an expanded row directly
beneath the selected row, not a separate lower pane. Selecting the same row
closes it; only one drawer is open at a time. The drawer is internally organized
into tabs — Overview, Request, Response, and WebSocket — each with its own
plain-language empty state; the security-critical Overview tab is selected by
default. The tab body is height-bounded (maximum 60vh) with its own scrollbar so
a large capture never pushes the rest of the list off-screen, and the table head
stays pinned while the list scrolls. Anchoring detail to its row keeps a single
scroll container and preserves the operator's place. At 640px and below the
drawer follows the natural stacked document flow. The Overview tab shows
identity, target, destination IP, decision, mediation mode, independently
negotiated downstream and upstream HTTP protocols, substituted and scrubbed
secret names, status, bytes, duration, reason, and an ordered policy-decision
trace. The Request and Response tabs each split into **Headers** and **Body**
second-level sub-tabs so operators can compare metadata and payloads
independently; the Headers sub-tab is selected by default. The request Headers
sub-tab also carries the bounded sanitized query value. The Body sub-tabs show
supported textual request and response bodies. The WebSocket tab lists text
messages and metadata-only binary WebSocket records. Text streams have a compact
message navigator with chronological message numbers, direction and event-type
filters, text search, previous/next match controls, and a current/total count.
High-volume contiguous JSON delta events may be summarized by stable response and
item identifiers, but every original message remains available in an expandable
chronological raw view. Formatted HTML, JSON, JSONL, Server-Sent Events
(text/event-stream), and Form URL-Encoded (application/x-www-form-urlencoded)
bodies open prettified with the documented syntax-key/string/number/literal/
markup highlighting and a Raw/Prettify toggle in both light and dark mode.
Long or multiline JSON string values keep their lexical representation in the
highlighted code and additionally expose collapsed, text-only readable previews
with their JSON path and line count. Binary records show direction, decoded
byte size, and SHA-256; binary bytes and Base64 are never retained. Captures use `[secret:name]` markers and
must never show proxy credentials, credential-bearing header values,
placeholders, or post-substitution secret values. Unsupported HTTP binary
content is identified as omitted rather than decoded or rendered. The detail
notice states that captures are bounded plaintext and may retain unrelated
sensitive data.

At widths below 900px the sidebar becomes a compact top rail. At widths below
640px, table rows become stacked records in two labeled columns separated by
`{spacing.base}` so a wrapped target never abuts the adjacent value, and
nonessential columns are hidden;
the document must not overflow horizontally. Controls and rows must remain
usable at 390px. Dark mode is the default; a locally persisted explicit theme
choice overrides it.

## Elevation and shapes

Use flat tonal layers and 1px outlines. Cards may use only a subtle
`0 1px 2px` shadow at approximately 6% opacity. Controls use
`{rounded.md}`, cards `{rounded.lg}`, and badges `{rounded.full}`. Table rows do
not lift on hover. The selected row may use the documented selected surface and
a cyan leading rule.

## Components and interaction

- **Application shell:** product name and one-sentence role in the sidebar,
  Traffic as the sole active destination, connection freshness and theme
  control in the footer.
- **Page header:** one H1 and a restrained description, paired with an aligned connection status badge and feed control button (`Pause feed` / `Resume feed`). Opening a flow detail drawer automatically pauses the live stream to prevent content jumps during inspection; closing the drawer resumes it, and the list keeps its place by anchoring on the row the operator was reading rather than on a raw scroll offset. A pause the operator requested explicitly survives opening and closing a drawer. The resume button, as well as applying or resetting filters, refetches history and re-establishes the live connection.
- **Status strip:** states whether the console is connected to the event feed;
  it is operational context, not a vanity metric.
- **Filter toolbar:** labeled client text field, host combo field (text input paired with a dynamic datalist of discovered hostnames updated in real time), native decision and mode selects, one primary Apply action, and one secondary Reset action.
  The URL query string reflects active filters without containing captured
  request data. Filtering does not pause the live feed; new rows appear only
  when they match the active filters.
- **Flow table:** newest first, keyboard-selectable buttons, stable timestamps,
  status text, client, method, target, response status, size, and duration.
- **Flow list pagination:** the list loads a bounded newest-first page and
  extends toward older flows through an end-of-list sentinel that auto-loads as
  it nears the viewport, plus an always-visible, keyboard-focusable "Load older
  flows" button. A plain-text state reports when the full retained history has
  been reached. Live arrivals never move an operator who is reading older flows.
- **Live feed follow mode:** while the operator is within 40px of the top of the
  list and no flow is selected, prepended live arrivals push the existing rows
  down and the list snaps back to the exact top so the newest flow clears the
  sticky column header. Only live arrivals snap; expanding a row, opening a
  drawer, and loading older history never move the viewport. Scrolling past the
  tolerance, or selecting a flow, restores scroll anchoring so content never
  shifts under the operator. The tolerance keeps a slightly nudged scroll
  position in follow mode instead of silently dropping out of it, and the snap
  is instant rather than smooth so it stays within the reduced-motion contract.
- **Flow detail drawer:** an inline expanded row beneath the selected flow,
  toggled by selecting the row again, with a horizontal tab list (Overview,
  Request, Response, WebSocket). Tabs are real `role="tab"` buttons with
  `aria-selected` state and arrow-key/Home/End navigation; the active tab uses a
  cyan underline paired with the selected state, never color alone. The Request
  and Response tabs each contain a smaller second-level `role="tab"` sub-tablist
  with Headers and Body, following the same keyboard and selected-state rules at
  a reduced size. The tab body is height-bounded with its own scrollbar. Overview
  holds a definition list with
  selectable technical values, interception mode, downstream and upstream
  protocol values, substituted and response-scrubbed secret names (never
  values), an ordered policy trace using plain pass/fail text and detail, and an
  explicit notice that capture is bounded and sanitized. Opaque CONNECT sessions
  remain distinguishable from intercepted HTTP requests.
- **Capture panel:** separate Request, Response, and WebSocket sections below
  metadata. Sanitized request and response headers appear as name/value rows;
  authentication, cookie, token, API-key, credential, and secret values show
  `[redacted]`, while configured material elsewhere shows `[secret:name]`.
  When gateway mediation substitutes a JSON request value, the forwarded body
  is intentionally parsed and re-marshaled; key order, duplicate keys, and
  HTML-sensitive escaping may change, and request-body signatures may no
  longer verify. Integrity headers are removed rather than presented as
  trustworthy after transformation.
  Query and body content uses the code typography in a bordered,
  preformatted card with wrapping and selectable text. Each section has a
  visible content-type label and an explicit empty, omitted, or truncated state.
  Text is inserted as text content, never interpreted as markup. Multiline JSON
  string previews decode display-only escape sequences without changing the
  retained or Raw representation; incomplete or truncated string tokens do not
  produce a preview. WebSocket messages identify client-to-upstream or
  upstream-to-client direction and retain chronological order; binary messages
  show metadata only. The WebSocket navigator filters and searches the retained
  sanitized text, labels JSON event types, summarizes only contiguous compatible
  delta events, and keeps each source message expandable for exact examination.
  Built-in display formatter plugins recognize
  HTML, JSON, JSONL/NDJSON, Server-Sent Events (text/event-stream), and Form URL-Encoded (application/x-www-form-urlencoded) by media type with conservative content
  detection as a fallback. Supported captures open prettified for readability
  and provide a secondary Raw/Prettify toggle; formatting changes display only,
  never the retained capture. JSON formatting preserves lexical number and
  string tokens. Formatted HTML, JSON, JSONL, SSE, and Form URL-Encoded use the documented syntax-key,
  syntax-string, syntax-number, syntax-literal, and syntax-markup colors in
  light and dark mode. Highlighting reinforces token shape and punctuation and
  is never the only representation of meaning. Formatted content is still
  inserted as text, never rendered as active HTML.
- **Empty state:** explains that flows appear after an authenticated client uses
  the proxy; it does not fabricate sample traffic.
- **Theme control:** a labeled button, persisted in local storage, with a
  visible focus state.

The console updates without stealing focus or announcing every high-frequency
flow. The freshness state may use a polite live region. Reduced-motion
preferences disable the brief new-row highlight.

## Accessibility

Maintain WCAG AA text contrast, visible `:focus-visible` outlines, semantic
headings, table headers, buttons for selectable rows, and a polite connection
status. Do not use clickable `div` elements. Timestamps use `<time>` and expose
the full ISO value. The responsive representation preserves labels rather than
relying on column position alone.

## Do's and Don'ts

- **Do** make identity, destination, decision, and denial reason obvious.
- **Do** keep bounded captured values selectable and sanitized with explicit
  `[secret:name]` markers.
- **Do** let operators switch formatted HTML/JSON/JSONL/SSE/Form URL-Encoded captures back to their
  exact retained raw representation.
- **Do** provide readable previews for long or multiline JSON strings without
  replacing the lexical JSON code view.
- **Do** let operators search, filter, summarize, and expand high-volume
  WebSocket streams without losing chronological raw messages.
- **Do** keep the flow list at full height and anchor the detail drawer to its
  row so the operator never loses their place, including during live arrivals
  and pagination.
- **Do** expose CONNECT grouping and sanitized header names without revealing
  authentication, cookie, token, API-key, credential, or secret header values.
- **Do** pair every status color with meaningful text.
- **Do** preserve keyboard operation and visible focus.
- **Do** distinguish live, stale, and disconnected event-feed states in text.
- **Don't** imply request replay, policy mutation, unredacted credential-header
  viewing, placeholder viewing, or secret-value viewing.
- **Don't** add charts, aggregate hero cards, gradients, glows, or animation.
- **Don't** use cyan as a synonym for allowed traffic.
- **Don't** render raw `Authorization`, `Proxy-Authorization`, cookies,
  placeholders, or post-substitution values.
- **Don't** introduce a frontend framework or asset build pipeline for this
  console.
