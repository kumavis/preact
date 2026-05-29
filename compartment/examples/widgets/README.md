# Confined widgets demo

A small Vite demo for `preact/compartment`. Three untrusted widgets,
each evaluated in its own SES `Compartment`, render side by side in
a trusted host shell. Each widget receives a host-controlled "log
out" button via opaque transclusion. A "malicious" widget tries every
attack the renderer defends against; the page logs whether any of
them landed.

## Running

```sh
cd compartment/examples/widgets
npm install
npm run dev
```

Then open the printed URL.

Vite resolves `preact`, `preact/hooks`, `preact/secure`, and
`preact/compartment` directly to the source in this repo (see
`vite.config.mjs`), so the demo exercises the same code the tests do.

## What to look for

- The **Counter** uses `useState` from the endowments bundle. The
  attacker function never reaches into the DOM — it only calls
  `h('button', { onClick })`.
- The **Form** reads `e.target.value` from a `SafeEvent`. Submitting
  calls back into the host with the primitive name string. Try typing
  in the field, the value is reflected on each keystroke.
- The **Malicious** widget tries `<script>`, `javascript:` URLs, refs,
  and `dangerouslySetInnerHTML`. The event log at the bottom of the
  page reports `undefined ✓` / `(stripped) ✓` / `none ✓` after mount,
  proving each attack was neutralized.
- Each widget renders a `<div class="host-slot">` containing the
  host's log-out button. The widget chose **where** to position it;
  the widget cannot inspect or impersonate the host vnode. Clicking
  the button logs "real DOM event" — the host's handler runs in the
  host's context (refs work, raw events).

## Threat model recap

- SES `lockdown()` runs first.
- Each widget is evaluated via `compartment.evaluate('(' + source +
  ')')`. The compartment has empty globals.
- The wrapper hands the resulting function `(endowments, props)`. All
  capabilities flow through `endowments`.
- The wrapper coerces the return value through `coerceToSafeVNode`,
  rebuilding via our own `h()`.
- The whole tree mounts via `secureRender`, which sanitizes refs,
  disallowed tags, URL schemes, and event listeners across the
  confined subtrees.

For the protected / unprotected matrix (including the ambient-
authority channels this demo intentionally does NOT exercise), see
`../../README.md` and `../../../secure/README.md`.
