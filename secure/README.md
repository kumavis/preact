# `preact/secure`

A sanitizing Preact renderer. Component code rendered through
`secureRender` never sees DOM nodes, raw DOM `Event` objects, or any
ambient authority the host did not explicitly hand it. The renderer
strips refs and other DOM-leak vectors, blocks dangerous tag names,
validates URL schemes, and wraps event listeners into a frozen
`SafeEvent` facade.

## Install

This package lives alongside `preact`, `preact/hooks`, `preact/compat`,
etc. Once it ships:

```js
import { secureRender, unmount, SecureExit } from 'preact/secure';
```

## Quick start

```jsx
import { h } from 'preact';
import { secureRender } from 'preact/secure';

function App({ name }) {
  return (
    <button onClick={(e) => console.log('clicked', e.type)}>
      hi {name}
    </button>
  );
}

secureRender(<App name="world" />, document.getElementById('root'));
```

The `onClick` handler receives a `SafeEvent`, not a DOM `MouseEvent`:
no `target.parentNode`, no `currentTarget`, no `view`.

## Threat model

The renderer is built for the case where the **component code is not
trusted** by the host. Examples:

- a plugin loaded from another origin
- third-party JSX evaluated in a SES `Compartment`
- user-authored render snippets

The host trusts:

- the JavaScript runtime and the Preact library
- the DOM element it hands to `secureRender` as the mount point
- props it explicitly passes to the root vnode

The renderer defends:

1. **Live DOM access** — refs (object, callback, forwarded-via-props)
   are stripped, so component code can never obtain a reference to a
   mounted element.
2. **Raw DOM events** — every `on*` handler is wrapped. The wrapper
   constructs a frozen `SafeEvent` with primitive snapshots of
   `target` and `currentTarget` (`{ tagName, name, id, type, value,
   checked, selectedIndex }`) and methods that proxy to the underlying
   event (`preventDefault`, `stopPropagation`,
   `stopImmediatePropagation`).
3. **HTML injection and live DOM-setter abuse** — `BLOCKED_PROPS`
   removes a denylist of prop names that would otherwise reach a
   dangerous setter via Preact's `name in dom` path or via
   `setAttribute` + browser case normalization. Today this includes
   `dangerouslySetInnerHTML`, `is`, `srcdoc`, the DOM
   property writeables `innerHTML` / `outerHTML` / `textContent` /
   `innerText` / `nodeValue`, the `HTMLHyperlinkElementUtils`
   URL-component setters (`hostname` / `host` / `port` / `protocol` /
   `pathname` / `search` / `hash` / `username` / `password`),
   the anchor `text` setter, `attributionSrc`, and `inert`.
   Comparison is case-insensitive, so case-variants like `INNERHTML`
   or `OnError` are also blocked (the browser normalizes attribute
   names to lowercase, so a case-variant would otherwise survive to
   `setAttribute` and end up as the canonical-cased content
   attribute).
4. **Dangerous element types** — tag names outside a configurable
   allowlist are replaced with `Fragment` so the offending element
   disappears while its children continue to render. The default list
   covers ~80 common semantic, form, media, and text elements.
   Excluded by default: `<script>`, `<iframe>`, `<object>`, `<embed>`,
   `<base>`, `<meta>`, `<link>`, `<style>`, plus anything not on the
   list.
5. **URL scheme injection** — attributes that carry URLs (`href`,
   `src`, `formaction`, `action`, `srcset`, `poster`, `cite`, `data`,
   `background`, `ping`, `xlinkHref`) are scheme-checked. Allowed:
   `https?:`, `mailto:`, `tel:`, `sms:`, `ftp:`, relative paths,
   fragments, and `data:image/*` for `src`/`poster` only. Everything
   else (`javascript:`, `vbscript:`, unknown schemes,
   control-character-prefixed schemes) is dropped.
6. **Inline event-handler strings** — `onClick="alert(1)"` (as a
   string value) is rejected; only function-typed handlers reach the
   DOM.

## API

### `secureRender(vnode, parentDom, opts?)`

Render `vnode` into `parentDom` under the sandbox. Re-call with the
same `parentDom` to update.

`opts.allowedTags` is an iterable of tag names that overrides the
default allowlist for this tree only. Multiple `secureRender` calls
with different allowlists can coexist — each tree carries its own
list, even across state-driven re-renders.

### `unmount(parentDom)`

Tear down the tree rooted at `parentDom`.

### `SecureExit`

```jsx
<SecureExit>{hostTrustedSubtree}</SecureExit>
```

Renders its children with sanitization *turned off*. Refs work,
attributes pass through, the full Preact API is in scope. Use this
only with vnodes the host fully controls — e.g. when transcluding
host-supplied content through an untrusted component (the companion
`preact/compartment` addon does exactly this for its opaque-children
mechanism).

A `SecureExit` is balanced internally: an exception thrown inside the
island does not leave the renderer's depth counters elevated, and the
counter is restored even when the surrounding tree has no error
boundary.

## Known gaps — ambient authority (NOT covered)

The sanitizer protects against *direct* DOM access and HTML injection,
but the browser exposes a large surface of side effects that fire
simply because a sanitized element is in the tree. These channels can
exfiltrate or beacon even though every API surface looks clean. They
are documented here so hosts can make an informed call about whether
to add their own protections on top (e.g. a CSP, an iframe sandbox, a
proxying mount):

| Vector | Status | Note |
|---|---|---|
| `<img src="https://attacker/pixel">` | **unblocked** | GET fires on render. Classic identity beacon. |
| `<audio src="…">`, `<video src="…">`, `<track src="…">`, `<source src="…">` | **unblocked** | Same as `<img>` — auto-fetches on render. |
| Inline `style={{ background: 'url(https://attacker/…)' }}` | **unblocked** | The renderer applies the style as-is. The CSS engine fetches the URL when it paints. Style values are not parsed. |
| `<a href="https://attacker" target="_blank">` | **unblocked** | User click → cross-origin navigation. No `rel="noopener noreferrer"` is forced. |
| `<a ping="https://attacker">` | **unblocked** | `ping` is in `URL_ATTRS`, so it gets scheme-checked, but `https://` passes the check. Browser fires a beacon on link click. |
| `<form action="https://attacker">` | **partial** | The `action` URL scheme is checked; `https://attacker` passes. If the user (or the attacker via a `<button type="submit">`) submits the form, a cross-origin POST happens. Components have to call `e.preventDefault()` on `onSubmit` to stop this. |
| `<link>`, `<style>`, `<script>`, `<iframe>`, `<object>`, `<embed>`, `<meta>` | **blocked** | Not on the allowlist; replaced with `Fragment`. |

If your threat model requires blocking these channels, layer on top
one of:

1. **A strict Content Security Policy.** `img-src 'self'`,
   `media-src 'self'`, `style-src 'self'`, `connect-src 'self'`,
   `form-action 'self'`, etc. closes most of the gaps at the browser.
2. **An iframe sandbox** rendering into a separate origin/`sandbox`
   attribute.
3. **A "strict resources" mode** of this renderer (not yet
   implemented). The hooks in `src/index.js` are small additive
   changes: tighten `URL_ATTRS` to require same-origin / `data:`,
   strip `ping`, force `rel="noopener noreferrer"` on
   `target="_blank"`, and pull `form` off the default allowlist.

### Sanitization-bypass via cloneElement

The renderer does **not** re-export `cloneElement`. If your host
imports `cloneElement` from `preact` directly and uses it on a vnode
*after* obtaining it from untrusted code but *before* calling
`secureRender`, the clone's props will not have gone through the
input-tree walk — and a `ref` you forward via clone, for example,
would attach. State-driven re-renders inside the secure tree are
unaffected (they're caught by the per-vnode hook), only the input
tree relies on the entry walk.

Recommendation: do not pre-process untrusted vnodes outside the
renderer. If you must, also call the renderer's `walkSanitize` (not
currently exposed — file an issue if you need it).

## Notes for integrators

- Refs are stripped *unconditionally* in the secure subtree. If you
  need a ref on host-trusted content nested inside an untrusted tree,
  wrap that content in `<SecureExit>...</SecureExit>`.
- `e.target` / `e.currentTarget` on a `SafeEvent` are frozen
  snapshots. Reading them does not change. Reading later does not
  reflect the live DOM. If you need to react to *current* input
  values, use the snapshot inside the handler itself (it's captured
  at dispatch time).
- `e.defaultPrevented` is a live getter that reflects the underlying
  event's state, so chained handlers see the right value after a
  `preventDefault()` upstream.
- The first call to `secureRender` patches Preact's option hooks
  (`vnode`, `_render`, `diffed`, `_catchError`) once. The hooks are
  no-ops outside a secure subtree, so importing this module does not
  affect the rest of the page's render pipeline.

### How the input tree is sanitized

A call to `secureRender(vnode, parentDom, opts?)` does three things in
order:

1. Resolves the per-tree allowlist (from `opts.allowedTags` or the
   default ~80-tag list).
2. Walks `vnode` once *eagerly* — `walkSanitize` — and strips refs,
   blocks dangerous props, replaces disallowed tags with Fragments,
   and scheme-checks URLs. This catches vnodes the host created before
   the depth-based options hooks could see them.
3. Wraps `vnode` in a `SecureBoundary` and hands it to Preact's
   `render`. From then on the option hooks (`vnode`, `_render`,
   `diffed`, `_catchError`) sanitize state-driven re-renders and
   propagate the per-tree allowlist down via a `_secureAllowedTags`
   field on each vnode.

The entry-time walk stops descending at two markers:

- A vnode whose type is `SecureExit` — its children are an explicitly
  trusted island and must keep their refs.
- A vnode whose type has `type._haltSanitizeChildren === true` — used
  by `preact/compartment` so host children destined for opaque slots
  reach the slot un-stripped. Other addons can opt into the same
  contract by setting the flag on their wrapper functions.

### Defense-in-depth notes

- `options._render` deliberately does NOT trust `vnode._secureCtx` set
  on the child vnode alone. The bracket is entered only when a parent
  or the boundary type marker is present. Today every flagged vnode
  comes from our own hooks, so this is conservative; the gate would
  still hold if a future code path ever mounted a vnode without going
  through the input-tree walk first.
- The `trustedExitDepth` and `secureRenderDepth` counters are cleaned
  up in `options._catchError`, so an unhandled render exception does
  not leave the renderer in a half-bracketed state and subsequent
  host renders are handled correctly.
