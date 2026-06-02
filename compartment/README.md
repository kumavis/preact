# `preact/compartment`

Mount component code the host did not write — for example, JSX a host
evaluated in a SES `Compartment` — inside a regular Preact tree. The
attacker function can return any JavaScript value as its render
result; the wrapper coerces by walking once and rebuilding via our own
`h()`, then renders inside the `preact/secure` sandbox.

This module is **SES-agnostic**: it does not call `new Compartment(…)`
itself. The host evaluates source in their own compartment and hands
us the resulting function.

## Install

```js
import {
  confineComponent,
  isConfinedComponent
} from 'preact/compartment';
import { secureRender } from 'preact/secure';
```

## Quick start

> ⚠️ **SES `lockdown()` is a hard precondition.** Without it, every
> endowment we hand the attacker exposes the host realm's
> `Function` via its `.constructor` chain — the attacker can do
> `endowments.h.constructor('return globalThis')()` and obtain
> `globalThis`, `document`, `window`, the live DOM tree, and every
> module the host has imported. `lockdown()` taming neutralizes the
> `Function` constructor and that escape ceases to exist. The module
> emits a `console.warn` if it does not detect a successful
> lockdown. Treat that warning as a security blocker, not a soft
> reminder.
>
> Detection is a best-effort heuristic — `typeof globalThis.harden
> === 'function'`. Any module that defines a global `harden`
> (e.g. an unrelated deep-freeze polyfill) silences the warning
> even without a real `lockdown()`. Hosts that rely on the
> compartment's security guarantees should not depend on the
> warning alone — call `lockdown()` directly during bootstrap.

```js
import 'ses';

// IMPORTANT: pass `overrideTaming: 'severe'` so prototype properties
// (notably `constructor`) stay overridable. Preact's vnode-clone
// helper writes `constructor: undefined` as the vnode tag, and
// without this option SES will throw when the helper tries to
// overwrite the frozen `Object.prototype.constructor`. The lockdown
// is still real — primordials are frozen, the compartment isolation
// is in force.
lockdown({ overrideTaming: 'severe' });

// Host evaluates untrusted source in its own compartment.
const compartment = new Compartment(/* host's chosen globals */);
const attackerFn = compartment.evaluate(`
  ({ h, useState }, props) => {
    const [n, setN] = useState(0);
    return h('button', {
      onClick: () => setN(prev => prev + 1)
    }, 'clicked ' + n + ' times');
  }
`);

// Wrap and mount.
const Widget = confineComponent(attackerFn, { name: 'Widget' });
secureRender(<Widget />, document.getElementById('root'));
```

The attacker's function signature is **`(endowments, props)`**, not
React's `(props)`. The `endowments` argument is the only way to
acquire `h`, `Fragment`, and hooks inside the sandbox.

## API

### `confineComponent(fn, opts?)`

Wrap an attacker function as a Preact function component.

`fn` is called with `(endowments, props)`:

- `endowments` — a frozen object containing `h`, `Fragment`,
  `useState`, `useEffect`, `useCallback`, `useMemo`, `useRef`,
  `useReducer`.
- `props` — a frozen object containing the host's props, with
  `children` replaced by an array of opaque sentinel vnodes the
  attacker can position but not inspect.

`opts.name` sets the devtools display name. `opts.onError` is a
callback fired when the attacker function throws; the host's render
is not interrupted and the offending pass renders nothing. An
`onError` that itself throws is swallowed.

The attacker may return any value. The coercer accepts:

- primitives (`string`, `number`, `bigint`, `boolean`, `null`,
  `undefined`)
- arrays (recursed)
- plain Preact vnodes (rebuilt via our own `h()`, including `key`)

Anything else (Promise, Proxy, class instance, plain object, function)
is dropped. Disallowed `.type` values become `Fragment` so children
still render.

### `isConfinedComponent(value)`

Returns `true` for wrappers returned by `confineComponent`. Useful
for the host to assert it's mounting a confined function.

### Re-export

`SecureExit` from `preact/secure` is re-exported for advanced hosts
that want to splice trusted islands manually.

## Transclusion (opaque children)

The host can pass children through to the attacker:

```jsx
secureRender(
  <Widget>
    <div className="logout-button" onClick={signOut}>Log out</div>
  </Widget>,
  root
);
```

From the attacker's point of view, `props.children` is an array of
opaque sentinels. The attacker can position them — `h('header', null,
props.children[0])` — but cannot read the host vnode they represent,
because:

- the sentinel's vnode props carry only a frozen empty marker object,
  not the host vnode itself;
- the host vnode is held in a **per-render** `Map` that the renderer
  scopes via `options._render` / `options.diffed` hooks. The map is
  `.clear()`-ed and dropped at `diffed`; a slot the attacker stashed
  in their own state (`useRef`, closure) becomes a useless frozen
  empty object after the render that issued it completes.

When a sentinel mounts, it returns the original host vnode directly.
The renderer recognises `OpaqueChild` by IDENTITY as a trusted-exit
boundary (registered with `preact/secure` at module load) and turns
sanitization off for that subtree — host refs work, host event
handlers fire with real DOM events, etc. The host trusts its own
subtree.

The sentinel deliberately does NOT render a `<SecureExit>`-wrapped
vnode: that would have let the attacker read `.type` off the
sentinel's render output and obtain a reusable reference to
`SecureExit`. With the inline mechanism, no public reference to a
trusted-exit type ever appears in attacker-reachable JSX.

### Nesting and lifecycle

- **Confined inside SecureExit re-engages sanitization.** A host can
  render a host-trusted subtree (the `SecureExit` island) that itself
  contains a confined component. The confined component restarts
  sanitization for everything it returns, so an attacker buried
  inside an island still cannot reach the DOM.
- **Confined inside confined works.** A confined component's coercer
  recognises other confined component types and renders them
  normally. Each nested confined level applies its own coercer.
- **Multi-mount cleanup.** Each render mints fresh opaque sentinels
  in a fresh per-render `Map`. When the diff completes, the map is
  cleared and dropped. A slot stashed by attacker state from a
  previous mount no longer resolves; mounting `Confined` with one
  set of children, unmounting, and re-mounting with different
  children renders the new content, not stale content. Cross-tenant
  stashing (Tenant A grabbing a slot, Tenant B trying to render it)
  is also defeated by this mechanism.

## Callback props — security note

If the host passes a function-typed prop (e.g. an `onSubmit` callback
the attacker can invoke), the attacker can call it with **any
arguments**, including objects that throw on access. Host code
**must** treat callback arguments as untrusted JSON. The renderer does
not coerce them.

For event-style up-channels, prefer `on*` handlers on JSX produced by
the attacker — those receive `SafeEvent` facades that are already
defended.

## Coercion rules

`coerceToSafeVNode(value)` is the central defense. Given an arbitrary
value, it:

1. Passes primitives through unchanged.
2. Recurses arrays.
3. Verifies vnode shape: reads `value.constructor` defensively; if
   not `undefined`, drops the value.
4. Reads `value.type`, `value.props`, `value.key` once each, each in
   its own try/catch — getter throws abort the value, not the host
   render.
5. Coerces `type` by IDENTITY (not by flag):
   - String tags pass through (the secure renderer applies the
     allowlist).
   - The `Fragment` reference passes through.
   - The internal `OpaqueChild` reference passes through (so an
     attacker can position the host children they were handed).
   - Functions in the `confinedComponents` WeakSet (i.e. wrappers we
     minted via `confineComponent`) pass through, supporting nested
     confinement.
   - Anything else — including a function the attacker hand-flagged
     with `_isSecureExit`, `_isSecureBoundary`, etc. — becomes
     `Fragment` so the children still render. This is a deliberate
     defense against forged trust gates.
6. Coerces props:
   - Keys are read via `Object.keys` (falls back to
     `Reflect.ownKeys` filtered to strings if `Object.keys` throws).
   - Symbol-keyed props are dropped — Preact does not consume any
     Symbol-keyed prop, and skipping them prevents accessor getters
     from firing during commit.
   - Names in `DROPPED_PROPS_ALWAYS` (`ref`) are skipped on every
     vnode. The secure layer also strips `vnode.ref`, but when the
     attacker hand-builds a vnode (instead of calling `h()`), `ref`
     lives in `props` and would otherwise be re-emitted onto
     `vnode.ref` by `h()`.
   - All other DOM-specific filtering (`innerHTML`, `srcdoc`, the
     `HTMLHyperlinkElementUtils` URL-component setters,
     case-variant `OnError`, `attributionSrc`, `inert`, every
     unknown attribute name a future browser might ship, …) is
     handled DOWNSTREAM in `preact/secure`'s allow-by-default
     `DEFAULT_SAFE_ATTRS` filter. Mounting `confineComponent`
     WITHOUT `secureRender` on top is unsupported — see "Required
     environment" above.
   - `style` (when an object) is replaced with a shallow data-only
     copy. Accessor properties are dropped, so getters cannot fire
     side effects while Preact iterates the style to apply it.
   - `children` is split out and recursively coerced.
   - All other prop values are forwarded as-is.

Anything that survives is built into a fresh vnode via our own `h()`;
the attacker's original object is discarded.

## Using the coercer without `secureRender`

A confined component mounted with plain `preact.render` (not
`secureRender`) gets a meaningful subset of the protections:

- the attacker function is still called via `Reflect.apply(fn,
  undefined, [endowments, props])`, so `this === undefined`;
- the endowments bundle and the props bag are still frozen;
- the return value is still coerced — fake vnodes, Proxies, plain
  objects, and Promises are dropped;
- `key` is preserved; `ref` is silently dropped because the coercer
  never reads it.

But the surrounding `preact/secure` layer is off, so the following
are NOT in force when the host skips `secureRender`:

- URL-scheme checks (`javascript:` URLs reach the DOM).
- The disallowed-tag allowlist (`<script>`, `<iframe>`, etc. render).
- `dangerouslySetInnerHTML` is not stripped.
- Event handlers receive raw DOM `Event` objects, not `SafeEvent`.

The expected mounting pattern is `secureRender(h(Confined, …), root)`.
The standalone coercer is a useful belt-and-braces — it's how the
compartment layer defends if, for example, a future host code path
ever stops going through `secureRender` for some subtree.

## What's NOT in this module

- Ambient-authority hardening (network exfil via `<img>`, inline
  `style` URL fetches, `<a target=_blank>`, `<a ping>`, `<form
  action>`). See `preact/secure`'s README for the matrix and
  recommended mitigations (a Content Security Policy is the usual
  answer).
- Deep coercion of non-`style` object props.
- Throttling or DoS budgets — an attacker that schedules infinite
  state updates can still loop the diff scheduler. Preact's
  per-render 25-iter cap helps but is per-render, not cumulative.
- Lifecycle observability beyond `onError`. The host learns about a
  confined render only by what it sees in its props bag.
