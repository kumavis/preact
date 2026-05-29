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

```js
import 'ses';
lockdown();

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

- the sentinel's vnode props carry only a frozen empty marker, not
  the host vnode itself;
- the host vnode is held in a closure-bound `WeakMap` keyed by the
  marker, which the attacker has no path to.

When a sentinel mounts, it routes the original host vnode through a
`SecureExit` boundary. Sanitization turns off for that subtree — host
refs work, host event handlers fire with real DOM events, etc. The
host trusts its own subtree.

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
5. Coerces `type`:
   - String tags pass through (the secure renderer applies the
     allowlist).
   - `Fragment`, `SecureExit`, `SecureBoundary`, `OpaqueChild`, and
     any other `confineComponent`-wrapped function are accepted as
     component types.
   - Anything else becomes `Fragment` so children still render.
6. Coerces props:
   - Keys are read via `Object.keys` (falls back to
     `Reflect.ownKeys` filtered to strings if `Object.keys` throws).
   - Symbol-keyed props are dropped — Preact does not consume any
     Symbol-keyed prop, and skipping them prevents accessor getters
     from firing during commit.
   - `style` (when an object) is replaced with a shallow data-only
     copy. Accessor properties are dropped, so getters cannot fire
     side effects while Preact iterates the style to apply it.
   - `children` is split out and recursively coerced.
   - All other prop values are forwarded as-is.

Anything that survives is built into a fresh vnode via our own `h()`;
the attacker's original object is discarded.

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
