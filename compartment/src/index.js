import { h, Fragment, options } from 'preact';
import {
	useState,
	useEffect,
	useCallback,
	useMemo,
	useRef,
	useReducer
} from 'preact/hooks';
import {
	SecureExit,
	_registerTrustedExitType,
	_registerSecureReentryType
} from 'preact/secure';

/**
 * `preact/compartment` — mount untrusted component code inside a Preact
 * tree.
 *
 * Threat model: the host hands us a function the host already evaluated
 * in a SES Compartment (we never call `new Compartment` ourselves — we
 * stay SES-agnostic). That function can return any JavaScript value as
 * its render result. Our job is to defend the seam between the
 * attacker-supplied function and the live DOM.
 *
 * The wrapper this module returns is a normal Preact function component.
 * Mount it inside a `secureRender` tree to get full sanitization on top.
 */

// Set of every confined-component wrapper we have minted. Used by the
// coercer to decide whether an attacker-returned `vnode.type` is allowed
// to be a function (it must be another confined component).
const confinedComponents = new WeakSet();

// Prop names the coercer drops on EVERY vnode (regardless of whether
// `secureRender` is on top, and regardless of whether the vnode is a
// DOM element or a function component). Today this is just `ref` —
// `h()` extracts `ref` off props onto `vnode.ref`, and the secure
// layer's sanitizer strips it again, but when the attacker hand-builds
// a vnode (`{ type:'div', constructor: undefined, props:{ ref: fn }}`)
// without going through `h()`, the only defense is dropping `ref`
// here in the coercer.
//
// `key` is intentionally not in this list because the coercer reads
// it from the vnode directly and re-emits it via `rest.key`; the
// attacker putting `key` in `props` is harmless (vnode-level wins).
const DROPPED_PROPS_ALWAYS = new Set(['ref']);

// Prop names the coercer drops only when the vnode renders as a DOM
// element. These are all reachable through Preact's `name in dom`
// setter path in `src/diff/props.js`. Function components can
// legitimately receive a prop named `text` (etc.); blocking it on
// every vnode would clobber innocent uses. The mirror list in
// `secure/src/index.js` `BLOCKED_PROPS` has the same scoping rule.
const DROPPED_PROPS_DOM = new Set([
	'dangerouslySetInnerHTML',
	'is',
	'srcdoc',
	'innerHTML',
	'outerHTML',
	'textContent',
	'innerText',
	'nodeValue',
	// HTMLHyperlinkElementUtils URL-component setters — see the
	// `BLOCKED_PROPS` doc comment in `secure/src/index.js` for the
	// phishing primitive these neutralize.
	'hostname',
	'host',
	'port',
	'protocol',
	'pathname',
	'search',
	'hash',
	'username',
	'password',
	'text',
	'attributionSrc',
	'inert'
]);

// Per-render opaque-slot map. `currentSlotMap` points at the slot map of
// the confined component currently rendering (or whose subtree is
// currently diffing). It's bracketed by our `options._render` /
// `options.diffed` hooks; when the diff for a confined component finishes
// we `.clear()` the map AND drop the reference, so a slot the attacker
// stashed in their own state (across renders or compartments) becomes
// useless — the host vnode it once pointed to is no longer reachable.
//
// IMPORTANT: this replaces a previous module-global `WeakMap` that allowed
// an attacker who stashed (OpaqueChild type, slot) from tenant A to
// resurrect tenant A's host vnode inside tenant B's tree. See the
// `cross-mount slot reuse` test for the regression.
let currentSlotMap = null;
const slotMapStack = [];

function pushSlotMap() {
	slotMapStack.push(currentSlotMap);
	currentSlotMap = new Map();
}

function popSlotMap() {
	if (currentSlotMap) currentSlotMap.clear();
	currentSlotMap = slotMapStack.length > 0 ? slotMapStack.pop() : null;
}

/**
 * Frozen bundle of utilities handed to the attacker function as its
 * first argument. These are the ONLY tools we provide; the attacker can
 * use them but is not required to — they may build vnode-shaped objects
 * by hand. The coercer below treats both paths identically.
 */
const endowments = Object.freeze({
	h,
	Fragment,
	useState,
	useEffect,
	useCallback,
	useMemo,
	useRef,
	useReducer
});

/**
 * Component placed inline by `Confined` to mark a slot where one of the
 * host's children should render. The sentinel's vnode carries no own
 * property pointing at the real child — the link is held in a per-render
 * `currentSlotMap` keyed by the slot object, unreachable by the
 * attacker.
 *
 * `OpaqueChild` itself is registered as a trusted-exit boundary with
 * `preact/secure` (see `install()`), so the host vnode it returns
 * renders without sanitization. Crucially: we return the host vnode
 * DIRECTLY, not wrapped in `<SecureExit>`. Returning a vnode with
 * `type: SecureExit` would let the attacker read `.type` off our
 * output and obtain a reference to `SecureExit` they could re-use to
 * smuggle other content into trusted-exit mode.
 */
function OpaqueChild(props) {
	const real = currentSlotMap && currentSlotMap.get(props._slot);
	return real == null ? null : real;
}

/**
 * Walk an arbitrary value returned by the attacker and re-create it
 * using vnode primitives we control. Anything that doesn't match a
 * known shape is dropped (returned as `null`). This is the critical
 * defensive coercion step: even if the attacker returns a Proxy, a
 * vnode-shaped object with getters, or a custom-prototype "fake vnode",
 * we read it once and rebuild via our own `h()`, throwing away the
 * original.
 */
function coerceToSafeVNode(value) {
	if (value == null || typeof value === 'boolean') return null;
	const t = typeof value;
	if (t === 'string' || t === 'number' || t === 'bigint') return value;
	if (Array.isArray(value)) {
		const out = [];
		for (let i = 0; i < value.length; i++) {
			out.push(coerceToSafeVNode(value[i]));
		}
		return out;
	}
	if (t !== 'object') return null;

	// Preact tags real vnodes with `constructor === undefined` (see
	// `src/create-element.js` — `UNDEFINED` is set as the constructor on
	// every vnode literal). Anything else is not a vnode.
	let ctor;
	try {
		ctor = value.constructor;
	} catch (_) {
		return null;
	}
	if (ctor !== undefined) return null;

	// Read each field defensively: the attacker may have installed
	// getters that throw or that return varying values per read.
	let type;
	let props;
	let key;
	try {
		type = value.type;
	} catch (_) {
		return null;
	}
	try {
		props = value.props;
	} catch (_) {
		return null;
	}
	try {
		// `key` lives on the vnode itself, not in `props`. Preserve it so
		// the attacker's keyed lists reconcile correctly (and so host
		// children we re-wrap with `key: i` keep stable identity across
		// re-renders even when the attacker reorders them).
		key = value.key;
	} catch (_) {
		key = undefined;
	}
	// `ref` is intentionally NOT read. Even though the secure renderer
	// strips refs in its sanitize pass, the coercer drops them here too
	// so behavior is correct if the compartment is ever mounted without
	// `secureRender` on top (e.g. a unit test).

	const safeType = coerceType(type);
	// Only apply the dangerous-prop deny list when the vnode is going to
	// mount as a DOM element (string-tagged). Function components can
	// legitimately receive a prop named `text` (etc.); blocking it on
	// every vnode would clobber attacker-to-attacker or host-to-attacker
	// prop passing for innocent prop names. Defense remains complete
	// because every DOM element ultimately renders through a
	// string-tagged vnode.
	const dropDom = typeof safeType === 'string';
	const { children, rest } = coerceProps(props, dropDom);
	// Surface the key via props so `h()` picks it up — `h` extracts `key`
	// from props before forwarding to `createVNode`.
	if (key != null) rest.key = key;
	return h(safeType, rest, ...children);
}

function coerceType(type) {
	if (type === Fragment) return Fragment;
	if (typeof type === 'string') {
		// String tags are passed through; the secure renderer applies the
		// allowlist and replaces disallowed tags with Fragment. We do the
		// same fallback here for the case where the compartment is used
		// outside `secureRender` (e.g. a test).
		return type;
	}
	if (typeof type === 'function') {
		// Identity-based allowlist of attacker-usable component types.
		// We deliberately do NOT trust `_isOpaqueChild` / `_isSecureExit`
		// / `_isSecureBoundary` flags — an attacker can set those on
		// their own function and pass through this gate (the documented
		// CVE class from the original release). Identity is checked
		// against the actual `OpaqueChild` reference and the
		// `confinedComponents` WeakSet of wrappers we minted.
		//
		// SecureExit and SecureBoundary are deliberately NOT in this
		// allowlist — the attacker has no legitimate path to obtain
		// either reference (SecureExit is no longer exposed via
		// OpaqueChild's render output; SecureBoundary is module-private
		// to secure). Trusted-exit semantics arrive through `OpaqueChild`
		// itself, which is registered with secure as a trusted-exit type.
		if (confinedComponents.has(type) || type === OpaqueChild) {
			return type;
		}
	}
	// Anything else (objects, class constructors, Proxies, etc.) becomes
	// a Fragment so children still render.
	return Fragment;
}

/**
 * @param props      The attacker-returned vnode's props object.
 * @param dropDom    True when the resulting vnode will render as a DOM
 *                   element (string-tagged). DOM-specific dangerous
 *                   prop names are dropped only in that case;
 *                   function components can receive arbitrary prop
 *                   names so we don't clobber innocent uses like
 *                   `text` on a host or attacker component.
 */
function coerceProps(props, dropDom) {
	const rest = {};
	const children = [];
	if (props == null || typeof props !== 'object') {
		return { rest, children };
	}
	// Use Reflect.ownKeys so a Proxy that throws on Object.keys can still
	// be handled (we wrap each read in try/catch below). Symbols are
	// skipped because every meaningful Preact prop is string-keyed and
	// a symbol-keyed getter could fire as a side effect during diff.
	let keys;
	try {
		keys = Object.keys(props);
	} catch (_) {
		try {
			keys = Reflect.ownKeys(props).filter(k => typeof k === 'string');
		} catch (__) {
			return { rest, children };
		}
	}
	for (let i = 0; i < keys.length; i++) {
		const key = keys[i];
		// Drop dangerous prop names. `ref` is always dropped; the DOM
		// writeables (innerHTML, hostname, …) only when this vnode will
		// mount as a DOM element. See the constant comments above.
		if (DROPPED_PROPS_ALWAYS.has(key)) continue;
		if (dropDom && DROPPED_PROPS_DOM.has(key)) continue;
		// `children` is special: split out so we can recursively coerce
		// and forward as positional `h()` arguments.
		let value;
		try {
			value = props[key];
		} catch (_) {
			continue;
		}
		if (key === 'children') {
			const coerced = coerceToSafeVNode(value);
			if (Array.isArray(coerced)) {
				for (let j = 0; j < coerced.length; j++) children.push(coerced[j]);
			} else if (coerced != null) {
				children.push(coerced);
			}
			continue;
		}
		// `style` is read by Preact's commit phase via `for (name in value)`
		// and `value[name]` — if the attacker installs a getter that has
		// side effects, those getters fire while we're applying the DOM.
		// Defensive shallow copy reads each own data property once via a
		// descriptor and drops accessors, neutering the getter trick.
		if (key === 'style' && value !== null && typeof value === 'object') {
			rest[key] = shallowDataCopy(value);
			continue;
		}
		rest[key] = value;
	}
	return { rest, children };
}

/**
 * Shallow copy that reads own data properties only — accessors are
 * dropped, so getters never fire during the secure renderer's commit
 * phase. Used for prop values like `style` that Preact iterates and
 * reads in-place when applying to the DOM.
 */
function shallowDataCopy(obj) {
	const out = {};
	let keys;
	try {
		keys = Object.keys(obj);
	} catch (_) {
		return out;
	}
	for (let i = 0; i < keys.length; i++) {
		const k = keys[i];
		let desc;
		try {
			desc = Object.getOwnPropertyDescriptor(obj, k);
		} catch (_) {
			continue;
		}
		if (desc && 'value' in desc) {
			const v = desc.value;
			// Only carry primitives — nested objects could themselves hide
			// accessors. Functions are kept (some style libraries embed
			// units as templates, but for `style` we want strings/numbers).
			const t = typeof v;
			if (
				v === null ||
				t === 'string' ||
				t === 'number' ||
				t === 'boolean' ||
				t === 'bigint'
			) {
				out[k] = v;
			}
		}
	}
	return out;
}

/**
 * Replace each host child in `children` with an opaque sentinel.
 * Returns the sentinel array (or `undefined` if the host passed no
 * children) plus a teardown function the wrapper component can run
 * once it unmounts.
 */
function wrapOpaqueChildren(children) {
	if (children == null) return undefined;
	const list = Array.isArray(children) ? children : [children];
	const sentinels = [];
	for (let i = 0; i < list.length; i++) {
		// Each slot is a unique object so multiple host children can be
		// looked up independently. The slot is registered into the
		// CURRENT confined component's slot map (set up by the
		// `options._render` hook below). When that render's diff
		// completes (`options.diffed`), the map is `.clear()`-ed and
		// dropped — slots the attacker stashed in their own state
		// become useless.
		const slot = Object.freeze({});
		if (currentSlotMap) currentSlotMap.set(slot, list[i]);
		sentinels.push(h(OpaqueChild, { _slot: slot, key: i }));
	}
	return sentinels;
}

// Best-effort detection of SES `lockdown()`. SES exposes `harden` on
// `globalThis` and freezes `Function.prototype.constructor` so the
// attacker cannot escape via `endowments.h.constructor('return
// globalThis')()`. Without lockdown, every function we hand to the
// attacker exposes the realm's `Function` via its `.constructor`
// chain and the sandbox is essentially decorative.
function sesAppearsActive() {
	return (
		typeof globalThis !== 'undefined' && typeof globalThis.harden === 'function'
	);
}

let warnedNoSes = false;
function warnIfNoSes() {
	if (warnedNoSes || sesAppearsActive()) return;
	warnedNoSes = true;
	// eslint-disable-next-line no-console
	if (typeof console !== 'undefined' && console.warn) {
		console.warn(
			'preact/compartment: SES `lockdown()` was not detected. The ' +
				"sandbox's endowments expose `Function` via their " +
				'`.constructor` chain, so an attacker in the compartment ' +
				'can reach the host realm via `endowments.h.constructor' +
				'("return globalThis")()`. Call `lockdown({ overrideTaming: ' +
				'"severe" })` BEFORE constructing any Compartment.'
		);
	}
}

let installed = false;
function install() {
	if (installed) return;
	installed = true;

	warnIfNoSes();

	// Tell `preact/secure` that `OpaqueChild` is a trusted-exit
	// boundary. The secure renderer will bracket `trustedExitDepth`
	// around its diff so the host child it returns renders without
	// sanitization — refs work, raw events fire, etc. — restoring the
	// behavior the previous code achieved by wrapping in `<SecureExit>`.
	_registerTrustedExitType(OpaqueChild);

	const previousRender = options._render;
	const previousDiffed = options.diffed;
	const previousCatchError = options._catchError;

	options._render = vnode => {
		// Idempotent — `_render` may fire multiple times for the same
		// vnode when the component calls setState synchronously during
		// render (Preact's do-while loop in `src/diff/index.js`). The
		// flag guard means we only push once per vnode lifecycle; the
		// matching `diffed` (or `_catchError`) pops once.
		if (
			vnode.type &&
			confinedComponents.has(vnode.type) &&
			!vnode._slotMapBracketed
		) {
			vnode._slotMapBracketed = true;
			pushSlotMap();
		}
		if (previousRender) previousRender(vnode);
	};

	options.diffed = vnode => {
		if (vnode._slotMapBracketed) {
			vnode._slotMapBracketed = false;
			popSlotMap();
		}
		if (previousDiffed) previousDiffed(vnode);
	};

	// On an unhandled render exception, `options.diffed` doesn't fire
	// — clean up the slot-map bracket here so the next render starts
	// from a balanced state.
	options._catchError = (error, vnode, oldVNode, errorInfo) => {
		if (vnode && vnode._slotMapBracketed) {
			vnode._slotMapBracketed = false;
			popSlotMap();
		}
		if (previousCatchError) {
			return previousCatchError(error, vnode, oldVNode, errorInfo);
		}
		throw error;
	};
}

/**
 * Wrap an attacker-supplied component function so it can be mounted in
 * a normal Preact tree.
 *
 * @param {(endowments: object, props: object) => unknown} fn
 *   The untrusted function. Must accept `(endowments, props)`. May
 *   return any value; the wrapper coerces it.
 * @param {{ name?: string, onError?: (err: unknown) => void }} [opts]
 *   `name` is a display name for devtools. `onError`, if provided, is
 *   called whenever the attacker function throws — useful for
 *   telemetry. It is invoked with the thrown value; any exception it
 *   throws is swallowed so a misbehaving telemetry hook cannot itself
 *   crash the host render.
 * @returns {import('preact').FunctionComponent}
 */
export function confineComponent(fn, opts) {
	if (typeof fn !== 'function') {
		throw new TypeError('confineComponent: expected a function');
	}
	install();
	const displayName =
		(opts && typeof opts.name === 'string' && opts.name) || 'Confined';
	const onError =
		opts && typeof opts.onError === 'function' ? opts.onError : null;

	function Confined(rawProps) {
		// Split host children off and replace with opaque sentinels.
		const { children: rawChildren, ...rest } = rawProps;
		const opaqueChildren = wrapOpaqueChildren(rawChildren);
		const sanitizedProps = Object.freeze({
			...rest,
			children: opaqueChildren
		});

		let result;
		try {
			result = Reflect.apply(fn, undefined, [endowments, sanitizedProps]);
		} catch (err) {
			if (onError) {
				try {
					onError(err);
				} catch (_) {
					// telemetry hook must not break the host render
				}
			}
			return null;
		}
		return coerceToSafeVNode(result);
	}
	Confined.displayName = displayName;
	// Tell `preact/secure`'s entry-tree walk not to descend into our
	// children: those vnodes are host-trusted content that we route
	// through opaque sentinels and `SecureExit` islands at render time.
	Confined._haltSanitizeChildren = true;
	confinedComponents.add(Confined);
	// Register as a secure-reentry boundary so that an attacker confined
	// inside a `<SecureExit>` island still has its output sanitized.
	// Without this, `<SecureExit><Confined/></SecureExit>` would let the
	// attacker render `<script>` and arbitrary JS.
	_registerSecureReentryType(Confined);
	return Confined;
}

/** Returns true if `value` is a wrapper returned by `confineComponent`. */
export function isConfinedComponent(value) {
	return typeof value === 'function' && confinedComponents.has(value);
}

export { SecureExit } from 'preact/secure';
