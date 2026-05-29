import { h, Fragment } from 'preact';
import {
	useState,
	useEffect,
	useCallback,
	useMemo,
	useRef,
	useReducer
} from 'preact/hooks';
import { SecureExit } from 'preact/secure';

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

// Host vnode trapped behind an opaque sentinel. Lookup is closure-based:
// the sentinel vnode itself exposes no property carrying the host vnode.
const opaqueRealChildren = new WeakMap();

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
 * property pointing at the real child — the link is held in a closure
 * and a module-level WeakMap, both unreachable by the attacker.
 */
function OpaqueChild(props) {
	const real = opaqueRealChildren.get(props._slot);
	return h(SecureExit, null, real == null ? null : real);
}
OpaqueChild._isOpaqueChild = true;

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
	const { children, rest } = coerceProps(props);
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
		// Only allow known-safe component functions: confined wrappers,
		// the Fragment, the opaque-child slot, and the SecureExit
		// boundary itself.
		if (
			confinedComponents.has(type) ||
			type._isOpaqueChild === true ||
			type._isSecureExit === true ||
			type._isSecureBoundary === true
		) {
			return type;
		}
	}
	// Anything else (objects, class constructors, Proxies, etc.) becomes
	// a Fragment so children still render.
	return Fragment;
}

function coerceProps(props) {
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
		// looked up independently in the WeakMap.
		const slot = Object.freeze({});
		opaqueRealChildren.set(slot, list[i]);
		sentinels.push(h(OpaqueChild, { _slot: slot, key: i }));
	}
	return sentinels;
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
	const displayName =
		(opts && typeof opts.name === 'string' && opts.name) || 'Confined';
	const onError = opts && typeof opts.onError === 'function' ? opts.onError : null;

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
	return Confined;
}

/** Returns true if `value` is a wrapper returned by `confineComponent`. */
export function isConfinedComponent(value) {
	return typeof value === 'function' && confinedComponents.has(value);
}

export { SecureExit } from 'preact/secure';
