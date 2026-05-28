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

	const safeType = coerceType(type);
	const { children, rest } = coerceProps(props);
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
	let keys;
	try {
		keys = Object.keys(props);
	} catch (_) {
		return { rest, children };
	}
	for (let i = 0; i < keys.length; i++) {
		const key = keys[i];
		// `children` is special: split out so we can recursively coerce
		// and forward as positional `h()` arguments. Anything else is
		// shallowly copied — the secure renderer is the layer that
		// strips refs, URL schemes, etc. Deep structural sanitization of
		// non-children prop values is intentionally out of scope here.
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
		rest[key] = value;
	}
	return { rest, children };
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
 * @param {{ name?: string }} [opts]
 *   Optional metadata. `name` shows up in devtools.
 * @returns {import('preact').FunctionComponent}
 */
export function confineComponent(fn, opts) {
	if (typeof fn !== 'function') {
		throw new TypeError('confineComponent: expected a function');
	}
	const displayName =
		(opts && typeof opts.name === 'string' && opts.name) || 'Confined';

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
		} catch (_) {
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
