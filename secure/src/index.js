import { render as preactRender, Fragment, options, h } from 'preact';

/**
 * Secure renderer for Preact.
 *
 * Threat model: a component author is untrusted. They may render JSX,
 * receive props from the host, manage their own state, and register
 * event listeners. They must not be able to obtain a reference to any
 * DOM node, the real DOM `Event` object, or perform HTML injection.
 *
 * The renderer wraps the user's tree in a SecureBoundary. While Preact
 * is rendering anything inside that boundary, freshly created vnodes
 * are sanitized: refs are stripped, dangerous props are removed,
 * disallowed tags are replaced with Fragments, URLs are scheme-checked,
 * and event listeners are wrapped so they only ever see SafeEvent
 * facades.
 *
 * Sanitization is scoped: vnodes outside any SecureBoundary are
 * untouched, so the host application can keep rendering normally.
 */

const DEFAULT_ALLOWED_TAGS = new Set([
	'a',
	'abbr',
	'address',
	'article',
	'aside',
	'b',
	'bdi',
	'bdo',
	'blockquote',
	'br',
	'button',
	'caption',
	'cite',
	'code',
	'col',
	'colgroup',
	'data',
	'datalist',
	'dd',
	'del',
	'details',
	'dfn',
	'dialog',
	'div',
	'dl',
	'dt',
	'em',
	'fieldset',
	'figcaption',
	'figure',
	'footer',
	'form',
	'h1',
	'h2',
	'h3',
	'h4',
	'h5',
	'h6',
	'header',
	'hgroup',
	'hr',
	'i',
	'img',
	'input',
	'ins',
	'kbd',
	'label',
	'legend',
	'li',
	'main',
	'mark',
	'menu',
	'meter',
	'nav',
	'ol',
	'optgroup',
	'option',
	'output',
	'p',
	'picture',
	'pre',
	'progress',
	'q',
	'rp',
	'rt',
	'ruby',
	's',
	'samp',
	'section',
	'select',
	'small',
	'source',
	'span',
	'strong',
	'sub',
	'summary',
	'sup',
	'table',
	'tbody',
	'td',
	'textarea',
	'tfoot',
	'th',
	'thead',
	'time',
	'tr',
	'track',
	'u',
	'ul',
	'var',
	'video',
	'audio',
	'wbr'
]);

const URL_ATTRS = new Set([
	'href',
	'src',
	'formaction',
	'action',
	'srcset',
	'poster',
	'cite',
	'data',
	'background',
	'ping',
	'xlinkHref',
	'xlink:href'
]);

// Props that must never reach Preact's prop-application path on a DOM
// element. Beyond the obvious HTML-injection vectors
// (`dangerouslySetInnerHTML`, `srcdoc`) and the custom-element registration
// vector (`is`), this set also covers the DOM-property writeables
// (`innerHTML`, `outerHTML`, `textContent`, `innerText`, `nodeValue`) that
// Preact's `setProperty` (`src/diff/props.js`) assigns via the `name in
// dom` setter path — without this entry, an attacker can return
// `h('div', { innerHTML: '<img onerror=…>' })` and trigger script
// execution.
const BLOCKED_PROPS = new Set([
	'dangerouslySetInnerHTML',
	'is',
	'srcdoc',
	'innerHTML',
	'outerHTML',
	'textContent',
	'innerText',
	'nodeValue'
]);

const SAFE_URL_RE = /^(?:https?:|mailto:|tel:|sms:|ftp:|\/|\.{0,2}\/|#|\?)/i;
const SAFE_DATA_IMG_RE =
	/^data:image\/(?:png|jpe?g|gif|webp|svg\+xml|bmp|x-icon|vnd\.microsoft\.icon);/i;

function sanitizeUrl(value, attr) {
	if (typeof value !== 'string') return null;
	const trimmed = value.replace(/^[\s\x00-\x1f]+/, '');
	if (SAFE_URL_RE.test(trimmed)) return value;
	if ((attr === 'src' || attr === 'poster') && SAFE_DATA_IMG_RE.test(trimmed)) {
		return value;
	}
	return null;
}

const KEY_PROPS = [
	'key',
	'code',
	'keyCode',
	'which',
	'charCode',
	'location',
	'repeat',
	'isComposing'
];
const MOD_PROPS = ['altKey', 'ctrlKey', 'metaKey', 'shiftKey'];
const MOUSE_PROPS = ['button', 'buttons'];
const COORD_PROPS = [
	'clientX',
	'clientY',
	'pageX',
	'pageY',
	'screenX',
	'screenY',
	'offsetX',
	'offsetY',
	'movementX',
	'movementY'
];
const POINTER_PROPS = [
	'pointerId',
	'pointerType',
	'isPrimary',
	'width',
	'height',
	'pressure',
	'tangentialPressure',
	'tiltX',
	'tiltY',
	'twist'
];
const WHEEL_PROPS = ['deltaX', 'deltaY', 'deltaZ', 'deltaMode'];

function copyKnown(src, names, dest) {
	for (let i = 0; i < names.length; i++) {
		const k = names[i];
		if (k in src) dest[k] = src[k];
	}
}

function safeTargetSnapshot(node) {
	if (!node || typeof node !== 'object') return null;
	const tagName =
		typeof node.tagName === 'string' ? node.tagName.toLowerCase() : null;
	const snapshot = {
		tagName,
		name: typeof node.name === 'string' ? node.name : null,
		id: typeof node.id === 'string' ? node.id : null,
		type: typeof node.type === 'string' ? node.type : null,
		value:
			'value' in node && typeof node.value !== 'object'
				? node.value
				: undefined,
		checked: 'checked' in node ? !!node.checked : undefined,
		selectedIndex: 'selectedIndex' in node ? node.selectedIndex : undefined
	};
	return Object.freeze(snapshot);
}

function makeSafeEvent(e) {
	const safe = {
		type: e.type,
		timeStamp: e.timeStamp,
		bubbles: !!e.bubbles,
		cancelable: !!e.cancelable,
		isTrusted: !!e.isTrusted,
		eventPhase: e.eventPhase,
		target: safeTargetSnapshot(e.target),
		currentTarget: safeTargetSnapshot(e.currentTarget),
		preventDefault() {
			e.preventDefault();
		},
		stopPropagation() {
			e.stopPropagation();
		},
		stopImmediatePropagation() {
			e.stopImmediatePropagation();
		}
	};
	copyKnown(e, KEY_PROPS, safe);
	copyKnown(e, MOD_PROPS, safe);
	copyKnown(e, MOUSE_PROPS, safe);
	copyKnown(e, COORD_PROPS, safe);
	copyKnown(e, POINTER_PROPS, safe);
	copyKnown(e, WHEEL_PROPS, safe);

	// `defaultPrevented` is live — handlers further along the bubble chain
	// will see the up-to-date value after a preventDefault() call.
	Object.defineProperty(safe, 'defaultPrevented', {
		enumerable: true,
		get() {
			return !!e.defaultPrevented;
		}
	});

	return Object.freeze(safe);
}

/**
 * Marker component placed at the root of every secure tree. Its presence
 * in a vnode's ancestry is what tells the diff hooks to sanitize.
 */
function SecureBoundary(props) {
	return props.children;
}
// SecureBoundary is module-private and is detected by identity in the
// `_render` hook; no flag is necessary, and exposing one would be a
// forge-able trust gate.

/**
 * Inverse of `SecureBoundary`: anything rendered below this component is
 * treated as host-trusted and is NOT sanitized. Used by add-on layers
 * (e.g. `preact/compartment`) to splice host-controlled vnodes back into
 * an otherwise-confined tree.
 */
export function SecureExit(props) {
	return props.children;
}

// Set of component types that act as trusted-exit boundaries. Membership
// is by IDENTITY, not by flag — an attacker who sets
// `myFn._isSecureExit = true` on their own function cannot enter the
// trusted-exit branch this way. Add-on layers (`preact/compartment`)
// register their own internal boundary types via `_registerTrustedExitType`.
const trustedExitTypes = new Set([SecureExit]);

/**
 * Register an additional function type as a trusted-exit boundary.
 * Intended for sibling addons (`preact/compartment`) — NOT to be
 * imported by attacker code. Calling this with an attacker-controlled
 * function would expose the trusted-exit branch.
 */
export function _registerTrustedExitType(fn) {
	if (typeof fn === 'function') trustedExitTypes.add(fn);
}

let installed = false;

// How deep we are inside a SecureBoundary's render call(s). When > 0,
// every newly created vnode is sanitized.
let secureRenderDepth = 0;

// How deep we are inside a SecureExit's render call(s). When > 0, the
// sanitizer no-ops and `_secureCtx` does not propagate, so descendants
// render as ordinary host content.
let trustedExitDepth = 0;

// Allowlist of the secure tree currently being rendered. Multiple
// secure trees can coexist with different allowlists; we keep the
// previous values on a stack and pop on diffed.
let currentAllowedTags = DEFAULT_ALLOWED_TAGS;
const allowedTagsStack = [];

function pushAllowedTags(next) {
	allowedTagsStack.push(currentAllowedTags);
	currentAllowedTags = next;
}

function popAllowedTags() {
	currentAllowedTags =
		allowedTagsStack.length > 0
			? allowedTagsStack.pop()
			: DEFAULT_ALLOWED_TAGS;
}

function install() {
	if (installed) return;
	installed = true;

	const previousVnode = options.vnode;
	const previousRender = options._render;
	const previousDiffed = options.diffed;
	const previousCatchError = options._catchError;

	options.vnode = vnode => {
		// Sanitize when:
		//  - a parent or ancestor is currently rendering inside a secure
		//    tree (depth > 0)
		//  - this vnode is a clone of a previously-secure vnode (the
		//    `_secureCtx` flag survived the renderComponent clone)
		//  - this vnode's `_parent` already carries the secure marker
		//    (for vnodes coerced during diffChildren)
		// Skipped entirely if we are inside a SecureExit island.
		if (
			trustedExitDepth === 0 &&
			(secureRenderDepth > 0 ||
				vnode._secureCtx === true ||
				(vnode._parent && vnode._parent._secureCtx === true))
		) {
			vnode._secureCtx = true;
			// Resolve allowlist: prefer the one cached on the vnode (clone
			// from a re-render), then the parent's, then the active stack
			// top. This keeps multiple secure trees with different
			// allowlists from stepping on each other when their renders
			// interleave via setState.
			const tags =
				vnode._secureAllowedTags ||
				(vnode._parent && vnode._parent._secureAllowedTags) ||
				currentAllowedTags;
			vnode._secureAllowedTags = tags;
			sanitizeVNode(vnode, tags);
		}
		if (previousVnode) previousVnode(vnode);
	};

	options._render = vnode => {
		// Trusted-exit boundary: enter a trusted island, suppress secure
		// bookkeeping for the subtree. Membership is by IDENTITY against
		// `trustedExitTypes`, NOT by a `._isSecureExit` flag — an
		// attacker who sets that flag on their own function cannot
		// enter this branch.
		if (vnode.type && trustedExitTypes.has(vnode.type)) {
			vnode._trustedExitBracketed = true;
			trustedExitDepth++;
		} else if (
			trustedExitDepth === 0 &&
			// We deliberately do NOT trust `vnode._secureCtx` on its own here.
			// That flag is set by our own hooks on real renders, so it's
			// safe today, but relying on the *parent* / boundary type alone
			// keeps the gate from getting opened by a pre-flagged vnode if
			// some future code path mounts a vnode without going through
			// the coercer.
			// Boundary detection is also identity-based: SecureBoundary
			// is module-private so attacker code has no way to obtain
			// the reference.
			(vnode.type === SecureBoundary ||
				(vnode._parent && vnode._parent._secureCtx === true) ||
				secureRenderDepth > 0)
		) {
			vnode._secureCtx = true;
			vnode._secureBracketed = true;
			// Resolve and push the allowlist for the duration of this
			// component's render. The boundary props carry the per-tree
			// allowlist; descendants inherit via their parent's cached
			// `_secureAllowedTags`, surviving renderComponent clones.
			let tags;
			if (vnode.type === SecureBoundary) {
				tags =
					(vnode.props && vnode.props._allowedTags) ||
					DEFAULT_ALLOWED_TAGS;
			} else {
				tags =
					vnode._secureAllowedTags ||
					(vnode._parent && vnode._parent._secureAllowedTags) ||
					currentAllowedTags;
			}
			vnode._secureAllowedTags = tags;
			pushAllowedTags(tags);
			secureRenderDepth++;
		}
		if (previousRender) previousRender(vnode);
	};

	options.diffed = vnode => {
		if (vnode._secureBracketed) {
			vnode._secureBracketed = false;
			secureRenderDepth--;
			popAllowedTags();
		}
		if (vnode._trustedExitBracketed) {
			vnode._trustedExitBracketed = false;
			trustedExitDepth--;
		}
		if (previousDiffed) previousDiffed(vnode);
	};

	// If a render throws and no error boundary catches it, `options.diffed`
	// never fires for the throwing vnode and our depth counter would
	// stay elevated — the next host render would then incorrectly be
	// treated as secure. Hook `options._catchError` to clean up the
	// brackets we stamped in `options._render` on the affected vnode.
	options._catchError = (error, vnode, oldVNode, errorInfo) => {
		if (vnode) {
			if (vnode._secureBracketed) {
				vnode._secureBracketed = false;
				secureRenderDepth--;
				popAllowedTags();
			}
			if (vnode._trustedExitBracketed) {
				vnode._trustedExitBracketed = false;
				trustedExitDepth--;
			}
		}
		// `options._catchError` is *usually* installed by preact itself
		// (default: `_catchError` from `./diff/catch-error`), but guard
		// in case a host has cleared it.
		if (previousCatchError) {
			return previousCatchError(error, vnode, oldVNode, errorInfo);
		}
		throw error;
	};
}

function sanitizeVNode(vnode, allowedTags) {
	if (vnode.ref) vnode.ref = null;

	const props = vnode.props;
	if (!props || typeof props !== 'object') return;

	if ('ref' in props) delete props.ref;

	for (const key of BLOCKED_PROPS) {
		if (key in props) delete props[key];
	}

	if (typeof vnode.type === 'string') {
		const tag = vnode.type.toLowerCase();
		if (!allowedTags.has(tag)) {
			vnode.type = Fragment;
			vnode.props = { children: props.children };
			return;
		}
		sanitizeElementProps(props);
	}
}

function sanitizeElementProps(props) {
	for (const key in props) {
		if (key === 'children') continue;
		const value = props[key];
		if (key.length > 2 && key[0] === 'o' && key[1] === 'n') {
			if (value == null) continue;
			if (typeof value !== 'function') {
				delete props[key];
				continue;
			}
			props[key] = wrapListener(value);
			continue;
		}
		if (URL_ATTRS.has(key)) {
			const sanitized = value == null ? value : sanitizeUrl(value, key);
			if (sanitized == null) {
				delete props[key];
			} else {
				props[key] = sanitized;
			}
		}
	}
}

const wrapped = new WeakMap();
function wrapListener(userFn) {
	let w = wrapped.get(userFn);
	if (w) return w;
	w = function (e) {
		const evt =
			e && typeof Event !== 'undefined' && e instanceof Event
				? makeSafeEvent(e)
				: e;
		return userFn(evt);
	};
	wrapped.set(userFn, w);
	return w;
}

/**
 * Recursively sanitize a vnode tree. Used for the input tree handed to
 * `secureRender` (those vnodes were already created before the depth-
 * based hook could see them). State-driven re-renders inside the secure
 * tree are covered by the options.vnode hook.
 */
function walkSanitize(node, allowedTags) {
	if (Array.isArray(node)) {
		for (let i = 0; i < node.length; i++) walkSanitize(node[i], allowedTags);
		return;
	}
	if (!node || typeof node !== 'object' || node.constructor !== undefined) {
		return;
	}
	sanitizeVNode(node, allowedTags);
	node._secureAllowedTags = allowedTags;
	// Stop descending if:
	//  - the type is a `SecureExit` (its subtree is explicitly trusted)
	//  - the type advertises that it manages its own children's
	//    sanitization (e.g. `confineComponent`, which routes children
	//    through opaque sentinels)
	// Without these halts, host content destined for trusted islands
	// would be stripped of refs etc. before it ever reaches the island.
	const type = node.type;
	if (
		type &&
		(trustedExitTypes.has(type) || type._haltSanitizeChildren === true)
	) {
		return;
	}
	const children = node.props && node.props.children;
	if (children != null) walkSanitize(children, allowedTags);
}

/**
 * Render a Preact vnode into a container while enforcing the secure
 * sandbox. Components in the tree never see DOM nodes or raw events.
 *
 * @param {*} vnode The vnode to render.
 * @param {Element} parentDom The host-controlled DOM container.
 * @param {{ allowedTags?: Iterable<string> }} [opts]
 */
export function secureRender(vnode, parentDom, opts) {
	const allowedTags =
		opts && opts.allowedTags
			? new Set(
					Array.from(opts.allowedTags, tag => String(tag).toLowerCase())
				)
			: DEFAULT_ALLOWED_TAGS;
	install();
	walkSanitize(vnode, allowedTags);
	// Stash the per-tree allowlist on the boundary so concurrent secure
	// trees with different allowlists can coexist. The `_allowedTags`
	// prop is picked up by `options._render` when the boundary mounts.
	preactRender(
		h(SecureBoundary, { _allowedTags: allowedTags }, vnode),
		parentDom
	);
}

/** Tear down a secure tree. */
export function unmount(parentDom) {
	preactRender(null, parentDom);
}

export { h, Fragment, createElement } from 'preact';
