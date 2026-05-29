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

const BLOCKED_PROPS = new Set(['dangerouslySetInnerHTML', 'is', 'srcdoc']);

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
SecureBoundary._isSecureBoundary = true;

/**
 * Inverse of `SecureBoundary`: anything rendered below this component is
 * treated as host-trusted and is NOT sanitized. Used by add-on layers
 * (e.g. `preact/compartment`) to splice host-controlled vnodes back into
 * an otherwise-confined tree.
 */
export function SecureExit(props) {
	return props.children;
}
SecureExit._isSecureExit = true;

let installed = false;

// How deep we are inside a SecureBoundary's render call(s). When > 0,
// every newly created vnode is sanitized.
let secureRenderDepth = 0;

// How deep we are inside a SecureExit's render call(s). When > 0, the
// sanitizer no-ops and `_secureCtx` does not propagate, so descendants
// render as ordinary host content.
let trustedExitDepth = 0;

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
			sanitizeVNode(vnode);
		}
		if (previousVnode) previousVnode(vnode);
	};

	options._render = vnode => {
		// SecureExit boundary: enter a trusted island, suppress secure
		// bookkeeping for the subtree. This branch wins even when nested
		// inside a secure tree — the whole point is to opt out.
		if (vnode.type && vnode.type._isSecureExit === true) {
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
			((vnode.type && vnode.type._isSecureBoundary === true) ||
				(vnode._parent && vnode._parent._secureCtx === true) ||
				secureRenderDepth > 0)
		) {
			vnode._secureCtx = true;
			vnode._secureBracketed = true;
			secureRenderDepth++;
		}
		if (previousRender) previousRender(vnode);
	};

	options.diffed = vnode => {
		if (vnode._secureBracketed) {
			vnode._secureBracketed = false;
			secureRenderDepth--;
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
			}
			if (vnode._trustedExitBracketed) {
				vnode._trustedExitBracketed = false;
				trustedExitDepth--;
			}
		}
		return previousCatchError(error, vnode, oldVNode, errorInfo);
	};
}

function sanitizeVNode(vnode) {
	if (vnode.ref) vnode.ref = null;

	const props = vnode.props;
	if (!props || typeof props !== 'object') return;

	if ('ref' in props) delete props.ref;

	for (const key of BLOCKED_PROPS) {
		if (key in props) delete props[key];
	}

	if (typeof vnode.type === 'string') {
		const tag = vnode.type.toLowerCase();
		if (!activeAllowedTags.has(tag)) {
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

let activeAllowedTags = DEFAULT_ALLOWED_TAGS;

/**
 * Recursively sanitize a vnode tree. Used for the input tree handed to
 * `secureRender` (those vnodes were already created before the depth-
 * based hook could see them). State-driven re-renders inside the secure
 * tree are covered by the options.vnode hook.
 */
function walkSanitize(node) {
	if (Array.isArray(node)) {
		for (let i = 0; i < node.length; i++) walkSanitize(node[i]);
		return;
	}
	if (!node || typeof node !== 'object' || node.constructor !== undefined) {
		return;
	}
	sanitizeVNode(node);
	// Stop descending if the type advertises that it manages its own
	// children's sanitization (e.g. `confineComponent`, which routes
	// children through opaque sentinels). Without this halt, host
	// children destined for opaque slots would be stripped of refs etc.
	// before they ever reach the SecureExit island.
	if (node.type && node.type._haltSanitizeChildren === true) return;
	const children = node.props && node.props.children;
	if (children != null) walkSanitize(children);
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
	if (opts && opts.allowedTags) {
		activeAllowedTags = new Set(
			Array.from(opts.allowedTags, tag => String(tag).toLowerCase())
		);
	} else {
		activeAllowedTags = DEFAULT_ALLOWED_TAGS;
	}
	install();
	walkSanitize(vnode);
	preactRender(h(SecureBoundary, null, vnode), parentDom);
}

/** Tear down a secure tree. */
export function unmount(parentDom) {
	preactRender(null, parentDom);
}

export { h, Fragment, createElement } from 'preact';
