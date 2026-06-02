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

// ALLOW-BY-DEFAULT attribute set. Any prop name not on this set, not
// `on*`, not `aria-*`, and not `data-*` is DROPPED on a DOM-element
// vnode. This is a structural defense: the previous denylist had to
// enumerate every dangerous setter (innerHTML, hostname, srcdoc,
// attributionSrc, …), and every round of review found something new
// that needed adding. An allowlist inverts the failure mode — the
// next dangerous setter the browser ships does not become exploitable
// the moment it lands; the host has to explicitly opt in.
//
// Entries stored LOWERCASE; lookup lowercases the prop key. Browsers
// normalize HTML attribute names to lowercase, so a case-variant like
// `INNERHTML` is also caught (it would otherwise fall through Preact's
// case-sensitive `name in dom` check, hit `setAttribute`, and land as
// canonical lowercase in the DOM).
//
// Conservative defaults — `form` (the input/button → form-by-id
// association attribute), `nonce`, `is`, and similar "magic" attrs are
// intentionally omitted. Hosts that need extras can pass an
// `allowedAttrs` option to `secureRender` to extend this set for one
// tree.
const DEFAULT_SAFE_ATTRS = new Set([
	// Global content attributes
	'id',
	'class',
	'classname',
	'title',
	'lang',
	'dir',
	'hidden',
	'tabindex',
	'role',
	'style',
	'accesskey',
	'draggable',
	'spellcheck',
	'translate',
	'autocapitalize',
	'autocorrect',
	'enterkeyhint',
	'inputmode',
	// Form controls
	'type',
	'name',
	'value',
	'placeholder',
	'disabled',
	'required',
	'readonly',
	'min',
	'max',
	'step',
	'pattern',
	'maxlength',
	'minlength',
	'size',
	'multiple',
	'accept',
	'checked',
	'selected',
	'for',
	'htmlfor',
	'autocomplete',
	'autofocus',
	// `form` attribute is INTENTIONALLY OMITTED — it associates an
	// `<input>`/`<button>` with a `<form id="...">` elsewhere in the
	// document, which would let an attacker submit fields they
	// authored as part of a host-owned form.
	// Form submission
	'enctype',
	'method',
	'novalidate',
	'acceptcharset',
	'formenctype',
	'formmethod',
	'formnovalidate',
	'formtarget',
	// Media / images
	'alt',
	'width',
	'height',
	'loading',
	'decoding',
	'crossorigin',
	'referrerpolicy',
	'controls',
	'autoplay',
	'loop',
	'muted',
	'preload',
	'playsinline',
	'controlslist',
	'disableremoteplayback',
	'disablepictureinpicture',
	'ismap',
	// Track
	'kind',
	'srclang',
	'label',
	'default',
	// Source / link / media
	'media',
	'sizes',
	// Tables
	'colspan',
	'rowspan',
	'headers',
	'scope',
	'abbr',
	'span',
	// Lists
	'start',
	'reversed',
	// Time / dialog / details / progress / meter
	'datetime',
	'open',
	'low',
	'high',
	'optimum',
	// Textarea
	'wrap',
	'cols',
	'rows',
	// Anchor / link
	'download',
	'target',
	'rel',
	'hreflang',
	// URL attributes (also in URL_ATTRS for value sanitization)
	'href',
	'src',
	'srcset',
	'poster',
	'formaction',
	'action',
	'cite',
	'ping',
	// Color input (and global)
	'color'
]);

// Subset of SAFE_ATTRS whose VALUES must be URL-sanitized. The
// allowlist gate above admits the prop name; this set gates the
// value. Lookup is lowercase (the gate already lowercases the key).
const URL_ATTRS = new Set([
	'href',
	'src',
	'srcset',
	'poster',
	'formaction',
	'action',
	'cite',
	'ping'
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

// Set of component types that RE-ENTER secure mode even when nested
// inside a trusted-exit subtree. `preact/compartment` registers each
// `Confined` wrapper here so that an attacker confined inside a
// host-trusted island still has its output sanitized — without this,
// `<SecureExit><Confined/></SecureExit>` would let the attacker
// render `<script>` and arbitrary JS with full DOM access.
const secureReentryTypes = new WeakSet();

/**
 * Register an additional function type as a SECURE-REENTRY boundary.
 * A vnode whose type is registered here will RESET `trustedExitDepth`
 * to zero for its subtree (saving the prior value on the vnode and
 * restoring it on diffed/catchError). Sibling addons like
 * `preact/compartment` register each `Confined` wrapper they mint so
 * that an attacker rendered inside a `SecureExit` island still has
 * its output sanitized.
 *
 * SECURITY: any module that calls this can promote a function to a
 * secure-reentry boundary; the consequence is just that the
 * function's vnode resets the trusted-exit counter, so this is much
 * less dangerous than `_registerTrustedExitType`. Still, treat as a
 * privileged extension point.
 */
export function _registerSecureReentryType(fn) {
	if (typeof fn !== 'function') return;
	// Mutual exclusion: registering the same function in both sets
	// would let setState-in-render iterate `_render` such that the
	// first iteration takes the secure-reentry branch (sets
	// `_secureBracketed`) and the second takes the trusted-exit
	// branch (sets `_trustedExitBracketed`), at which point the
	// second iteration's render runs with `trustedExitDepth > 0` and
	// sanitization off. Throwing prevents the dual-registration foot-
	// gun outright.
	if (trustedExitTypes.has(fn)) {
		throw new Error(
			'preact/secure: cannot register a function as both a ' +
				'trusted-exit type and a secure-reentry type.'
		);
	}
	secureReentryTypes.add(fn);
}

/**
 * Register an additional function type as a trusted-exit boundary.
 * Intended for sibling addons (`preact/compartment`) — NOT to be
 * imported by attacker code. Calling this with an attacker-controlled
 * function would expose the trusted-exit branch.
 */
export function _registerTrustedExitType(fn) {
	if (typeof fn !== 'function') return;
	if (secureReentryTypes.has(fn)) {
		throw new Error(
			'preact/secure: cannot register a function as both a ' +
				'trusted-exit type and a secure-reentry type.'
		);
	}
	trustedExitTypes.add(fn);
}

let installed = false;

// How deep we are inside a SecureBoundary's render call(s). When > 0,
// every newly created vnode is sanitized.
let secureRenderDepth = 0;

// How deep we are inside a SecureExit's render call(s). When > 0, the
// sanitizer no-ops and `_secureCtx` does not propagate, so descendants
// render as ordinary host content.
let trustedExitDepth = 0;

// Allowlists for the secure tree currently being rendered. Multiple
// secure trees can coexist with different allowlists; we keep the
// previous values on a stack and pop on diffed/catchError. Tags and
// attrs share a single stack — they always push/pop together, and
// any divergence would mean a bracket-cleanup bug.
let currentAllowedTags = DEFAULT_ALLOWED_TAGS;
let currentSafeAttrs = DEFAULT_SAFE_ATTRS;
const allowedTagsStack = [];
const safeAttrsStack = [];

function pushAllowed(nextTags, nextAttrs) {
	allowedTagsStack.push(currentAllowedTags);
	safeAttrsStack.push(currentSafeAttrs);
	currentAllowedTags = nextTags;
	currentSafeAttrs = nextAttrs;
}

function popAllowed() {
	currentAllowedTags =
		allowedTagsStack.length > 0 ? allowedTagsStack.pop() : DEFAULT_ALLOWED_TAGS;
	currentSafeAttrs =
		safeAttrsStack.length > 0 ? safeAttrsStack.pop() : DEFAULT_SAFE_ATTRS;
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
			// Resolve allowlists: prefer the ones cached on the vnode
			// (clone from a re-render), then the parent's, then the
			// active stack top. This keeps multiple secure trees with
			// different allowlists from stepping on each other when their
			// renders interleave via setState.
			const tags =
				vnode._secureAllowedTags ||
				(vnode._parent && vnode._parent._secureAllowedTags) ||
				currentAllowedTags;
			const attrs =
				vnode._secureSafeAttrs ||
				(vnode._parent && vnode._parent._secureSafeAttrs) ||
				currentSafeAttrs;
			vnode._secureAllowedTags = tags;
			vnode._secureSafeAttrs = attrs;
			sanitizeVNode(vnode, tags, attrs);
		}
		if (previousVnode) previousVnode(vnode);
	};

	options._render = vnode => {
		// Top-level idempotency guard: if THIS vnode already entered
		// ANY of our brackets in a prior `_render` call, never enter
		// another one. Preact's diff fires `_render` once per render
		// invocation, and on setState-in-render it loops `c.render()`
		// up to 25 times. Without this guard, a vnode whose type was
		// (incorrectly) registered in both `secureReentryTypes` AND
		// `trustedExitTypes` would take the reentry branch on
		// iteration 1 and the trusted-exit branch on iteration 2,
		// flipping sanitization off for the rest of the render. The
		// per-branch `!_*Bracketed` guards below also work, but this
		// top-level check is the strongest defense-in-depth.
		if (vnode._secureBracketed || vnode._trustedExitBracketed) {
			if (previousRender) previousRender(vnode);
			return;
		}
		// Each bracket below is idempotent: guarded by a per-vnode flag
		// that gets cleared on diffed/catchError. This matters because
		// Preact runs the function-component render in a do-while loop
		// when the component calls setState synchronously during
		// render — `_render` would fire N times for the same vnode but
		// `diffed` only once. Without the guards, `secureRenderDepth`
		// would grow unboundedly and pollute later host renders.
		//
		// Secure-reentry boundary FIRST. Confined wrappers register
		// themselves here so that an attacker rendered inside a
		// `SecureExit` island still has its output sanitized.
		if (
			vnode.type &&
			secureReentryTypes.has(vnode.type) &&
			!vnode._secureBracketed
		) {
			vnode._secureBracketed = true;
			vnode._secureCtx = true;
			// Save the trusted-exit depth and reset it for this subtree
			// so the sanitizer re-engages. Restored on diffed/catchError.
			vnode._savedTrustedExitDepth = trustedExitDepth;
			trustedExitDepth = 0;
			const tags =
				vnode._secureAllowedTags ||
				(vnode._parent && vnode._parent._secureAllowedTags) ||
				currentAllowedTags;
			const attrs =
				vnode._secureSafeAttrs ||
				(vnode._parent && vnode._parent._secureSafeAttrs) ||
				currentSafeAttrs;
			vnode._secureAllowedTags = tags;
			vnode._secureSafeAttrs = attrs;
			pushAllowed(tags, attrs);
			secureRenderDepth++;
		}
		// Trusted-exit boundary: enter a trusted island, suppress secure
		// bookkeeping for the subtree. Membership is by IDENTITY against
		// `trustedExitTypes`, NOT by a `._isSecureExit` flag — an
		// attacker who sets that flag on their own function cannot
		// enter this branch.
		else if (
			vnode.type &&
			trustedExitTypes.has(vnode.type) &&
			!vnode._trustedExitBracketed
		) {
			vnode._trustedExitBracketed = true;
			trustedExitDepth++;
		} else if (
			trustedExitDepth === 0 &&
			!vnode._secureBracketed &&
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
			// Resolve and push the allowlists for the duration of this
			// component's render. The boundary props carry the per-tree
			// allowlists; descendants inherit via their parent's cached
			// `_secureAllowedTags` / `_secureSafeAttrs`, surviving
			// renderComponent clones.
			let tags;
			let attrs;
			if (vnode.type === SecureBoundary) {
				tags =
					(vnode.props && vnode.props._allowedTags) || DEFAULT_ALLOWED_TAGS;
				attrs = (vnode.props && vnode.props._safeAttrs) || DEFAULT_SAFE_ATTRS;
			} else {
				tags =
					vnode._secureAllowedTags ||
					(vnode._parent && vnode._parent._secureAllowedTags) ||
					currentAllowedTags;
				attrs =
					vnode._secureSafeAttrs ||
					(vnode._parent && vnode._parent._secureSafeAttrs) ||
					currentSafeAttrs;
			}
			vnode._secureAllowedTags = tags;
			vnode._secureSafeAttrs = attrs;
			pushAllowed(tags, attrs);
			secureRenderDepth++;
		}
		if (previousRender) previousRender(vnode);
	};

	options.diffed = vnode => {
		if (vnode._secureBracketed) {
			vnode._secureBracketed = false;
			secureRenderDepth--;
			popAllowed();
			// If this vnode was a secure-reentry boundary, restore the
			// trusted-exit depth we saved on _render.
			if (vnode._savedTrustedExitDepth !== undefined) {
				trustedExitDepth = vnode._savedTrustedExitDepth;
				vnode._savedTrustedExitDepth = undefined;
			}
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
				popAllowed();
				if (vnode._savedTrustedExitDepth !== undefined) {
					trustedExitDepth = vnode._savedTrustedExitDepth;
					vnode._savedTrustedExitDepth = undefined;
				}
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

function sanitizeVNode(vnode, allowedTags, safeAttrs) {
	if (vnode.ref) vnode.ref = null;

	const props = vnode.props;
	if (!props || typeof props !== 'object') return;

	if ('ref' in props) delete props.ref;

	if (typeof vnode.type === 'string') {
		const tag = vnode.type.toLowerCase();
		if (!allowedTags.has(tag)) {
			vnode.type = Fragment;
			vnode.props = { children: props.children };
			return;
		}
		// Per-prop sanitization only meaningful on DOM elements —
		// Preact's `name in dom` setter path and `setAttribute` only
		// fire for string-tagged vnodes. Function components can
		// receive arbitrary prop names as data; the allowlist would
		// strip every legitimate prop name a host passes through.
		sanitizeElementProps(props, safeAttrs);
	}
}

function sanitizeElementProps(props, safeAttrs) {
	for (const key in props) {
		// `children` is the subtree, not a DOM attribute. `key` is a
		// vnode-level field that `h()` already lifted off props; on the
		// rare hand-built vnode path it may still appear here, but it
		// is never assigned to the DOM.
		if (key === 'children' || key === 'key') continue;
		const value = props[key];

		// Case-INSENSITIVE event-handler detection. Preact's diff and
		// JS property lookup are case-sensitive, but the browser's
		// HTML-attribute parsing is case-insensitive: an attacker
		// passing `OnError` survives Preact's `name[0]=='o' &&
		// name[1]=='n'` check, falls through to `setAttribute(name,
		// value)`, and the browser registers an `onerror` content
		// attribute that runs the string as JS. We drop case-variant
		// on-handlers entirely (only canonical lowercase `on*` is
		// honored).
		if (key.length > 2) {
			const c0 = key.charCodeAt(0) | 0x20; // ASCII lowercase
			const c1 = key.charCodeAt(1) | 0x20;
			if (c0 === 0x6f /* o */ && c1 === 0x6e /* n */) {
				if (key[0] !== 'o' || key[1] !== 'n') {
					delete props[key];
					continue;
				}
				if (value == null) continue;
				if (typeof value !== 'function') {
					delete props[key];
					continue;
				}
				props[key] = wrapListener(value);
				continue;
			}
		}

		const lower = key.toLowerCase();

		// `aria-*` and `data-*` are user-extensible by spec and
		// considered safe: no live setter behavior, no script
		// execution. Anything with a non-empty suffix is admitted.
		// We do not iterate the value, so accessor side effects can
		// only fire when Preact later reads it — same exposure as
		// `style` (which is shallow-copied in `preact/compartment`).
		if (
			lower.length > 5 &&
			(lower.indexOf('aria-') === 0 || lower.indexOf('data-') === 0)
		) {
			continue;
		}

		// ALLOWLIST GATE — drop anything not explicitly admitted. This
		// is the structural defense: new browser-shipped dangerous
		// setters do not become exploitable until the host opts in.
		if (!safeAttrs.has(lower)) {
			delete props[key];
			continue;
		}

		// URL value sanitization for allowlisted URL-bearing attrs.
		// Case-INSENSITIVE: `<a HREF="javascript:…">` survives the
		// allowlist via the lowercased lookup, then the value gate
		// blocks the unsafe scheme. If the value is unsafe the prop
		// is dropped entirely; safe values are written back under the
		// original key (so legitimate camelCase like `formAction` is
		// preserved).
		if (URL_ATTRS.has(lower)) {
			const sanitized = value == null ? value : sanitizeUrl(value, lower);
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
function walkSanitize(node, allowedTags, safeAttrs) {
	if (Array.isArray(node)) {
		for (let i = 0; i < node.length; i++) {
			walkSanitize(node[i], allowedTags, safeAttrs);
		}
		return;
	}
	if (!node || typeof node !== 'object' || node.constructor !== undefined) {
		return;
	}
	sanitizeVNode(node, allowedTags, safeAttrs);
	node._secureAllowedTags = allowedTags;
	node._secureSafeAttrs = safeAttrs;
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
	if (children != null) walkSanitize(children, allowedTags, safeAttrs);
}

/**
 * Render a Preact vnode into a container while enforcing the secure
 * sandbox. Components in the tree never see DOM nodes or raw events.
 *
 * @param {*} vnode The vnode to render.
 * @param {Element} parentDom The host-controlled DOM container.
 * @param {{ allowedTags?: Iterable<string>, allowedAttrs?: Iterable<string> }} [opts]
 *   `allowedTags` replaces the default tag allowlist for this tree.
 *   `allowedAttrs` EXTENDS the default attribute allowlist for this
 *   tree (additive — the defaults still apply). This is deliberate:
 *   shrinking the attribute allowlist is rarely useful, while adding
 *   one or two host-specific attrs (e.g. a custom data-bound name) is
 *   the common case.
 */
export function secureRender(vnode, parentDom, opts) {
	const allowedTags =
		opts && opts.allowedTags
			? new Set(Array.from(opts.allowedTags, tag => String(tag).toLowerCase()))
			: DEFAULT_ALLOWED_TAGS;
	let safeAttrs = DEFAULT_SAFE_ATTRS;
	if (opts && opts.allowedAttrs) {
		safeAttrs = new Set(DEFAULT_SAFE_ATTRS);
		for (const a of opts.allowedAttrs) safeAttrs.add(String(a).toLowerCase());
	}
	install();
	walkSanitize(vnode, allowedTags, safeAttrs);
	// Stash the per-tree allowlists on the boundary so concurrent
	// secure trees with different allowlists can coexist. The
	// `_allowedTags` / `_safeAttrs` props are picked up by
	// `options._render` when the boundary mounts.
	preactRender(
		h(
			SecureBoundary,
			{ _allowedTags: allowedTags, _safeAttrs: safeAttrs },
			vnode
		),
		parentDom
	);
}

/** Tear down a secure tree. */
export function unmount(parentDom) {
	preactRender(null, parentDom);
}

export { h, Fragment, createElement } from 'preact';
