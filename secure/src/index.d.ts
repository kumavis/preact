import { ComponentChild, ContainerNode } from 'preact';

export { h, Fragment, createElement } from 'preact';

export interface SecureRenderOptions {
	/**
	 * Override the set of HTML tag names that may be rendered. Anything
	 * outside the list is replaced with a Fragment so the offending element
	 * disappears while its children continue to render.
	 */
	allowedTags?: Iterable<string>;
}

/**
 * A flat snapshot of the DOM target an event fired on. Only primitive,
 * read-only fields are exposed — there is no path back to the live element.
 */
export interface SafeEventTarget {
	readonly tagName: string | null;
	readonly name: string | null;
	readonly id: string | null;
	readonly type: string | null;
	readonly value: string | number | boolean | undefined;
	readonly checked: boolean | undefined;
	readonly selectedIndex: number | undefined;
}

/**
 * A sanitized facade over a DOM `Event`. Component code only ever receives
 * objects of this shape; the underlying DOM event is never reachable.
 */
export interface SafeEvent {
	readonly type: string;
	readonly timeStamp: number;
	readonly bubbles: boolean;
	readonly cancelable: boolean;
	readonly isTrusted: boolean;
	readonly eventPhase: number;
	readonly defaultPrevented: boolean;
	readonly target: SafeEventTarget | null;
	readonly currentTarget: SafeEventTarget | null;

	readonly key?: string;
	readonly code?: string;
	readonly keyCode?: number;
	readonly which?: number;
	readonly charCode?: number;
	readonly location?: number;
	readonly repeat?: boolean;
	readonly isComposing?: boolean;

	readonly altKey?: boolean;
	readonly ctrlKey?: boolean;
	readonly metaKey?: boolean;
	readonly shiftKey?: boolean;

	readonly button?: number;
	readonly buttons?: number;

	readonly clientX?: number;
	readonly clientY?: number;
	readonly pageX?: number;
	readonly pageY?: number;
	readonly screenX?: number;
	readonly screenY?: number;
	readonly offsetX?: number;
	readonly offsetY?: number;
	readonly movementX?: number;
	readonly movementY?: number;

	readonly pointerId?: number;
	readonly pointerType?: string;
	readonly isPrimary?: boolean;

	readonly deltaX?: number;
	readonly deltaY?: number;
	readonly deltaZ?: number;
	readonly deltaMode?: number;

	preventDefault(): void;
	stopPropagation(): void;
	stopImmediatePropagation(): void;
}

export function secureRender(
	vnode: ComponentChild,
	parentDom: ContainerNode,
	opts?: SecureRenderOptions
): void;

export function unmount(parentDom: ContainerNode): void;

/**
 * Boundary that disables sanitization for everything rendered inside it.
 * Used by add-on layers (e.g. `preact/compartment`) to splice
 * host-trusted vnodes back into an otherwise-confined tree. Components
 * rendered below a `SecureExit` see real DOM events, real refs work,
 * etc. Use only with vnodes the host fully controls.
 */
export const SecureExit: import('preact').FunctionComponent<{
	children?: ComponentChild;
}>;
