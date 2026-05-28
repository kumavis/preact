import { FunctionComponent } from 'preact';

/**
 * Bundle of utilities handed to the attacker function as its first
 * argument. The attacker can use these to produce vnodes and manage
 * component state; they cannot reach the DOM through them.
 */
export interface CompartmentEndowments {
	h: typeof import('preact').h;
	Fragment: typeof import('preact').Fragment;
	useState: typeof import('preact/hooks').useState;
	useEffect: typeof import('preact/hooks').useEffect;
	useCallback: typeof import('preact/hooks').useCallback;
	useMemo: typeof import('preact/hooks').useMemo;
	useRef: typeof import('preact/hooks').useRef;
	useReducer: typeof import('preact/hooks').useReducer;
}

/**
 * Shape of the props the attacker sees. The host's `children` is
 * replaced with an array of opaque sentinel vnodes the attacker can
 * position but not inspect.
 *
 * SECURITY: any function-typed prop the host passes through (e.g. an
 * `onSubmit` callback) is callable by the attacker with arbitrary
 * arguments. Host code MUST treat those arguments as untrusted JSON.
 */
export type ConfinedProps<P extends object = {}> = Readonly<P> & {
	readonly children?: readonly unknown[];
};

export interface ConfineOptions {
	/** Display name used by devtools. Default: `"Confined"`. */
	name?: string;
}

/**
 * Wrap an attacker-supplied component function so it can be mounted in
 * a normal Preact tree. Place the result inside a `secureRender` tree
 * to get full sanitization on top.
 */
export function confineComponent<P extends object = {}>(
	fn: (endowments: CompartmentEndowments, props: ConfinedProps<P>) => unknown,
	opts?: ConfineOptions
): FunctionComponent<P>;

/** Returns true if `value` is a wrapper returned by `confineComponent`. */
export function isConfinedComponent(value: unknown): boolean;

export { SecureExit } from 'preact/secure';
