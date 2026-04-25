/*
 * Reproduces a SES-lockdown incompatibility in Preact.
 *
 *   Run from repo root:
 *     npm install --no-save ses jsdom esbuild
 *     node ./node_modules/.bin/esbuild --bundle src/index.js --format=esm \
 *       --outfile=test/ses/.preact.bundle.mjs
 *     node test/ses/repro.mjs
 *
 * Expected: a class component that calls setState() (which triggers the
 * async re-render path through renderComponent()) throws under SES:
 *
 *   TypeError: Cannot assign to read only property 'constructor' of object
 *
 * Why:
 *   - Preact tags every vnode with `constructor: undefined` as an own
 *     property so it can do `vnode.constructor === undefined` to recognize
 *     a real vnode (and reject JSON-injected fakes). See createVNode in
 *     src/create-element.js.
 *   - In src/component.js, renderComponent() copies the vnode with
 *     `assign({}, oldVNode)` (Object.assign).
 *   - Object.assign uses [[Set]] semantics. SES's default `overrideTaming`
 *     turns Object.prototype.constructor into a non-writable property to
 *     prevent the "override mistake". A bare `{}` inherits from
 *     Object.prototype, so assigning to its `constructor` walks up the
 *     prototype chain to that frozen property and throws.
 *
 *   Initial renders go through createVNode where vnodes are built with an
 *   object literal — literal init uses [[CreateDataProperty]], not Set, so
 *   it bypasses the override mistake. That is why first render works but
 *   any setState/forceUpdate-triggered re-render fails.
 *
 *   Other Object.assign({}, vnode) call sites (cloneNode in diff/index.js,
 *   etc.) are vulnerable to the same failure on relevant code paths.
 */

import 'ses';
import { JSDOM } from 'jsdom';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { existsSync } from 'node:fs';

const here = dirname(fileURLToPath(import.meta.url));
const bundlePath = resolve(here, '.preact.bundle.mjs');

if (!existsSync(bundlePath)) {
	console.error(
		`missing bundle at ${bundlePath} — see header of this file for build steps`
	);
	process.exit(2);
}

const dom = new JSDOM(
	'<!doctype html><html><body><div id="root"></div></body></html>'
);
for (const k of [
	'window',
	'document',
	'HTMLElement',
	'Node',
	'Element',
	'SVGElement',
	'Text',
	'customElements',
	'Event',
	'CustomEvent'
]) {
	if (dom.window[k]) globalThis[k] = dom.window[k];
}

lockdown();
console.log('lockdown() applied');

const { createElement: h, render, Component, options } = await import(bundlePath);
// Flush re-renders synchronously so we can try/catch the error rather than
// having SES's uncaughtException handler exit the process.
options.debounceRendering = fn => fn();

const root = document.getElementById('root');

let inst;
class Counter extends Component {
	constructor(props) {
		super(props);
		this.state = { n: 0 };
		inst = this;
	}
	render(_, s) {
		return h('p', null, 'n=' + s.n);
	}
}

render(h(Counter, null), root);
console.log('initial render OK:', root.innerHTML);

let captured = null;
try {
	inst.setState({ n: 1 });
} catch (err) {
	captured = err;
}

if (
	captured &&
	/Cannot assign to read only property 'constructor'/.test(String(captured.message || captured))
) {
	console.log('REPRODUCED — SES incompatibility:');
	console.log('   ', String(captured.message || captured));
	const frame = String(captured.stack || '').split('\n').find(l => /preact|component|diff/.test(l));
	if (frame) console.log('  at:', frame.trim());
	process.exit(0);
}

if (/n=1/.test(root.innerHTML)) {
	console.log('No SES incompatibility observed (re-render OK:', root.innerHTML, ')');
	process.exit(0);
}

console.log('Unexpected: html=', root.innerHTML, 'captured=', captured);
process.exit(1);
