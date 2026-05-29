import { createElement, createRef } from 'preact';
import { secureRender, unmount } from 'preact/secure';
import {
	confineComponent,
	isConfinedComponent
} from 'preact/compartment';
import { setupRerender } from 'preact/test-utils';
import { setupScratch, teardown } from '../../../test/_util/helpers';

/** @jsx createElement */

describe('preact/compartment', () => {
	/** @type {HTMLDivElement} */
	let scratch;
	/** @type {() => void} */
	let rerender;

	beforeEach(() => {
		scratch = setupScratch();
		rerender = setupRerender();
	});

	afterEach(() => {
		unmount(scratch);
		teardown(scratch);
	});

	it('confineComponent returns a Preact function component', () => {
		const Confined = confineComponent(({ h }, props) => h('div', null, props.title));
		expect(typeof Confined).to.equal('function');
		expect(isConfinedComponent(Confined)).to.equal(true);
		expect(isConfinedComponent(() => {})).to.equal(false);
	});

	it('mounts attacker output via endowments.h', () => {
		const Confined = confineComponent(({ h }, props) =>
			h('div', { class: 'k' }, 'hi ', props.who)
		);
		secureRender(<Confined who="world" />, scratch);
		expect(scratch.firstChild.className).to.equal('k');
		expect(scratch.firstChild.textContent).to.equal('hi world');
	});

	it('attacker can use hooks from endowments for local state', () => {
		const Confined = confineComponent(({ h, useState }) => {
			const [n, setN] = useState(0);
			return h(
				'button',
				{
					onClick: () => setN(prev => prev + 1)
				},
				String(n)
			);
		});
		secureRender(<Confined />, scratch);
		const btn = scratch.querySelector('button');
		expect(btn.textContent).to.equal('0');
		btn.click();
		rerender();
		expect(btn.textContent).to.equal('1');
	});

	it('attacker props are frozen — assignment fails silently or throws', () => {
		let seenProps;
		const Confined = confineComponent(({ h }, props) => {
			seenProps = props;
			return h('span', null, props.label);
		});
		secureRender(<Confined label="hi" />, scratch);
		expect(Object.isFrozen(seenProps)).to.equal(true);
		expect(() => {
			'use strict';
			seenProps.label = 'mutated';
		}).to.throw();
		expect(seenProps.label).to.equal('hi');
	});

	it('drops attacker return value of a wrong shape (plain object)', () => {
		const Confined = confineComponent(() => ({ not: 'a vnode' }));
		secureRender(<Confined />, scratch);
		expect(scratch.innerHTML).to.equal('');
	});

	it('drops attacker return value that is a Promise', () => {
		const Confined = confineComponent(() => Promise.resolve('x'));
		secureRender(<Confined />, scratch);
		expect(scratch.innerHTML).to.equal('');
	});

	it('drops attacker return value that is a Proxy pretending to be a vnode', () => {
		const Confined = confineComponent(() => {
			return new Proxy(
				{ type: 'div', props: { children: 'x' } },
				{
					get(target, key) {
						return target[key];
					}
				}
			);
		});
		secureRender(<Confined />, scratch);
		// Proxies have a real Object constructor so the coercer rejects them.
		expect(scratch.innerHTML).to.equal('');
	});

	it('replaces a vnode with a class-instance .type with a Fragment', () => {
		class Sneaky {}
		const Confined = confineComponent(({ h, Fragment }) =>
			// Build a real vnode but with a banned class as its type
			h(Sneaky, null, h('span', null, 'kept-child'))
		);
		secureRender(<Confined />, scratch);
		expect(scratch.querySelector('span').textContent).to.equal('kept-child');
	});

	it('coerces a string return value to a text node', () => {
		const Confined = confineComponent(() => 'just text');
		secureRender(
			<div>
				<Confined />
			</div>,
			scratch
		);
		expect(scratch.firstChild.textContent).to.equal('just text');
	});

	it('coerces an array return value', () => {
		const Confined = confineComponent(({ h }) => [
			h('span', { class: 'a' }, '1'),
			h('span', { class: 'b' }, '2')
		]);
		secureRender(
			<div>
				<Confined />
			</div>,
			scratch
		);
		expect(scratch.querySelectorAll('span')).to.have.lengthOf(2);
		expect(scratch.querySelector('.a').textContent).to.equal('1');
		expect(scratch.querySelector('.b').textContent).to.equal('2');
	});

	it('attacker rendering a disallowed tag still hits the secure allowlist', () => {
		const Confined = confineComponent(({ h }) =>
			h('div', null, h('script', null, 'alert(1)'), 'after')
		);
		secureRender(<Confined />, scratch);
		expect(scratch.querySelector('script')).to.equal(null);
		expect(scratch.firstChild.textContent).to.equal('alert(1)after');
	});

	it('attacker on-handler still receives a SafeEvent (no DOM access)', () => {
		let captured;
		const Confined = confineComponent(({ h }) =>
			h(
				'button',
				{
					onClick: e => {
						captured = e;
					}
				},
				'go'
			)
		);
		secureRender(<Confined />, scratch);
		scratch.querySelector('button').click();
		expect(captured).to.exist;
		expect(captured instanceof Event).to.equal(false);
		expect(captured.target.parentNode).to.equal(undefined);
		expect(captured.target.tagName).to.equal('button');
	});

	it('host children appear as opaque sentinels the attacker cannot inspect', () => {
		let firstChildVNode;
		const Confined = confineComponent(({ h }, props) => {
			firstChildVNode = props.children[0];
			return h('div', null, props.children);
		});
		secureRender(
			<Confined>
				<span class="hostlabel">host-content</span>
			</Confined>,
			scratch
		);
		expect(firstChildVNode).to.exist;
		// The sentinel's type is the OpaqueChild marker, not the host's `span`.
		expect(firstChildVNode.type).to.not.equal('span');
		// And the sentinel's own props carry no reference to the host vnode.
		const ownProps = Object.keys(firstChildVNode.props).filter(k => k !== 'key');
		ownProps.forEach(k => {
			const v = firstChildVNode.props[k];
			expect(v && v.type).to.not.equal('span');
		});
		// Host content nonetheless reaches the DOM.
		expect(scratch.querySelector('.hostlabel').textContent).to.equal(
			'host-content'
		);
	});

	it('opaque slot renders host content inside a SecureExit (host refs work)', () => {
		const hostRef = createRef();
		const Confined = confineComponent(({ h }, props) =>
			h('section', null, props.children)
		);
		secureRender(
			<Confined>
				<div ref={hostRef}>trusted</div>
			</Confined>,
			scratch
		);
		// The ref attached on host content gets the live DOM node — that is
		// the explicit purpose of SecureExit (host trusts its own subtree).
		expect(hostRef.current).to.be.instanceof(Element);
		expect(hostRef.current.textContent).to.equal('trusted');
	});

	it('two host children render at the positions the attacker placed them', () => {
		const Confined = confineComponent(({ h }, props) =>
			h(
				'div',
				null,
				h('header', null, props.children[0]),
				h('footer', null, props.children[1])
			)
		);
		secureRender(
			<Confined>
				<span class="A">A</span>
				<span class="B">B</span>
			</Confined>,
			scratch
		);
		expect(scratch.querySelector('header .A').textContent).to.equal('A');
		expect(scratch.querySelector('footer .B').textContent).to.equal('B');
	});

	it('confined components can nest', () => {
		const Inner = confineComponent(({ h }, props) =>
			h('span', { class: 'inner' }, props.label)
		);
		const Outer = confineComponent(({ h }, props) =>
			h('div', { class: 'outer' }, h(Inner, { label: props.text }))
		);
		// The outer attacker references Inner by closure — but that only
		// works because confineComponent allows confined functions as
		// vnode types. Verify rendering hooks up correctly.
		secureRender(<Outer text="hello" />, scratch);
		expect(scratch.querySelector('.outer .inner').textContent).to.equal(
			'hello'
		);
	});

	it('rejects an unknown function as vnode.type, replacing with Fragment', () => {
		const evilType = () => 'whatever';
		const Confined = confineComponent(({ h }) =>
			h(evilType, null, h('span', null, 'kept'))
		);
		secureRender(<Confined />, scratch);
		expect(scratch.querySelector('span').textContent).to.equal('kept');
	});

	it('attacker throwing during render renders nothing (handled, not propagated)', () => {
		const Confined = confineComponent(() => {
			throw new Error('boom');
		});
		// Wrap in a host element so we can observe the empty slot.
		secureRender(
			<div class="slot">
				<Confined />
			</div>,
			scratch
		);
		expect(scratch.querySelector('.slot').children.length).to.equal(0);
	});

	it('onError option fires with the thrown value', () => {
		const captured = [];
		const Confined = confineComponent(
			() => {
				throw new Error('boom');
			},
			{
				onError: err => {
					captured.push(err);
				}
			}
		);
		secureRender(<Confined />, scratch);
		expect(captured).to.have.lengthOf(1);
		expect(captured[0].message).to.equal('boom');
	});

	it('an onError that itself throws does not break the host render', () => {
		const Confined = confineComponent(
			() => {
				throw new Error('boom');
			},
			{
				onError: () => {
					throw new Error('telemetry exploded');
				}
			}
		);
		expect(() => {
			secureRender(
				<div class="host">
					<Confined />
					<span class="next">still here</span>
				</div>,
				scratch
			);
		}).to.not.throw();
		expect(scratch.querySelector('.next').textContent).to.equal('still here');
	});

	it('preserves attacker keys across re-render: keyed list reorder reuses DOM nodes', () => {
		// Each <li> we render carries a known DOM node we can identify
		// by data-attribute. After a reorder, those same physical nodes
		// should appear in the new positions if keys reconciled.
		let setOrder;
		function Host() {
			const order = ['a', 'b', 'c'];
			// We expose setOrder by closing over it from a host hook.
			// Simpler: render twice with different orders.
			return null;
		}
		const Confined = confineComponent(({ h }, props) =>
			h(
				'ul',
				null,
				...props.items.map(k =>
					h('li', { key: k, 'data-k': k }, String(k))
				)
			)
		);
		secureRender(<Confined items={['a', 'b', 'c']} />, scratch);
		const before = Array.from(scratch.querySelectorAll('li'));
		const byKey = new Map(before.map(li => [li.getAttribute('data-k'), li]));

		secureRender(<Confined items={['c', 'a', 'b']} />, scratch);
		const after = Array.from(scratch.querySelectorAll('li'));

		// Same DOM nodes, just rearranged — proves keys round-tripped.
		expect(after[0]).to.equal(byKey.get('c'));
		expect(after[1]).to.equal(byKey.get('a'));
		expect(after[2]).to.equal(byKey.get('b'));
	});

	it('host children keep stable identity across re-renders (host refs persist)', () => {
		// If the opaque-slot wrapping lost keys, the host's <div> would be
		// torn down + remounted on each render, and the host's ref would
		// receive `null` then a new element.
		const refHistory = [];
		const hostRef = el => {
			refHistory.push(el);
		};
		const Confined = confineComponent(({ h }, props) =>
			h('section', null, props.children)
		);
		secureRender(
			<Confined key="x">
				<div ref={hostRef}>persistent</div>
			</Confined>,
			scratch
		);
		const firstEl = refHistory[refHistory.length - 1];
		// re-render with the same children
		secureRender(
			<Confined key="x">
				<div ref={hostRef}>persistent</div>
			</Confined>,
			scratch
		);
		const lastEl = refHistory[refHistory.length - 1];
		expect(firstEl).to.be.instanceof(Element);
		expect(lastEl).to.equal(firstEl);
	});
});
