import { createElement } from 'preact';
import lavatube from '@lavamoat/lavatube';
import { secureRender, unmount } from 'preact/secure';
import { setupScratch, teardown } from '../../../test/_util/helpers';

/** @jsx createElement */

/**
 * These tests use @lavamoat/lavatube to walk the object graph reachable
 * from objects that component code receives, looking for paths back to
 * live DOM elements. lavatube cannot peek into closures or invoke
 * functions, so a negative result is "no path found via property
 * traversal" rather than a proof of unreachability — but it is a strong
 * defense-in-depth signal that the SafeEvent facade does not
 * accidentally hold a reference to a real DOM Element.
 */

// Bound the walk so tests run in finite time. The DOM and prototype
// chain together expose a very large graph; if a leak existed it would
// almost always sit within a few hops of the surface.
const WALK_OPTS = { maxDepth: 8 };

function captureFirstHandlerArg(scratch) {
	let captured;
	secureRender(
		<button
			onClick={e => {
				captured = e;
			}}
		>
			ok
		</button>,
		scratch
	);
	scratch.querySelector('button').click();
	return captured;
}

describe('preact/secure: dom unreachability (lavatube)', () => {
	/** @type {HTMLDivElement} */
	let scratch;

	beforeEach(() => {
		scratch = setupScratch();
	});

	afterEach(() => {
		unmount(scratch);
		teardown(scratch);
	});

	it('SafeEvent has no path to the live button it fired on', () => {
		const safe = captureFirstHandlerArg(scratch);
		const button = scratch.querySelector('button');
		expect(button).to.exist;
		// sanity: confirm lavatube *can* find the button when the start
		// reference actually contains it. Catches misconfiguration where
		// the negative tests below trivially pass for the wrong reason.
		expect(lavatube.find({ button }, button, WALK_OPTS)).to.not.equal(
			undefined
		);

		const path = lavatube.find(safe, button, WALK_OPTS);
		expect(path).to.equal(undefined);
	});

	it('SafeEvent has no path to document', () => {
		const safe = captureFirstHandlerArg(scratch);
		const path = lavatube.find(safe, document, WALK_OPTS);
		expect(path).to.equal(undefined);
	});

	it('SafeEvent has no path to window', () => {
		const safe = captureFirstHandlerArg(scratch);
		const path = lavatube.find(safe, window, WALK_OPTS);
		expect(path).to.equal(undefined);
	});

	it('SafeEvent has no path to the scratch container', () => {
		const safe = captureFirstHandlerArg(scratch);
		const path = lavatube.find(safe, scratch, WALK_OPTS);
		expect(path).to.equal(undefined);
	});

	it('SafeEvent.target snapshot has no path back to the live element', () => {
		const safe = captureFirstHandlerArg(scratch);
		const button = scratch.querySelector('button');
		// the snapshot must not BE the live element
		expect(safe.target).to.not.equal(button);
		// and must not lead to it
		expect(lavatube.find(safe.target, button, WALK_OPTS)).to.equal(undefined);
		expect(lavatube.find(safe.target, document, WALK_OPTS)).to.equal(undefined);
	});

	it('SafeEvent.currentTarget snapshot has no path back to the live element', () => {
		const safe = captureFirstHandlerArg(scratch);
		const button = scratch.querySelector('button');
		expect(safe.currentTarget).to.not.equal(button);
		expect(lavatube.find(safe.currentTarget, button, WALK_OPTS)).to.equal(
			undefined
		);
	});

	it('SafeEvent does not expose the underlying DOM Event via any field', () => {
		// Capture both the safe facade and the raw browser Event so we
		// can search for a path from one to the other.
		let safe;
		let raw;
		secureRender(
			<button
				onClick={e => {
					safe = e;
				}}
			>
				ok
			</button>,
			scratch
		);
		const button = scratch.querySelector('button');
		button.addEventListener('click', e => {
			raw = e;
		});
		button.click();
		expect(safe).to.exist;
		expect(raw).to.exist;
		expect(safe).to.not.equal(raw);
		const path = lavatube.find(safe, raw, WALK_OPTS);
		expect(path).to.equal(undefined);
	});

	it('SafeEvent passed to a deeply nested component still has no DOM path', () => {
		let captured;
		function Inner({ onPing }) {
			return (
				<button
					onClick={e => {
						onPing(e);
					}}
				>
					inner
				</button>
			);
		}
		function Outer() {
			return (
				<div>
					<Inner
						onPing={e => {
							captured = e;
						}}
					/>
				</div>
			);
		}
		secureRender(<Outer />, scratch);
		scratch.querySelector('button').click();

		const button = scratch.querySelector('button');
		expect(captured).to.exist;
		expect(lavatube.find(captured, button, WALK_OPTS)).to.equal(undefined);
		expect(lavatube.find(captured, document, WALK_OPTS)).to.equal(undefined);
	});
});
