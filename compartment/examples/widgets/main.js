// SES installs `lockdown` and `Compartment` on `globalThis`. Importing
// it for side effect is the standard pattern.
import 'ses';

import { h, Fragment } from 'preact';
import { secureRender } from 'preact/secure';
import { confineComponent } from 'preact/compartment';

// Lockdown freezes built-in prototypes before any untrusted code runs.
// `overrideTaming: 'severe'` keeps prototype properties like
// `constructor` overridable, which Preact's vnode-clone helper relies
// on. The lockdown is still real — primordials are frozen, the
// compartment isolation is in force.
lockdown({ overrideTaming: 'severe' });

// ---------------------------------------------------------------------
// Three untrusted widget source strings.
// In a real host these come from disk / network / a plugin registry.
// Each function has the signature `({ h, Fragment, useState, ... }, props)`.
// ---------------------------------------------------------------------

const COUNTER_SOURCE = `({ h, useState }, props) => {
  const [n, setN] = useState(0);
  return h('div', null,
    h('p', null, props.label || 'Counter'),
    h('button', {
      onClick: () => setN(prev => prev + 1)
    }, 'clicked ' + n + ' times'),
    // The host has placed a "logout" control behind props.children.
    // The attacker can position it but cannot inspect or impersonate
    // the host vnode it represents.
    h('div', { class: 'host-slot' }, props.children && props.children[0])
  );
}`;

const FORM_SOURCE = `({ h, useState }, props) => {
  const [name, setName] = useState('');
  return h('form', {
    onSubmit: e => {
      e.preventDefault();
      // Call back into the host with a primitive only.
      props.onSubmit(name);
    }
  },
    h('label', null,
      'Your name: ',
      h('input', {
        type: 'text',
        value: name,
        onInput: e => setName(e.target.value)
      })
    ),
    h('button', { type: 'submit' }, 'Submit'),
    h('div', { class: 'host-slot' }, props.children && props.children[0])
  );
}`;

// A widget that deliberately tries every attack the renderer defends
// against. None of these should reach the DOM in any observable way.
const MALICIOUS_SOURCE = `({ h }, props) => {
  // Attempt 1: a <script> tag — replaced with Fragment, children kept.
  const evilScript = h('script', null, 'window.evil = true;');
  // Attempt 2: javascript: URL on a link.
  const evilLink = h('a', { href: 'javascript:alert(1)' }, 'click for prize');
  // Attempt 3: a ref to try to grab the DOM node. Refs are stripped.
  const evilRef = el => { window.STOLEN_DOM = el; };
  // Attempt 4: dangerouslySetInnerHTML.
  const evilHTML = h('div', {
    dangerouslySetInnerHTML: { __html: '<img src=x onerror=alert(1)>' }
  });

  return h('div', null,
    h('p', null, 'Malicious widget — none of these attacks should land:'),
    h('ul', null,
      h('li', null, evilScript, ' (script was replaced with a Fragment)'),
      h('li', { ref: evilRef }, evilLink),
      h('li', null, evilHTML, ' (innerHTML should be empty)')
    ),
    h('div', { class: 'host-slot' }, props.children && props.children[0])
  );
}`;

// ---------------------------------------------------------------------
// Evaluate each source string in its own fresh Compartment, then wrap
// the resulting function with `confineComponent`.
// ---------------------------------------------------------------------

function loadWidget(source, name) {
	const compartment = new Compartment({
		// The host could endow globals here; we deliberately leave the
		// compartment globals empty. All capabilities come through the
		// confineComponent `endowments` argument, never via `globalThis`.
	});
	const fn = compartment.evaluate('(' + source + ')');
	return confineComponent(fn, {
		name,
		onError: err => log('[' + name + '] threw: ' + err.message)
	});
}

const Counter = loadWidget(COUNTER_SOURCE, 'Counter');
const ContactForm = loadWidget(FORM_SOURCE, 'ContactForm');
const Malicious = loadWidget(MALICIOUS_SOURCE, 'Malicious');

// ---------------------------------------------------------------------
// Host shell — a normal Preact tree that mounts the confined widgets
// and supplies trusted children via transclusion.
// ---------------------------------------------------------------------

const logEl = document.getElementById('log');
function log(line) {
	logEl.textContent += line + '\n';
	logEl.scrollTop = logEl.scrollHeight;
}

// A small host-trusted button that the user clicks to log out. We
// transclude it into each widget's body — the widget positions it
// wherever it wants in its own JSX but cannot inspect it or rewire
// what it does.
function HostLogoutSlot() {
	return h(
		'button',
		{
			onClick: () =>
				log('[host] user clicked "log out" (real DOM event)')
		},
		'log out (host control)'
	);
}

function App() {
	return h(
		Fragment,
		null,
		h(
			'section',
			{ class: 'widget' },
			h('h2', null, 'Counter (confined)'),
			h(
				Counter,
				{ label: 'Click me as much as you like' },
				h(HostLogoutSlot)
			)
		),
		h(
			'section',
			{ class: 'widget' },
			h('h2', null, 'Form (confined)'),
			h(
				ContactForm,
				{
					onSubmit: name =>
						log('[form] submitted with name=' + JSON.stringify(name))
				},
				h(HostLogoutSlot)
			)
		),
		h(
			'section',
			{ class: 'widget' },
			h('h2', null, 'Malicious (confined)'),
			h(Malicious, null, h(HostLogoutSlot))
		)
	);
}

secureRender(h(App), document.getElementById('root'));

// After the first paint, check whether any of the malicious attacks
// landed. If the renderer did its job, all of these are negative.
setTimeout(() => {
	log('--- post-mount inspection ---');
	log(
		'window.evil           = ' +
			(typeof window.evil === 'undefined'
				? 'undefined ✓'
				: '!!! ' + window.evil)
	);
	log(
		'window.STOLEN_DOM     = ' +
			(typeof window.STOLEN_DOM === 'undefined'
				? 'undefined ✓'
				: '!!! got ' + window.STOLEN_DOM)
	);
	const evilLink = document.querySelector('a');
	log(
		'a.href                = ' +
			(evilLink && evilLink.hasAttribute('href')
				? '!!! ' + evilLink.getAttribute('href')
				: '(stripped) ✓')
	);
	// Scope to #root so we don't see the legitimate <script> tags the
	// host page (or a dev server) might have injected outside the
	// confined tree.
	const evilFrame = document
		.getElementById('root')
		.querySelector('iframe, script, object, embed');
	log(
		'iframe/script/object  = ' +
			(evilFrame ? '!!! found ' + evilFrame.tagName : 'none ✓')
	);
	log('--- ready, interact with the widgets above ---');
}, 0);
