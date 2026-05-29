import { defineConfig } from 'vite';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, '../../..');

// Map the bare specifiers used in the demo to the local source in this
// repo. This lets the example exercise the code in `secure/src` and
// `compartment/src` directly, with no separate build step.
export default defineConfig({
	resolve: {
		alias: [
			{ find: /^preact$/, replacement: path.join(repo, 'src/index.js') },
			{
				find: /^preact\/hooks$/,
				replacement: path.join(repo, 'hooks/src/index.js')
			},
			{
				find: /^preact\/secure$/,
				replacement: path.join(repo, 'secure/src/index.js')
			},
			{
				find: /^preact\/compartment$/,
				replacement: path.join(repo, 'compartment/src/index.js')
			}
		]
	}
});
