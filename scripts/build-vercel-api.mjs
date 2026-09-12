/**
 * Bundles apps/control-plane/src/vercel-handler.ts (and every @chronicle/*
 * workspace package it transitively imports) into a single self-contained
 * api/index.js via esbuild.
 *
 * Needed because Vercel's zero-config Node.js function builder only
 * transpiles the function's own entry file, not other .ts files it imports
 * elsewhere in the workspace — so a plain multi-file TypeScript entry fails
 * at runtime with ERR_MODULE_NOT_FOUND on the untranspiled imports.
 *
 * Run manually (`npm run build:vercel-api`) and commit the resulting
 * api/index.js whenever apps/control-plane/src or its @chronicle/* package
 * dependencies change. Vercel detects serverless functions by scanning the
 * source tree BEFORE running any build command, so a generated-but-uncommitted
 * api/index.js would not exist yet when Vercel looks for it — this can't be
 * wired up as an automatic pre-build step the way framework builds are.
 */
import { build } from 'esbuild';
import { mkdirSync } from 'node:fs';

mkdirSync('api', { recursive: true });

await build({
  entryPoints: ['apps/control-plane/src/vercel-handler.ts'],
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: 'node22',
  outfile: 'api/index.js',
  logLevel: 'info'
});

console.log('[build-vercel-api] Bundled apps/control-plane/src/vercel-handler.ts -> api/index.js');
