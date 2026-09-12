/**
 * Vercel serverless entrypoint source for the Chronicle Control Plane API.
 *
 * This file is NOT deployed as-is — scripts/build-vercel-api.mjs bundles it
 * (and every @chronicle/* workspace package it transitively imports) into a
 * single self-contained api/index.js via esbuild before each Vercel build,
 * because Vercel's zero-config Node.js builder only transpiles the function's
 * own entry file, not other .ts files it imports across the workspace.
 *
 * The ChronicleControlPlane instance below is created once at module scope,
 * so it is reused (in-memory state included) across invocations for as long
 * as this serverless function instance stays warm.
 */
import { ChronicleControlPlane } from './index.ts';

const controlPlane = new ChronicleControlPlane();

export default controlPlane.getRequestHandler();
