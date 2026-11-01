// vtest fixed k6 load-test template (H2). It is NEVER generated or edited by an LLM.
//
// Inputs are data only, passed as container environment variables:
//   VTEST_ROUTES  JSON array of URL paths (already validated on the host; re-validated here)
//   VTEST_PORT    TCP port the sandboxed app listens on (shared loopback only)
//
// Output: handleSummary() writes the k6 summary as JSON to stdout. k6's own logs go to stderr.

import http from 'k6/http';
import { sleep } from 'k6';

const ROUTE_RE = /^\/[A-Za-z0-9\/_\-.~]{0,199}$/;
const MAX_ROUTES = 50;

const PORT = parseInt(__ENV.VTEST_PORT || '', 10);
if (!(PORT >= 1 && PORT <= 65535)) {
  throw new Error('invalid VTEST_PORT');
}
const BASE = 'http://127.0.0.1:' + PORT;

let parsed = [];
try {
  parsed = JSON.parse(__ENV.VTEST_ROUTES || '[]');
} catch (e) {
  parsed = [];
}
const ROUTES = (Array.isArray(parsed) ? parsed : [])
  .filter((r) => typeof r === 'string' && ROUTE_RE.test(r) && r.indexOf('..') === -1)
  .slice(0, MAX_ROUTES);
if (ROUTES.length === 0) {
  ROUTES.push('/');
}

export const options = {
  stages: [
    { duration: '3s', target: 10 },
    { duration: '5s', target: 10 },
    { duration: '2s', target: 0 },
  ],
  setupTimeout: '45s',
  discardResponseBodies: true,
  // Always-passing thresholds: they only make k6 report sub-metrics for the
  // load phase, so readiness probes in setup() don't skew the latency numbers.
  thresholds: {
    'http_req_duration{phase:load}': ['max>=0'],
    'http_req_failed{phase:load}': ['rate>=0'],
  },
};

export function setup() {
  // Wait until the sandboxed app accepts connections. Any HTTP status counts as ready.
  for (let i = 0; i < 80; i++) {
    const res = http.get(BASE + ROUTES[0], { timeout: '2s', tags: { phase: 'probe' } });
    if (res.status !== 0) {
      return { ready: true };
    }
    sleep(0.5);
  }
  throw new Error('app did not accept connections on 127.0.0.1:' + PORT);
}

export default function () {
  for (const route of ROUTES) {
    http.get(BASE + route, { timeout: '5s', tags: { phase: 'load' } });
  }
  sleep(1);
}

export function handleSummary(data) {
  return { stdout: JSON.stringify(data) };
}
