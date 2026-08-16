'use strict';

const ALLOWED_FIELDS = new Set([
  'reason', 'method', 'resource', 'status', 'upstreamStatus', 'diagnosticCode',
  'requestId', 'route', 'outcome'
]);

function safeText(value, maximum = 120) {
  return String(value ?? '')
    .replace(/[\u0000-\u001f\u007f]/g, '')
    .slice(0, maximum);
}

function securityDiagnostic(event, details = {}) {
  const record = { event:safeText(event, 80) };
  for (const [key, value] of Object.entries(details || {})) {
    if (!ALLOWED_FIELDS.has(key)) continue;
    record[key] = typeof value === 'number' ? value : safeText(value);
  }
  console.warn(JSON.stringify(record));
}

module.exports = { securityDiagnostic };
