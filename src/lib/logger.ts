import type { FastifyServerOptions } from 'fastify';

/**
 * Fields that must never reach the logs.
 *
 * Structured logging with explicit redaction is required: tokens, keys, secrets,
 * passwords, and connection strings never belong in log output.
 */
export const REDACT_PATHS = [
  'req.headers.authorization',
  'req.headers.cookie',
  'req.headers["x-api-key"]',
  'res.headers["set-cookie"]',
  'DATABASE_URL',
  'SUPABASE_SERVICE_ROLE_KEY',
  'WALLET_NONCE_SECRET',
  'S3_ACCESS_KEY_ID',
  'S3_SECRET_ACCESS_KEY',
  'password',
  'secret',
  'token',
  'privateKey',
  '*.password',
  '*.secret',
  '*.token',
  '*.privateKey',
  '*.authorization',
] as const;

/**
 * Builds Fastify logger options with secret redaction enabled.
 *
 * Emits JSON logs across environments for structured aggregation, setting
 * the log level to 'info' in production and 'debug' outside production.
 */
export function buildLoggerOptions(nodeEnv: string): FastifyServerOptions['logger'] {
  const isProduction = nodeEnv === 'production';

  return {
    level: isProduction ? 'info' : 'debug',
    redact: {
      paths: [...REDACT_PATHS],
      censor: '[redacted]',
    },
  };
}
