import { Writable } from 'node:stream';
import Fastify, { type FastifyLoggerOptions } from 'fastify';
import pino, { type LoggerOptions } from 'pino';
import { describe, expect, it } from 'vitest';
import { buildLoggerOptions, REDACT_PATHS } from './logger';

describe('buildLoggerOptions', () => {
  it('configures info level and redaction in production', () => {
    const options = buildLoggerOptions('production') as FastifyLoggerOptions & LoggerOptions;
    expect(options.level).toBe('info');
    expect(options.redact).toEqual({
      paths: [...REDACT_PATHS],
      censor: '[redacted]',
    });
    expect(options.transport).toBeUndefined();
  });

  it('configures debug level and redaction outside production', () => {
    const devOptions = buildLoggerOptions('development') as FastifyLoggerOptions & LoggerOptions;
    expect(devOptions.level).toBe('debug');
    expect(devOptions.redact).toEqual({
      paths: [...REDACT_PATHS],
      censor: '[redacted]',
    });
    expect(devOptions.transport).toBeUndefined();

    const testOptions = buildLoggerOptions('test') as FastifyLoggerOptions & LoggerOptions;
    expect(testOptions.level).toBe('debug');
    expect(testOptions.transport).toBeUndefined();
  });

  it('includes all required security paths in REDACT_PATHS', () => {
    expect(REDACT_PATHS).toContain('req.headers.authorization');
    expect(REDACT_PATHS).toContain('DATABASE_URL');
    expect(REDACT_PATHS).toContain('token');
    expect(REDACT_PATHS).toContain('password');
    expect(REDACT_PATHS).toContain('secret');
  });
});

describe('logger serialization & redaction', () => {
  function captureLogs(nodeEnv: string = 'test'): {
    logger: pino.Logger;
    getOutput: () => string;
    getParsedLogs: () => Record<string, unknown>[];
  } {
    const chunks: string[] = [];
    const stream = new Writable({
      write(chunk, _encoding, callback) {
        chunks.push(chunk.toString());
        callback();
      },
    });

    const options = buildLoggerOptions(nodeEnv) as LoggerOptions;
    const logger = pino(options, stream);

    return {
      logger,
      getOutput: () => chunks.join(''),
      getParsedLogs: () =>
        chunks
          .join('')
          .trim()
          .split('\n')
          .filter(Boolean)
          .map((line) => JSON.parse(line) as Record<string, unknown>),
    };
  }

  it('redacts req.headers.authorization, DATABASE_URL, and token in serialized output', () => {
    const { logger, getOutput, getParsedLogs } = captureLogs();

    const authSecret = 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret-token';
    const dbSecret = 'postgresql://admin:super_secret_password@db.internal:5432/production';
    const tokenSecret = 'raw-api-token-xyz-12345';
    const safeMsg = 'request completed successfully';
    const safePath = '/api/v1/health';

    logger.info(
      {
        req: {
          headers: {
            authorization: authSecret,
          },
          url: safePath,
        },
        DATABASE_URL: dbSecret,
        token: tokenSecret,
        safeField: 'safe-value',
      },
      safeMsg,
    );

    const serialized = getOutput();
    const logs = getParsedLogs();
    expect(logs).toHaveLength(1);
    const entry = logs[0];

    // Assert that redacted values are replaced with [redacted]
    expect(entry.DATABASE_URL).toBe('[redacted]');
    expect(entry.token).toBe('[redacted]');
    const reqObj = entry.req as { headers?: { authorization?: string }; url?: string };
    expect(reqObj?.headers?.authorization).toBe('[redacted]');

    // Assert that sensitive values never appear verbatim in the raw serialized stream
    expect(serialized).not.toContain(authSecret);
    expect(serialized).not.toContain(dbSecret);
    expect(serialized).not.toContain(tokenSecret);

    // Assert safe fields remain visible and unredacted
    expect(serialized).toContain(safeMsg);
    expect(serialized).toContain(safePath);
    expect(entry.safeField).toBe('safe-value');
  });

  it('proves no configured secret path appears verbatim in serialized output', () => {
    const { logger, getOutput, getParsedLogs } = captureLogs();

    const secrets = {
      authorization: 'Bearer secret-bearer-token',
      cookie: 'session_id=secret_cookie_hash',
      apiKey: 'sec-api-key-999',
      setCookie: 'refresh_token=secret_refresh_hash; Path=/',
      databaseUrl: 'postgres://user:dbpass@localhost:5432/app',
      supabaseKey: 'supabase-service-role-super-secret-key',
      nonceSecret: 'nonce-secret-32-chars-long-abcde',
      s3KeyId: 'AKIAIOSFODNN7EXAMPLEKEY',
      s3Secret: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
      password: 'my-plaintext-password',
      secret: 'app-shared-secret',
      token: 'access-token-string',
      privateKey: '0xabcdef1234567890abcdef1234567890abcdef12',
      nestedPassword: 'nested-user-password',
      nestedSecret: 'nested-secret-value',
      nestedToken: 'nested-jwt-token',
      nestedPrivateKey: '0xdeadbeef12345678',
      nestedAuth: 'Basic dXNlcjpwYXNz',
    };

    logger.info(
      {
        req: {
          headers: {
            authorization: secrets.authorization,
            cookie: secrets.cookie,
            'x-api-key': secrets.apiKey,
          },
        },
        res: {
          headers: {
            'set-cookie': secrets.setCookie,
          },
        },
        DATABASE_URL: secrets.databaseUrl,
        SUPABASE_SERVICE_ROLE_KEY: secrets.supabaseKey,
        WALLET_NONCE_SECRET: secrets.nonceSecret,
        S3_ACCESS_KEY_ID: secrets.s3KeyId,
        S3_SECRET_ACCESS_KEY: secrets.s3Secret,
        password: secrets.password,
        secret: secrets.secret,
        token: secrets.token,
        privateKey: secrets.privateKey,
        nested: {
          password: secrets.nestedPassword,
          secret: secrets.nestedSecret,
          token: secrets.nestedToken,
          privateKey: secrets.nestedPrivateKey,
          authorization: secrets.nestedAuth,
        },
        publicField: 'safe-public-data',
      },
      'redaction test entry',
    );

    const serialized = getOutput();
    const logs = getParsedLogs();
    expect(logs).toHaveLength(1);
    const entry = logs[0];

    // Verify all secret values are NOT present verbatim anywhere in the output
    for (const [key, secretValue] of Object.entries(secrets)) {
      expect(
        serialized,
        `Expected secret for "${key}" to not appear verbatim in serialized log`,
      ).not.toContain(secretValue);
    }

    // Verify header paths are redacted to '[redacted]'
    const reqHeaders = (entry.req as { headers?: Record<string, string> })?.headers;
    expect(reqHeaders?.authorization).toBe('[redacted]');
    expect(reqHeaders?.cookie).toBe('[redacted]');
    expect(reqHeaders?.['x-api-key']).toBe('[redacted]');

    const resHeaders = (entry.res as { headers?: Record<string, string> })?.headers;
    expect(resHeaders?.['set-cookie']).toBe('[redacted]');

    // Verify root-level values are redacted to '[redacted]'
    expect(entry.DATABASE_URL).toBe('[redacted]');
    expect(entry.SUPABASE_SERVICE_ROLE_KEY).toBe('[redacted]');
    expect(entry.WALLET_NONCE_SECRET).toBe('[redacted]');
    expect(entry.S3_ACCESS_KEY_ID).toBe('[redacted]');
    expect(entry.S3_SECRET_ACCESS_KEY).toBe('[redacted]');
    expect(entry.password).toBe('[redacted]');
    expect(entry.secret).toBe('[redacted]');
    expect(entry.token).toBe('[redacted]');
    expect(entry.privateKey).toBe('[redacted]');

    // Verify nested wildcard paths are redacted to '[redacted]'
    const nested = entry.nested as Record<string, unknown>;
    expect(nested.password).toBe('[redacted]');
    expect(nested.secret).toBe('[redacted]');
    expect(nested.token).toBe('[redacted]');
    expect(nested.privateKey).toBe('[redacted]');
    expect(nested.authorization).toBe('[redacted]');

    // Verify safe fields remain intact
    expect(entry.publicField).toBe('safe-public-data');
    expect(serialized).toContain('safe-public-data');
  });

  it('initializes seamlessly inside a Fastify instance', async () => {
    const app = Fastify({
      logger: buildLoggerOptions('test'),
    });

    expect(app.log).toBeDefined();
    expect(typeof app.log.info).toBe('function');
    await app.close();
  });
});
