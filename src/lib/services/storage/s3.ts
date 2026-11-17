import { AwsClient } from "aws4fetch";

import { readEnv, type EnvSource } from "../../utils/env.ts";
import { assertServiceConfig } from "../service-config.ts";
import {
  normalizeStorageKey,
  type StorageObjectHead,
  StorageObjectNotFoundError,
  type StorageService,
} from "./types.ts";

// Storage in any S3-compatible bucket (Cloudflare R2, Backblaze B2, AWS S3,
// Supabase Storage). The bucket is private: every read goes through the app,
// which checks who is asking first.
//
//   S3_ENDPOINT           https://<account>.r2.cloudflarestorage.com
//   S3_BUCKET             the bucket's name
//   S3_ACCESS_KEY_ID      \ an access key allowed to read and write objects
//   S3_SECRET_ACCESS_KEY  /
//   S3_REGION             optional, "auto" by default (what R2 expects)

export const S3_ENV_KEYS = [
  "S3_ENDPOINT",
  "S3_BUCKET",
  "S3_ACCESS_KEY_ID",
  "S3_SECRET_ACCESS_KEY",
] as const;

type CreateS3StorageServiceOptions = {
  env?: EnvSource;
  /** Replaced in tests. */
  fetchImpl?: typeof fetch;
};

function objectUrl(endpoint: string, bucket: string, key: string): string {
  const encodedKey = key
    .split("/")
    .map((segment) => encodeURIComponent(segment))
    .join("/");

  return `${endpoint.replace(/\/+$/, "")}/${encodeURIComponent(bucket)}/${encodedKey}`;
}

function parseLength(value: string | null): number | undefined {
  const length = Number(value);

  return value !== null && Number.isFinite(length) ? length : undefined;
}

export function createS3StorageService({
  env = process.env,
  fetchImpl,
}: CreateS3StorageServiceOptions = {}): StorageService {
  assertServiceConfig("storage", S3_ENV_KEYS, env);

  const endpoint = readEnv(env, "S3_ENDPOINT")!;
  const bucket = readEnv(env, "S3_BUCKET")!;
  const client = new AwsClient({
    accessKeyId: readEnv(env, "S3_ACCESS_KEY_ID")!,
    region: readEnv(env, "S3_REGION") ?? "auto",
    secretAccessKey: readEnv(env, "S3_SECRET_ACCESS_KEY")!,
    service: "s3",
  });

  function request(key: string, init: RequestInit): Promise<Response> {
    const url = objectUrl(endpoint, bucket, key);

    return fetchImpl
      ? client.sign(url, init).then((signed) => fetchImpl(signed))
      : client.fetch(url, init);
  }

  async function failed(response: Response, action: string): Promise<Error> {
    const detail = (await response.text().catch(() => "")).slice(0, 300);

    return new Error(
      `Storage ${action} failed (HTTP ${String(response.status)}): ${detail}`,
    );
  }

  async function headObject(key: string): Promise<StorageObjectHead> {
    const normalizedKey = normalizeStorageKey(key);
    const response = await request(normalizedKey, { method: "HEAD" });

    if (response.status === 404) {
      return { bucketName: bucket, exists: false, key: normalizedKey };
    }

    if (!response.ok) {
      throw await failed(response, "head");
    }

    return {
      bucketName: bucket,
      contentLength: parseLength(response.headers.get("content-length")),
      contentType: response.headers.get("content-type") ?? undefined,
      etag: response.headers.get("etag") ?? undefined,
      exists: true,
      key: normalizedKey,
    };
  }

  async function fetchObject(key: string) {
    const normalizedKey = normalizeStorageKey(key);
    const response = await request(normalizedKey, { method: "GET" });

    if (response.status === 404) {
      throw new StorageObjectNotFoundError(normalizedKey);
    }

    if (!response.ok || !response.body) {
      throw await failed(response, "read");
    }

    return { normalizedKey, response, stream: response.body };
  }

  return {
    async deleteObject(key) {
      const response = await request(normalizeStorageKey(key), {
        method: "DELETE",
      });

      // Deleting what is not there is not a failure.
      if (!response.ok && response.status !== 404) {
        throw await failed(response, "delete");
      }
    },
    async getObject(key) {
      const { normalizedKey, response } = await fetchObject(key);
      const body = new Uint8Array(await response.arrayBuffer());

      return {
        body,
        bucketName: bucket,
        contentLength: body.byteLength,
        contentType: response.headers.get("content-type") ?? undefined,
        etag: response.headers.get("etag") ?? undefined,
        key: normalizedKey,
      };
    },
    async getObjectStream(key) {
      const { normalizedKey, response, stream } = await fetchObject(key);

      return {
        bucketName: bucket,
        contentLength: parseLength(response.headers.get("content-length")),
        contentType: response.headers.get("content-type") ?? undefined,
        key: normalizedKey,
        stream,
      };
    },
    headObject,
    async putObject(input) {
      const normalizedKey = normalizeStorageKey(input.key);
      const response = await request(normalizedKey, {
        body: input.body as BodyInit,
        headers: {
          "content-type": input.contentType,
          // The store itself refuses a second write: of two writers that
          // arrive together, exactly one is kept.
          ...(input.keepExisting ? { "if-none-match": "*" } : {}),
        },
        method: "PUT",
      });

      // 412: something is already stored here, which is what was asked for.
      if (!response.ok && !(input.keepExisting && response.status === 412)) {
        throw await failed(response, "write");
      }

      return { bucketName: bucket, key: normalizedKey };
    },
  };
}
