import { PROTOCOL, WorkspaceClient } from "./generated.js";
import type { Handshake, HeadersLike, Transport } from "./generated.js";

export interface OperationIdentity {
  actorId: string;
  realmId: string;
}

export interface OperationConnection {
  baseUrl: string;
  token: string;
}

export class OperationRetiredError extends Error {
  constructor() {
    super("Runtime operation lifetime is retired");
    this.name = "OperationRetiredError";
  }
}

/**
 * Direct credential owner only. Captured fetch must dispatch immediately with the
 * supplied fixed target, credential and options. Wrappers that await before
 * forwarding or reselect hidden upstreams/credentials cannot qualify this fence.
 * Automatic browser requester activation remains unsupported.
 */
export class OperationHandle {
  readonly client: WorkspaceClient;
  private retired = false;
  private identity?: OperationIdentity;
  private negotiation?: Promise<OperationIdentity>;
  private captureHandshake?: (body: Uint8Array) => void;

  constructor({ baseUrl, token }: OperationConnection) {
    if (!baseUrl.trim() || !token.trim()) throw new Error("Runtime base and owned credential are required");
    const base = baseUrl.replace(/\/$/, "");
    const dispatch = globalThis.fetch.bind(globalThis);
    const transport: Transport = async (method, path, headers, body) => {
      this.assertActive();
      const capture = method === "POST" && path === "/v1/handshake" ? this.captureHandshake : undefined;
      if (capture) this.captureHandshake = undefined;
      try {
        // No await between the lifetime check and the captured transport dispatch.
        const response = await dispatch(`${base}${path}`, {
          method, headers, body: body as BodyInit | undefined, credentials: "omit", redirect: "error",
        });
        this.assertActive();
        if (response.status === 401 || response.status === 403 || response.status >= 500) this.retire();
        const bytes = new Uint8Array(await response.arrayBuffer());
        this.assertActive();
        if (response.status === 200) capture?.(bytes);
        const responseHeaders: HeadersLike = {};
        response.headers.forEach((value, key) => { responseHeaders[key] = value; });
        return { status: response.status, headers: responseHeaders, body: bytes };
      } catch (error) {
        this.retire();
        throw error;
      }
    };
    this.client = new WorkspaceClient(base, token, transport);
  }

  private assertActive(): void {
    if (this.retired) throw new OperationRetiredError();
  }

  readonly retire = (): void => {
    this.retired = true;
  };

  /** Local owned lifetime, never a claim that remote revocation is observable synchronously. */
  readonly isCurrentIdentity = (expected: OperationIdentity): boolean => {
    return !this.retired && !!this.identity
      && !!expected.actorId && !!expected.realmId
      && expected.actorId === this.identity.actorId && expected.realmId === this.identity.realmId;
  };

  async negotiate(clientName: string, clientVersion: string, requestedScopes: string[]): Promise<OperationIdentity> {
    this.assertActive();
    if (this.negotiation) throw new Error("Runtime renegotiation requires a new operation binding");
    this.negotiation = this.open(clientName, clientVersion, [...requestedScopes]);
    const identity = await this.negotiation;
    this.assertActive();
    return { ...identity };
  }

  private async open(clientName: string, clientVersion: string, requestedScopes: string[]): Promise<OperationIdentity> {
    try {
      const health = await this.client.health();
      let capturedHandshake: Handshake | undefined;
      // Parse owned response bytes before generated handshakeInfo exposes its mutable alias.
      this.captureHandshake = bytes => { capturedHandshake = JSON.parse(new TextDecoder().decode(bytes)); };
      await this.client.handshake(clientName, clientVersion, requestedScopes);
      const handshake = capturedHandshake;
      const realm = await this.client.getRealm();
      this.assertActive();
      if (health.status !== "ok" || health.protocol !== PROTOCOL || !handshake || handshake.protocol !== PROTOCOL
        || typeof health.schema_digest !== "string" || !health.schema_digest.trim()
        || typeof handshake.schema_digest !== "string" || !handshake.schema_digest.trim()
        || health.schema_digest !== handshake.schema_digest
        || typeof handshake.actor_id !== "string" || !handshake.actor_id.trim()
        || typeof handshake.realm_id !== "string" || !handshake.realm_id.trim()
        || typeof realm.realm_id !== "string" || !realm.realm_id.trim()
        || realm.realm_id !== handshake.realm_id
        || !Array.isArray(handshake.scopes) || handshake.scopes.some(scope => typeof scope !== "string")
        || requestedScopes.some(scope => !handshake.scopes.includes(scope))) {
        throw new Error("Runtime operation negotiation did not establish the requested identity and scopes");
      }
      this.identity = { actorId: handshake.actor_id, realmId: handshake.realm_id };
      return this.identity;
    } catch (error) {
      this.retire();
      throw error;
    } finally {
      this.captureHandshake = undefined;
    }
  }

  readonly getRecoverableIdentity = async (): Promise<OperationIdentity> => {
    this.assertActive();
    if (!this.negotiation) throw new Error("Runtime operation has not negotiated");
    const identity = await this.negotiation;
    this.assertActive();
    return { ...identity };
  };
}

/** The connector calls bind BEFORE switching base, credential, transport or reconnecting. */
export class OperationHost {
  private current?: OperationHandle;
  private disposed = false;

  bind(connection: OperationConnection): OperationHandle {
    this.current?.retire();
    this.current = undefined;
    if (this.disposed) throw new OperationRetiredError();
    const handle = new OperationHandle(connection);
    this.current = handle;
    return handle;
  }

  dispose(): void {
    this.disposed = true;
    this.current?.retire();
    this.current = undefined;
  }
}
