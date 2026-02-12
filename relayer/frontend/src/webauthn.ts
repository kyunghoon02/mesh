import { decode, decodeMultiple } from "cbor-x";

type CoseKey = Map<number, unknown> | Record<string, unknown>;

function toHex(bytes: Uint8Array): string {
  return `0x${Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")}`;
}

function toUint8(value: unknown): Uint8Array {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (Array.isArray(value)) return new Uint8Array(value);
  throw new Error("Unsupported binary format");
}

function decodeCbor(buffer: Uint8Array): unknown {
  try {
    return decode(buffer);
  } catch (error) {
    const items: unknown[] = [];
    decodeMultiple(buffer, (item) => items.push(item));
    if (items.length === 0) throw error;
    return items[0];
  }
}

function readCoseParam(cose: CoseKey, key: number): Uint8Array {
  if (cose instanceof Map) {
    return toUint8(cose.get(key));
  }
  const direct = (cose as Record<string, unknown>)[key as unknown as string];
  if (direct) return toUint8(direct);
  const alt = (cose as Record<string, unknown>)[String(key)];
  return toUint8(alt);
}

function extractPublicKeyFromAuthData(authData: Uint8Array): Uint8Array {
  if (authData.length < 37) {
    throw new Error("Invalid authData");
  }
  const flags = authData[32];
  const hasAttestedData = (flags & 0x40) !== 0;
  if (!hasAttestedData) {
    throw new Error("Attested credential data missing");
  }

  let offset = 37;
  offset += 16;
  const credentialIdLength = (authData[offset] << 8) | authData[offset + 1];
  offset += 2 + credentialIdLength;

  const coseKeyBytes = authData.slice(offset);
  const cose = decodeCbor(coseKeyBytes) as CoseKey;
  const x = readCoseParam(cose, -2);
  const y = readCoseParam(cose, -3);

  const raw = new Uint8Array(1 + x.length + y.length);
  raw[0] = 0x04;
  raw.set(x, 1);
  raw.set(y, 1 + x.length);
  return raw;
}

function randomBytes(size: number): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(new ArrayBuffer(size)) as Uint8Array<ArrayBuffer>;
  crypto.getRandomValues(bytes);
  return bytes;
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  bytes.forEach((b) => {
    binary += String.fromCharCode(b);
  });
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export async function registerPasskey(options?: {
  rpId?: string;
  rpName?: string;
  userName?: string;
  displayName?: string;
}): Promise<{ publicKeyHex: string; credentialId: string; rpId: string }> {
  if (!window.PublicKeyCredential || !navigator.credentials?.create) {
    throw new Error("WebAuthn is not supported in this browser.");
  }

  const rpId = options?.rpId ?? window.location.hostname;
  const rpName = options?.rpName ?? "Mesh Relayer";
  const userName = options?.userName ?? "mesh-user";
  const displayName = options?.displayName ?? userName;

  const publicKey: PublicKeyCredentialCreationOptions = {
    rp: {
      id: rpId,
      name: rpName
    },
    user: {
      id: randomBytes(16),
      name: userName,
      displayName
    },
    challenge: randomBytes(32),
    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    timeout: 60000,
    attestation: "none",
    authenticatorSelection: {
      userVerification: "preferred"
    }
  };

  const credential = (await navigator.credentials.create({
    publicKey
  })) as PublicKeyCredential;

  if (!credential) {
    throw new Error("Passkey registration cancelled");
  }

  const response = credential.response as AuthenticatorAttestationResponse;
  const credentialId = toBase64Url(new Uint8Array(credential.rawId));
  const attestationObject = new Uint8Array(response.attestationObject);
  const decoded = decodeCbor(attestationObject) as { authData: Uint8Array };
  const authData = toUint8(decoded.authData);
  const rawKey = extractPublicKeyFromAuthData(authData);

  return { publicKeyHex: toHex(rawKey), credentialId, rpId };
}
