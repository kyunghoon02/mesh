export type JsonRpcError = {
  code: number;
  message: string;
};

type JsonRpcResponse<T> = {
  jsonrpc: "2.0";
  id: number;
  result?: T;
  error?: JsonRpcError;
};

const DEFAULT_RPC_URL = "/rpc";

function getRpcUrl(): string {
  const envUrl = import.meta.env.VITE_RELAYER_RPC as string | undefined;
  return envUrl && envUrl.trim() ? envUrl : DEFAULT_RPC_URL;
}

let nextId = 1;

export async function callRpc<T>(method: string, params?: unknown): Promise<T> {
  const id = nextId++;
  const payload: Record<string, unknown> = {
    jsonrpc: "2.0",
    id,
    method
  };
  if (params !== undefined) {
    payload.params = params;
  }

  const response = await fetch(getRpcUrl(), {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(payload)
  });

  if (!response.ok) {
    throw new Error(`RPC HTTP error: ${response.status}`);
  }

  const data = (await response.json()) as JsonRpcResponse<T>;
  if (data.error) {
    throw new Error(data.error.message);
  }
  if (data.result === undefined) {
    throw new Error("RPC result is undefined");
  }
  return data.result;
}

export type ChainConfig = {
  chain_id: number;
  mode: string;
  sca_address: string | null;
  factory_address: string | null;
  rpc_url: string | null;
  supports_passkey: boolean;
  status: string;
  updated_at: string;
};

export type PrepareDeployResult = {
  tx: Record<string, string>;
  request: Record<string, unknown>;
  predicted_address?: string;
};

export type SetPasskeyResult = {
  stored: boolean;
  warning?: string;
  tx?: Record<string, string>;
  request?: {
    method: string;
    params: Array<unknown>;
    jsonrpc: "2.0";
    id: number;
  };
};

export type RpcRequest = {
  method: string;
  params: Array<unknown>;
  jsonrpc: "2.0";
  id: number;
};

export type PrepareRecoverResult = {
  tx: Record<string, string>;
  request: {
    method: string;
    params: Array<unknown>;
    jsonrpc: "2.0";
    id: number;
  };
};

export type ConfirmDeployResult = {
  chain_id: number;
  status: "active" | "failed" | "pending";
  sca_address?: string | null;
  factory_address?: string | null;
  setpasskey_request?: RpcRequest;
};

export type PasskeyRecord = {
  owner: string;
  chain_id: number;
  passkey_pubkey: string;
  credential_id: string | null;
  rp_id: string | null;
  updated_at: string;
};
