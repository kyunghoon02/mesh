import { useEffect, useMemo, useState } from "react";
import {
  callRpc,
  type ChainConfig,
  type ConfirmDeployResult,
  type PasskeyRecord,
  type PrepareDeployResult,
  type PrepareRecoverResult,
  type SetPasskeyResult
} from "./rpc";
import { makeRecoveryChallenge, registerPasskey, signWithPasskey } from "./webauthn";

type ViewState = "idle" | "pending" | "active" | "confirm" | "error";
type SidebarTab = "dashboard" | "settings";

type EthereumProvider = {
  request(args: { method: string; params?: unknown[] | Record<string, unknown> }): Promise<unknown>;
};

declare global {
  interface Window {
    ethereum?: EthereumProvider;
  }
}

function parseForcedState(): ViewState | null {
  const raw = new URLSearchParams(window.location.search).get("state");
  if (raw === "pending" || raw === "active" || raw === "confirm" || raw === "error" || raw === "idle") {
    return raw;
  }
  return null;
}

function parseTabHash(): SidebarTab {
  const raw = window.location.hash.replace("#", "").toLowerCase();
  if (raw === "settings") return raw;
  return "dashboard";
}

function statusToView(status: string | undefined): ViewState {
  if (!status) return "idle";
  if (status === "pending") return "pending";
  if (status === "active") return "active";
  if (status === "failed") return "error";
  return "idle";
}

function shorten(hex: string | null | undefined): string {
  if (!hex) return "-";
  if (hex.length < 12) return hex;
  return `${hex.slice(0, 8)}...${hex.slice(-6)}`;
}

async function getWalletAccount(forceSelect = false): Promise<string | null> {
  if (!window.ethereum) return null;
  if (forceSelect) {
    try {
      await window.ethereum.request({
        method: "wallet_requestPermissions",
        params: [{ eth_accounts: {} }]
      });
    } catch (error) {
      // Ignore and fall back to eth_requestAccounts.
    }
  }
  const accounts = (await window.ethereum.request({
    method: "eth_requestAccounts"
  })) as string[];
  return Array.isArray(accounts) && accounts.length > 0 ? accounts[0] : null;
}

function App() {
  const forcedState = useMemo(parseForcedState, []);

  const [activeTab, setActiveTab] = useState<SidebarTab>(() => parseTabHash());

  const [owner, setOwner] = useState("");
  const [passkeyHex, setPasskeyHex] = useState("");
  const [factory, setFactory] = useState("");
  const [rpcUrl, setRpcUrl] = useState("");
  const [txHash, setTxHash] = useState("");
  const [runtimeChainId, setRuntimeChainId] = useState<number | null>(null);
  const [settingsChainId, setSettingsChainId] = useState("");
  const [supportsPasskey, setSupportsPasskey] = useState(false);
  const [newOwner, setNewOwner] = useState("");
  const [recoveryAuthData, setRecoveryAuthData] = useState("");
  const [recoveryClientData, setRecoveryClientData] = useState("");
  const [recoverySignature, setRecoverySignature] = useState("");

  const [chainConfig, setChainConfig] = useState<ChainConfig | null>(null);
  const [predictedAddress, setPredictedAddress] = useState<string>("");
  const [loading, setLoading] = useState(false);
  const [errorText, setErrorText] = useState("");
  const [settingsNotice, setSettingsNotice] = useState("");
  const [passkeyNotice, setPasskeyNotice] = useState("");

  const [logLines, setLogLines] = useState<string[]>([]);
  const [viewState, setViewState] = useState<ViewState>("idle");

  const appendLog = (line: string): void => {
    setLogLines((prev) => [`[${new Date().toLocaleTimeString()}] ${line}`, ...prev].slice(0, 30));
  };

  const setTab = (tab: SidebarTab): void => {
    setActiveTab(tab);
    window.history.replaceState(null, "", `#${tab}`);
  };

  const refreshChainConfig = async (): Promise<void> => {
    try {
      let result: ChainConfig | null = null;
      try {
        result = await callRpc<ChainConfig | null>("mesh_getChainConfig", [{}]);
      } catch (innerError) {
        const message = (innerError as Error).message;
        if (!message.includes("missing chain_id")) throw innerError;

        const chainHex = (await callRpc<string>("eth_chainId")) || "0x0";
        const chainId = Number.parseInt(chainHex, 16);
        if (!Number.isNaN(chainId)) {
          setRuntimeChainId(chainId);
          result = await callRpc<ChainConfig | null>("mesh_getChainConfig", [{ chain_id: chainHex }]);
        }
      }

      setChainConfig(result);
      if (result) {
        setRuntimeChainId(result.chain_id);
        setViewState(statusToView(result.status));
        setSupportsPasskey(result.supports_passkey ?? false);
        if (!factory && result.factory_address) setFactory(result.factory_address);
        if (!rpcUrl && result.rpc_url) setRpcUrl(result.rpc_url);
        if (result.sca_address) setPredictedAddress(result.sca_address);
      }
    } catch (error) {
      appendLog(`mesh_getChainConfig failed: ${(error as Error).message}`);
    }
  };

  useEffect(() => {
    void refreshChainConfig();

    const onHashChange = (): void => setActiveTab(parseTabHash());
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  useEffect(() => {
    if (!settingsChainId) {
      if (chainConfig?.chain_id) {
        setSettingsChainId(chainConfig.chain_id.toString());
      } else if (runtimeChainId) {
        setSettingsChainId(runtimeChainId.toString());
      }
    }
  }, [chainConfig, runtimeChainId, settingsChainId]);

  const effectiveViewState = forcedState ?? viewState;
  const isPending = effectiveViewState === "pending";
  const isActive = effectiveViewState === "active";
  const isConfirm = effectiveViewState === "confirm";
  const isError = effectiveViewState === "error";

  const handleRegisterPasskey = async (): Promise<void> => {
    setErrorText("");
    setSettingsNotice("");
    setPasskeyNotice("");
    if (!supportsPasskey) {
      setErrorText("Passkey is not supported on this chain.");
      return;
    }
    setLoading(true);
    try {
      let effectiveOwner = owner;
      if (!effectiveOwner) {
        effectiveOwner = (await getWalletAccount(true)) ?? "";
        if (!effectiveOwner) {
          throw new Error("Wallet connection required to store passkey.");
        }
        setOwner(effectiveOwner);
      }
      const chainId = chainConfig?.chain_id ?? runtimeChainId;
      if (!chainId) {
        throw new Error("Chain ID is required to store passkey.");
      }

      const result = await registerPasskey({
        rpId: (import.meta.env.VITE_RP_ID as string | undefined) ?? undefined,
        rpName: (import.meta.env.VITE_RP_NAME as string | undefined) ?? undefined,
        userName: effectiveOwner || "mesh-user",
        displayName: effectiveOwner || "mesh-user"
      });
      setPasskeyHex(result.publicKeyHex);

      const chainHex = `0x${chainId.toString(16)}`;
      const setPasskeyResult = await callRpc<SetPasskeyResult>("mesh_setPasskey", [
        {
          owner: effectiveOwner,
          chain_id: chainHex,
          passkey_pubkey: result.publicKeyHex,
          credential_id: result.credentialId,
          rp_id: result.rpId,
          from: effectiveOwner
        }
      ]);

      if (setPasskeyResult.warning) {
        appendLog(`passkey warning: ${setPasskeyResult.warning}`);
      }

      if (setPasskeyResult.request && setPasskeyResult.request.params?.length) {
        if (!window.ethereum) {
          appendLog("MetaMask not connected. Please submit the on-chain passkey tx manually in your wallet.");
        } else {
          try {
            await window.ethereum.request({
              method: setPasskeyResult.request.method,
              params: setPasskeyResult.request.params as unknown[]
            });
            appendLog("passkey on-chain set tx submitted");
          } catch (error) {
            const message = (error as Error).message;
            appendLog(`mesh_setPasskey tx submission failed: ${message}`);
          }
        }
      } else {
        appendLog("Passkey saved. On-chain update is available after SCA becomes active.");
      }

      setPasskeyNotice("Saved.");
      appendLog("passkey registered");
    } catch (error) {
      const message = (error as Error).message;
      setErrorText(message);
      setPasskeyNotice("");
      appendLog(`passkey registration failed: ${message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleLoadPasskey = async (): Promise<void> => {
    setErrorText("");
    setSettingsNotice("");
    setPasskeyNotice("");
    if (!supportsPasskey) {
      setErrorText("Passkey is not supported on this chain.");
      return;
    }
    try {
      let effectiveOwner = owner;
      if (!effectiveOwner) {
        effectiveOwner = (await getWalletAccount(true)) ?? "";
        if (!effectiveOwner) {
          throw new Error("Wallet connection required to load passkey.");
        }
        setOwner(effectiveOwner);
      }
      const chainId = chainConfig?.chain_id ?? runtimeChainId;
      if (!chainId) {
        throw new Error("Chain ID is required to load passkey.");
      }

      const record = await callRpc<PasskeyRecord | null>("mesh_getPasskey", [
        { owner: effectiveOwner, chain_id: `0x${chainId.toString(16)}` }
      ]);

      if (!record?.passkey_pubkey) {
        throw new Error("No passkey stored for this account.");
      }
      setPasskeyHex(record.passkey_pubkey);
      setPasskeyNotice("Loaded.");
    } catch (error) {
      const message = (error as Error).message;
      setErrorText(message);
      setPasskeyNotice("");
    }
  };

  const confirmDeployLoop = async (
    hash: string,
    scaAddress?: string,
    factoryAddress?: string
  ): Promise<void> => {
    setViewState("pending");
    for (let i = 0; i < 10; i += 1) {
      const chainId = chainConfig?.chain_id ?? runtimeChainId;
      const result = await callRpc<ConfirmDeployResult>("mesh_confirmDeploy", [
        {
          chain_id: chainId ? `0x${chainId.toString(16)}` : undefined,
          tx_hash: hash,
          sca_address: scaAddress,
          factory_address: factoryAddress,
          from: owner || undefined
        }
      ]);

      if (result.sca_address) {
        setPredictedAddress(result.sca_address);
      }
      if (result.factory_address) {
        setFactory(result.factory_address);
      }
      appendLog(`mesh_confirmDeploy status: ${result.status}`);
      if (result.status === "active") {
        setViewState("active");
        if (result.setpasskey_request && owner) {
          if (!window.ethereum) {
            appendLog("SetPasskey tx ready. Connect wallet to submit.");
          } else {
            try {
              await window.ethereum.request({
                method: result.setpasskey_request.method,
                params: result.setpasskey_request.params
              });
              appendLog("setPasskey tx submitted automatically.");
            } catch (error) {
              appendLog(`setPasskey submission failed: ${(error as Error).message}`);
            }
          }
        }
        await refreshChainConfig();
        return;
      }
      if (result.status === "failed") {
        setViewState("error");
        throw new Error("Deploy transaction failed.");
      }
      await new Promise((resolve) => setTimeout(resolve, 2500));
    }
    setViewState("confirm");
  };

  const handlePrepareDeploy = async (): Promise<void> => {
    setErrorText("");
    setSettingsNotice("");
    let effectiveOwner = owner;
    if (!effectiveOwner) {
      effectiveOwner = (await getWalletAccount(true)) ?? "";
      if (!effectiveOwner) {
        setErrorText("Owner address is required.");
        return;
      }
      setOwner(effectiveOwner);
    }
    if (supportsPasskey && !passkeyHex) {
      const chainId = chainConfig?.chain_id ?? runtimeChainId;
      if (!chainId) {
        setErrorText("Chain ID is required to load passkey.");
        return;
      }
      try {
        setPasskeyNotice("Loading saved passkey...");
        const record = await callRpc<PasskeyRecord | null>("mesh_getPasskey", [
          { owner: effectiveOwner, chain_id: `0x${chainId.toString(16)}` }
        ]);
        if (record?.passkey_pubkey) {
          setPasskeyHex(record.passkey_pubkey);
          setPasskeyNotice("Loaded.");
        } else {
          setPasskeyNotice("");
          setErrorText("Passkey pubkey(hex) is required.");
          return;
        }
      } catch (error) {
        setPasskeyNotice("");
        setErrorText((error as Error).message || "Passkey pubkey(hex) is required.");
        return;
      }
    }

    setLoading(true);
    setViewState("pending");
    appendLog("mesh_prepareDeploy request");

    try {
    const params: Record<string, string> = {
      owner: effectiveOwner,
      from: effectiveOwner
    };
    if (supportsPasskey && passkeyHex) {
      params.passkey_pubkey = passkeyHex;
    }
    if (factory) params.factory = factory;

      const prepared = await callRpc<PrepareDeployResult>("mesh_prepareDeploy", [params]);
      if (prepared.predicted_address) setPredictedAddress(prepared.predicted_address);
      setPasskeyHex("");
      appendLog("mesh_prepareDeploy success");

      if (!window.ethereum) {
        appendLog("MetaMask not found, switched to manual confirm");
        setViewState("confirm");
        return;
      }

      const result = (await window.ethereum.request({
        method: "eth_sendTransaction",
        params: [prepared.tx]
      })) as string;

      if (!result) throw new Error("No transaction hash returned.");
      setTxHash(result);
      appendLog(`tx sent: ${result}`);

      await confirmDeployLoop(result, prepared.predicted_address, prepared.tx.to);
    } catch (error) {
      const message = (error as Error).message;
      setErrorText(message);
      appendLog(`prepareDeploy failed: ${message}`);
      setViewState("error");
    } finally {
      setLoading(false);
    }
  };

  const handlePrepareRecover = async (): Promise<void> => {
    setErrorText("");
    setSettingsNotice("");

    if (!supportsPasskey) {
      setErrorText("Passkey is not supported on this chain.");
      return;
    }
    if (!newOwner) {
      setErrorText("New owner address is required.");
      return;
    }
    if (!recoveryAuthData || !recoveryClientData || !recoverySignature) {
      setErrorText("authenticator data, client data, and signature are required.");
      return;
    }

    let effectiveOwner = owner;
    if (!effectiveOwner) {
      effectiveOwner = (await getWalletAccount(true)) ?? "";
      if (!effectiveOwner) {
        setErrorText("Wallet connection required.");
        return;
      }
      setOwner(effectiveOwner);
    }

    const chainId = chainConfig?.chain_id ?? runtimeChainId;
    if (!chainId) {
      setErrorText("Chain ID is required.");
      return;
    }

    setLoading(true);
    appendLog("mesh_prepareRecover request");
    try {
      const chainHex = `0x${chainId.toString(16)}`;
      const prepared = await callRpc<PrepareRecoverResult>("mesh_prepareRecover", [
        {
          owner: effectiveOwner,
          chain_id: chainHex,
          new_owner: newOwner,
          authenticator_data: recoveryAuthData,
          client_data_json: recoveryClientData,
          signature: recoverySignature,
          from: effectiveOwner
        }
      ]);
      appendLog("mesh_prepareRecover success");

      if (window.ethereum) {
        await window.ethereum.request({
          method: prepared.request.method,
          params: prepared.request.params
        });
        appendLog("recover tx submitted");
      } else {
        appendLog("MetaMask not found. Save tx manually.");
      }
      setViewState("pending");
    } catch (error) {
      const message = (error as Error).message;
      setErrorText(message);
      setViewState("error");
      appendLog(`mesh_prepareRecover failed: ${message}`);
    } finally {
      setLoading(false);
    }
  };

  const handlePrepareRecoverByPasskey = async (): Promise<void> => {
    setErrorText("");
    setSettingsNotice("");

    if (!supportsPasskey) {
      setErrorText("Passkey is not supported on this chain.");
      return;
    }
    if (!newOwner) {
      setErrorText("New owner address is required.");
      return;
    }

    let effectiveOwner = owner;
    if (!effectiveOwner) {
      effectiveOwner = (await getWalletAccount(true)) ?? "";
      if (!effectiveOwner) {
        setErrorText("Wallet connection required.");
        return;
      }
      setOwner(effectiveOwner);
    }

    const chainId = chainConfig?.chain_id ?? runtimeChainId;
    if (!chainId) {
      setErrorText("Chain ID is required.");
      return;
    }

    const chainHex = `0x${chainId.toString(16)}`;
    const record = await callRpc<PasskeyRecord | null>("mesh_getPasskey", [
      { owner: effectiveOwner, chain_id: chainHex }
    ]);
    if (!record?.passkey_pubkey) {
      setErrorText("Passkey is not registered.");
      return;
    }

    const challenge = makeRecoveryChallenge({
      owner: effectiveOwner,
      newOwner,
      chainId
    });

    setLoading(true);
    appendLog("mesh_prepareRecover request");
    try {
      const assertion = await signWithPasskey({
        challenge,
        rpId: record.rp_id || (import.meta.env.VITE_RP_ID as string | undefined),
        credentialId: record.credential_id || undefined,
        userVerification: "required"
      });

      setRecoveryAuthData(assertion.authenticatorDataHex);
      setRecoveryClientData(assertion.clientDataJSONHex);
      setRecoverySignature(assertion.signatureHex);

      const prepared = await callRpc<PrepareRecoverResult>("mesh_prepareRecover", [
        {
          owner: effectiveOwner,
          chain_id: chainHex,
          new_owner: newOwner,
          authenticator_data: assertion.authenticatorDataHex,
          client_data_json: assertion.clientDataJSONHex,
          signature: assertion.signatureHex,
          from: effectiveOwner
        }
      ]);
      appendLog("mesh_prepareRecover success");

      if (window.ethereum) {
        await window.ethereum.request({
          method: prepared.request.method,
          params: prepared.request.params
        });
        appendLog("recover tx submitted");
      } else {
        appendLog("MetaMask not found. Save tx manually.");
      }
      setViewState("pending");
    } catch (error) {
      const message = (error as Error).message;
      setErrorText(message);
      setViewState("error");
      appendLog(`mesh_prepareRecover failed: ${message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleConfirmDeploy = async (): Promise<void> => {
    setErrorText("");
    setSettingsNotice("");
    if (!txHash) {
      setErrorText("tx hash is required for confirm.");
      return;
    }
    setLoading(true);
    appendLog("mesh_confirmDeploy manual request");
    try {
      await confirmDeployLoop(txHash, predictedAddress || undefined, factory || undefined);
    } catch (error) {
      const message = (error as Error).message;
      setErrorText(message);
      appendLog(`confirmDeploy failed: ${message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleConnectWallet = async (): Promise<void> => {
    setErrorText("");
    setSettingsNotice("");
    setPasskeyNotice("");
    try {
      const account = await getWalletAccount(true);
      if (!account) {
        throw new Error("Wallet connection cancelled.");
      }
      setOwner(account);
      appendLog(`Wallet connected: ${account}`);
    } catch (error) {
      const message = (error as Error).message;
      setErrorText(message);
    }
  };

  const handleSaveChainConfig = async (): Promise<void> => {
    setErrorText("");
    setSettingsNotice("");
    const rawChainId = settingsChainId.trim();
    let chainIdHex = "";
    if (rawChainId) {
      if (rawChainId.startsWith("0x")) {
        chainIdHex = rawChainId;
      } else if (/^\d+$/.test(rawChainId)) {
        chainIdHex = `0x${BigInt(rawChainId).toString(16)}`;
      }
    }

    const fallbackChainId = chainConfig?.chain_id ?? runtimeChainId;
    if (!chainIdHex && !fallbackChainId) {
      setErrorText("Chain ID is required to save config.");
      return;
    }
    if (!chainIdHex && fallbackChainId) {
      chainIdHex = `0x${fallbackChainId.toString(16)}`;
    }
    if (!rpcUrl.trim()) {
      setErrorText("RPC URL is required to save config.");
      return;
    }

    const params: Record<string, string | boolean> = {
      chain_id: chainIdHex,
      mode: chainConfig?.mode ?? "SCA",
      status: chainConfig?.status ?? "inactive",
      supports_passkey: supportsPasskey
    };

    if (chainConfig?.sca_address) params.sca_address = chainConfig.sca_address;
    else if (predictedAddress) params.sca_address = predictedAddress;
    params.rpc_url = rpcUrl.trim();

    try {
      await callRpc<boolean>("mesh_setChainConfig", [params]);
      setSettingsNotice("Saved.");
      appendLog("mesh_setChainConfig updated");
      await refreshChainConfig();
    } catch (error) {
      const message = (error as Error).message;
      setErrorText(message);
      setSettingsNotice("");
      appendLog(`mesh_setChainConfig failed: ${message}`);
    }
  };

  const renderDashboard = (): JSX.Element => (
    <>
      <section className="row two-col">
        <article className="card grow">
          <h2>Chain</h2>
          <p>Chain: {chainConfig?.chain_id ?? runtimeChainId ?? "-"}</p>
          <p>Mode: {chainConfig?.mode ?? "SCA"}</p>
          <p>Passkey: {chainConfig?.supports_passkey ? "Supported" : "EOA only"}</p>
          <p className={chainConfig?.status === "active" ? "success" : "danger"}>
            Status: {chainConfig?.status ?? "inactive"}
          </p>
        </article>

        <article className="card quick-actions">
          <h2>Actions</h2>
          <div className="button-row">
            <button className="btn btn-dark" type="button" onClick={handlePrepareDeploy} disabled={loading}>
              Prepare Deploy
            </button>
            <button className="btn btn-amber" type="button" onClick={handleConfirmDeploy} disabled={loading}>
              Confirm Deploy
            </button>
          </div>
          {errorText ? <p className="danger">{errorText}</p> : null}
        </article>
      </section>

      <section className="row">
        <article className="card grow">
          <h2>Activity</h2>
          {logLines.length === 0 ? <p>No recent events.</p> : null}
          {logLines.slice(0, 4).map((line) => (
            <p key={line}>{line}</p>
          ))}
        </article>
      </section>
    </>
  );

  const renderSettings = (): JSX.Element => (
    <section className="row two-col">
      <article className="card grow">
        <h2>RPC Profile</h2>
        <p className="muted">Target chain, RPC URL, and factory.</p>
        <div className="input-grid">
          <label>
            Chain ID
            <input
              value={settingsChainId}
              onChange={(e) => setSettingsChainId(e.target.value.trim())}
              placeholder="11155111"
            />
          </label>
          <label>
            RPC URL
            <input
              value={rpcUrl}
              onChange={(e) => setRpcUrl(e.target.value.trim())}
              placeholder="https://..."
              spellCheck={false}
            />
          </label>
          <label>
            Supports Passkey
            <input
              type="checkbox"
              checked={supportsPasskey}
              onChange={(e) => setSupportsPasskey(e.target.checked)}
            />
          </label>
          <label>
            Factory Address
            <input value={factory} readOnly />
          </label>
        </div>
        <div className="button-row">
          <button className="btn btn-soft" type="button" onClick={() => void refreshChainConfig()}>
            Refresh
          </button>
          <button className="btn btn-dark" type="button" onClick={handleSaveChainConfig} disabled={loading}>
            Save RPC Profile
          </button>
        </div>
        {errorText ? <p className="danger">{errorText}</p> : null}
        {settingsNotice ? <p className="success">{settingsNotice}</p> : null}
      </article>

        <article className="card side">
          <h2>Security</h2>
        <p className="muted">Passkey registration</p>
        {!supportsPasskey ? <p className="amber">This chain does not support passkey recovery. EOA only.</p> : null}
        <p>Owner: {shorten(owner)}</p>
        <div className="input-grid">
          <label>
            Passkey (hex)
            <input
              value={passkeyHex}
              onChange={(e) => setPasskeyHex(e.target.value.trim())}
              autoComplete="off"
              spellCheck={false}
              placeholder="04..."
              disabled={!supportsPasskey || loading}
            />
          </label>
        </div>
        <div className="button-row">
          <button className="btn btn-soft" type="button" onClick={handleConnectWallet} disabled={loading}>
            Connect Wallet
          </button>
          <button
            className="btn btn-dark"
            type="button"
            onClick={handleRegisterPasskey}
            disabled={!supportsPasskey || loading}
          >
            Register Passkey
          </button>
          <button
            className="btn btn-soft"
            type="button"
            onClick={handleLoadPasskey}
            disabled={!supportsPasskey || loading}
          >
            Load Saved
          </button>
        </div>
        {errorText ? <p className="danger">{errorText}</p> : null}
        {passkeyNotice ? (
          <p className={passkeyNotice.toLowerCase().includes("load") ? "amber" : "success"}>
            {passkeyNotice.toLowerCase().includes("load") ? (
              <span className="spinner" aria-hidden>
                <span />
              </span>
            ) : null}
            {passkeyNotice}
          </p>
        ) : null}

        <h2>Recovery</h2>
        <p className="muted">Prepare a recover tx with passkey data (authenticator signature).</p>
        <div className="input-grid">
          <label>
            New owner
            <input
              value={newOwner}
              onChange={(e) => setNewOwner(e.target.value.trim())}
              autoComplete="off"
              spellCheck={false}
              placeholder="0x..."
            />
          </label>
          <label>
            authenticatorData (hex)
            <input
              value={recoveryAuthData}
              onChange={(e) => setRecoveryAuthData(e.target.value.trim())}
              autoComplete="off"
              spellCheck={false}
              placeholder="0x..."
            />
          </label>
          <label>
            clientDataJSON (hex)
            <input
              value={recoveryClientData}
              onChange={(e) => setRecoveryClientData(e.target.value.trim())}
              autoComplete="off"
              spellCheck={false}
              placeholder="0x..."
            />
          </label>
          <label>
            signature (hex)
            <input
              value={recoverySignature}
              onChange={(e) => setRecoverySignature(e.target.value.trim())}
              autoComplete="off"
              spellCheck={false}
              placeholder="0x..."
            />
          </label>
        </div>
        <div className="button-row">
          <button
            className="btn btn-soft"
            type="button"
            onClick={handlePrepareRecover}
            disabled={!supportsPasskey || loading}
          >
            Prepare Recover
          </button>
          <button
            className="btn btn-dark"
            type="button"
            onClick={handlePrepareRecoverByPasskey}
            disabled={!supportsPasskey || loading}
          >
            Sign and Prepare Recover
          </button>
        </div>
      </article>
    </section>
  );

  return (
    <div className="page">
      <div className="dashboard">
        <aside className="sidebar">
          <div className="brand">
            <span className="logo" />
            <span className="brand-name">Mesh</span>
          </div>

          <p className="menu-title">MENU</p>
          <nav className="menu">
            <button className={`menu-item ${activeTab === "dashboard" ? "active" : ""}`} onClick={() => setTab("dashboard")} type="button">
              Dashboard
            </button>
            <button className={`menu-item ${activeTab === "settings" ? "active" : ""}`} onClick={() => setTab("settings")} type="button">
              Settings
            </button>
          </nav>

          <div className="status-box">
            <p>Relayer Online</p>
          </div>
        </aside>

        <main className="main">
          <header className="header">
            <h1>{activeTab === "settings" ? "Settings" : "Relayer Dashboard"}</h1>
            <div className="header-right">
              <span className="mode-pill">Local Mode</span>
              <span className="chain-meta">
                {chainConfig
                  ? `Chain ID: ${chainConfig.chain_id}`
                  : runtimeChainId
                    ? `Chain ID: ${runtimeChainId}`
                    : "Chain: unknown"}
              </span>
            </div>
          </header>

          {activeTab === "dashboard" ? renderDashboard() : null}
          {activeTab === "settings" ? renderSettings() : null}
        </main>

        <div className={`status-layer ${isPending || isActive || isError ? "visible" : ""}`}>
          <div className={`pending-banner ${isPending ? "show" : ""}`}>
            Deploying MeshVault... waiting for confirmations
          </div>
          <div className={`toast success-toast ${isActive ? "show" : ""}`}>
            <span className="dot success-dot" />
            <span>SCA activated successfully</span>
          </div>
          <div className={`toast error-toast ${isError ? "show" : ""}`}>
            <span className="dot error-dot" />
            <span>Deployment failed. Try again.</span>
          </div>
        </div>

        <div className={`overlay-layer ${isConfirm ? "visible" : ""}`}>
          <div className="overlay-bg" />
          <div className="modal">
            <h3>Confirm Tx</h3>
            <p>Please complete the transaction in MetaMask.</p>
            <div className="modal-info">
              <p>Chain: {chainConfig?.chain_id ?? "-"}</p>
              <p>Predicted SCA: {shorten(predictedAddress || chainConfig?.sca_address)}</p>
            </div>
            <div className="modal-actions">
              <button className="btn btn-soft" type="button" onClick={() => setViewState("idle")}>
                Close
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;
