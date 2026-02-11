import { useEffect, useMemo, useState } from "react";
import { callRpc, type ChainConfig, type ConfirmDeployResult, type PrepareDeployResult } from "./rpc";

type ViewState = "idle" | "pending" | "active" | "confirm" | "error";
type SidebarTab = "dashboard" | "chains" | "passkeys" | "logs";

type EthereumProvider = {
  request(args: { method: string; params?: unknown[] | Record<string, unknown> }): Promise<unknown>;
};

declare global {
  interface Window {
    ethereum?: EthereumProvider;
  }
}

const SAMPLE_PASSKEY =
  "0x04b64fa57d6f9691029c7573f861f54b50e26f5d0b6f3120f1a3bc6f0e3b6f17cbb2d5ef829f39ad0f9c5e4f66f3d2dce62ad119cf4a74976f36af1f8a44d0e7d1";

function parseForcedState(): ViewState | null {
  const raw = new URLSearchParams(window.location.search).get("state");
  if (raw === "pending" || raw === "active" || raw === "confirm" || raw === "error" || raw === "idle") {
    return raw;
  }
  return null;
}

function parseTabHash(): SidebarTab {
  const raw = window.location.hash.replace("#", "").toLowerCase();
  if (raw === "chains" || raw === "passkeys" || raw === "logs") return raw;
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

async function getWalletAccount(): Promise<string | null> {
  if (!window.ethereum) return null;
  const accounts = (await window.ethereum.request({
    method: "eth_requestAccounts"
  })) as string[];
  return Array.isArray(accounts) && accounts.length > 0 ? accounts[0] : null;
}

function App() {
  const forcedState = useMemo(parseForcedState, []);

  const [activeTab, setActiveTab] = useState<SidebarTab>(() => parseTabHash());

  const [owner, setOwner] = useState("");
  const [passkeyHex, setPasskeyHex] = useState(SAMPLE_PASSKEY);
  const [factory, setFactory] = useState("");
  const [salt, setSalt] = useState("");
  const [txHash, setTxHash] = useState("");
  const [runtimeChainId, setRuntimeChainId] = useState<number | null>(null);

  const [chainConfig, setChainConfig] = useState<ChainConfig | null>(null);
  const [serialStatus, setSerialStatus] = useState("unknown");
  const [predictedAddress, setPredictedAddress] = useState<string>("");
  const [loading, setLoading] = useState(false);
  const [errorText, setErrorText] = useState("");

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
        if (!factory && result.factory_address) setFactory(result.factory_address);
        if (result.sca_address) setPredictedAddress(result.sca_address);
      }
    } catch (error) {
      appendLog(`mesh_getChainConfig failed: ${(error as Error).message}`);
    }
  };

  const refreshSerialStatus = async (): Promise<void> => {
    try {
      const result = await callRpc<{ link: string; node_a: string; last_error: string }>("mesh_getStatus");
      setSerialStatus(`${result.link}/${result.node_a}`);
    } catch (error) {
      setSerialStatus("not-configured");
      appendLog(`mesh_getStatus failed: ${(error as Error).message}`);
    }
  };

  useEffect(() => {
    void refreshChainConfig();
    void refreshSerialStatus();

    const onHashChange = (): void => setActiveTab(parseTabHash());
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  const effectiveViewState = forcedState ?? viewState;
  const isPending = effectiveViewState === "pending";
  const isActive = effectiveViewState === "active";
  const isConfirm = effectiveViewState === "confirm";
  const isError = effectiveViewState === "error";

  const handleUseWallet = async (): Promise<void> => {
    setErrorText("");
    try {
      const account = await getWalletAccount();
      if (!account) throw new Error("Failed to load MetaMask account.");
      setOwner(account);
      appendLog(`Wallet connected: ${account}`);
    } catch (error) {
      setErrorText((error as Error).message);
      setViewState("error");
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
          factory_address: factoryAddress
        }
      ]);

      appendLog(`mesh_confirmDeploy status: ${result.status}`);
      if (result.status === "active") {
        setViewState("active");
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
    if (!owner) {
      setErrorText("Owner address is required.");
      return;
    }
    if (!passkeyHex) {
      setErrorText("Passkey pubkey(hex) is required.");
      return;
    }

    setLoading(true);
    setViewState("pending");
    appendLog("mesh_prepareDeploy request");

    try {
      const params: Record<string, string> = {
        owner,
        from: owner,
        passkey_pubkey: passkeyHex
      };
      if (factory) params.factory = factory;
      if (salt) params.salt = salt;

      const prepared = await callRpc<PrepareDeployResult>("mesh_prepareDeploy", [params]);
      if (prepared.predicted_address) setPredictedAddress(prepared.predicted_address);
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

  const handleConfirmDeploy = async (): Promise<void> => {
    setErrorText("");
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

  const renderDashboard = (): JSX.Element => (
    <>
      <section className="row two-col">
        <article className="card grow">
          <h2>Chain Status</h2>
          <p>Chain: {chainConfig ? chainConfig.chain_id : "-"}</p>
          <p>Mode: {chainConfig?.mode ?? "SCA"}</p>
          <p className={chainConfig?.status === "active" ? "success" : "danger"}>
            Status: {chainConfig?.status ?? "inactive"}
          </p>
        </article>

        <article className="card quick-actions">
          <h2>Quick Actions</h2>
          <div className="input-grid">
            <label>
              Owner (EOA)
              <input value={owner} onChange={(e) => setOwner(e.target.value.trim())} />
            </label>
            <label>
              Passkey Pubkey (hex)
              <input value={passkeyHex} onChange={(e) => setPasskeyHex(e.target.value.trim())} />
            </label>
            <label>
              Factory (optional)
              <input value={factory} onChange={(e) => setFactory(e.target.value.trim())} />
            </label>
            <label>
              Salt (optional bytes32)
              <input value={salt} onChange={(e) => setSalt(e.target.value.trim())} />
            </label>
            <label>
              Tx Hash (confirm)
              <input value={txHash} onChange={(e) => setTxHash(e.target.value.trim())} />
            </label>
          </div>
          <div className="button-row">
            <button className="btn btn-soft" type="button" onClick={handleUseWallet} disabled={loading}>
              Use Wallet
            </button>
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

      <section className="row two-col">
        <article className="card grow">
          <h2>Recent Requests</h2>
          {logLines.length === 0 ? <p>No requests yet.</p> : null}
          {logLines.slice(0, 8).map((line) => (
            <p key={line}>{line}</p>
          ))}
        </article>

        <article className="card side">
          <h2>Identity</h2>
          <p>EOA: {shorten(owner) || "-"}</p>
          <p>SCA: {shorten(chainConfig?.sca_address || predictedAddress)}</p>
          <p className="amber">Mode: {chainConfig?.mode ?? "SCA"} (predicted)</p>
        </article>
      </section>

      <section className="row two-col">
        <article className="card grow">
          <h2>Passkey</h2>
          <p className={passkeyHex ? "success" : "danger"}>
            Status: {passkeyHex ? "configured" : "not configured"}
          </p>
          <p>Device: browser passkey</p>
        </article>

        <article className="card side">
          <h2>System Health</h2>
          <p className="success">Relayer: Online</p>
          <p className={serialStatus === "not-configured" ? "danger" : "success"}>
            Node B: {serialStatus}
          </p>
          <p className={serialStatus === "not-configured" ? "danger" : "success"}>
            ESP-NOW: {serialStatus === "not-configured" ? "Unknown" : "Ready"}
          </p>
        </article>
      </section>
    </>
  );

  const renderChains = (): JSX.Element => (
    <section className="section-grid">
      <article className="card">
        <h2>Chain Registry</h2>
        <p>chain_id: {chainConfig?.chain_id ?? runtimeChainId ?? "-"}</p>
        <p>mode: {chainConfig?.mode ?? "-"}</p>
        <p>status: {chainConfig?.status ?? "-"}</p>
        <p>factory: {chainConfig?.factory_address ?? (factory || "-")}</p>
        <p>sca: {chainConfig?.sca_address ?? (predictedAddress || "-")}</p>
        <div className="button-row">
          <button className="btn btn-soft" type="button" onClick={() => void refreshChainConfig()}>
            Refresh Chain Config
          </button>
        </div>
      </article>

      <article className="card">
        <h2>Deploy Tracking</h2>
        <p>last tx hash: {txHash || "-"}</p>
        <p>predicted sca: {predictedAddress || "-"}</p>
        <p className={isActive ? "success" : isError ? "danger" : "amber"}>
          deploy state: {effectiveViewState}
        </p>
      </article>
    </section>
  );

  const renderPasskeys = (): JSX.Element => (
    <section className="section-grid">
      <article className="card">
        <h2>Passkey Config</h2>
        <p>Store the registration public key in hex format.</p>
        <div className="input-grid">
          <label>
            Passkey Public Key (hex)
            <input value={passkeyHex} onChange={(e) => setPasskeyHex(e.target.value.trim())} />
          </label>
        </div>
        <div className="button-row">
          <button className="btn btn-soft" type="button" onClick={() => appendLog("Passkey value updated")}>
            Save Local Value
          </button>
        </div>
        <p className={passkeyHex ? "success" : "danger"}>
          current status: {passkeyHex ? "configured" : "not configured"}
        </p>
      </article>
    </section>
  );

  const renderLogs = (): JSX.Element => (
    <section className="section-grid">
      <article className="card">
        <h2>Relayer Logs</h2>
        <div className="button-row">
          <button className="btn btn-soft" type="button" onClick={() => void refreshSerialStatus()}>
            Refresh Serial Status
          </button>
          <button className="btn btn-soft" type="button" onClick={() => setLogLines([])}>
            Clear Logs
          </button>
        </div>
        <div className="log-list">
          {logLines.length === 0 ? <p>No logs yet.</p> : null}
          {logLines.map((line) => (
            <p key={line}>{line}</p>
          ))}
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
            <button className={`menu-item ${activeTab === "chains" ? "active" : ""}`} onClick={() => setTab("chains")} type="button">
              Chains
            </button>
            <button className={`menu-item ${activeTab === "passkeys" ? "active" : ""}`} onClick={() => setTab("passkeys")} type="button">
              Passkeys
            </button>
            <button className={`menu-item ${activeTab === "logs" ? "active" : ""}`} onClick={() => setTab("logs")} type="button">
              Logs
            </button>
          </nav>

          <div className="status-box">
            <p>Relayer Online</p>
          </div>
        </aside>

        <main className="main">
          <header className="header">
            <h1>Relayer Dashboard</h1>
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
          {activeTab === "chains" ? renderChains() : null}
          {activeTab === "passkeys" ? renderPasskeys() : null}
          {activeTab === "logs" ? renderLogs() : null}

          <section className="card network">
            <h2>Network Activity</h2>
            <p className="muted">Recent approval/transport events</p>
            <div className="table-head">
              <span>Source</span>
              <span>Type</span>
              <span>Result</span>
              <span>Time</span>
            </div>
            <div className="table-row">
              <span>Relayer</span>
              <span>mesh_prepareDeploy</span>
              <span className={loading ? "amber" : isActive ? "success" : isError ? "danger" : "muted"}>
                {loading ? "Pending" : isActive ? "Active" : isError ? "Error" : "Idle"}
              </span>
              <span className="muted">{new Date().toLocaleTimeString()}</span>
            </div>
          </section>
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
