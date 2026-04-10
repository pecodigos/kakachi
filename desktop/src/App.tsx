import { FormEvent, useMemo, useState } from "react";
import {
  createNetwork,
  generateWireguardIdentity,
  getSession,
  joinNetwork,
  listPeers,
  loginUser,
  openSession,
  pingControlPlane,
  registerUser,
  runSessionProbe,
  type NegotiationRunSummary,
  type NetworkSummary,
  type PeerIdentity,
  type SessionSummary
} from "./lib/tauri";

export default function App() {
  const [controlPlaneUrl, setControlPlaneUrl] = useState("http://127.0.0.1:8080");
  const [apiStatus, setApiStatus] = useState("Not checked");

  const [registerUsername, setRegisterUsername] = useState("alice");
  const [registerPassword, setRegisterPassword] = useState("very-strong-password-123");
  const [publicKey, setPublicKey] = useState("");
  const [privateKey, setPrivateKey] = useState("");

  const [loginUsername, setLoginUsername] = useState("alice");
  const [loginPassword, setLoginPassword] = useState("very-strong-password-123");
  const [accessToken, setAccessToken] = useState("");
  const [tokenExpiresAt, setTokenExpiresAt] = useState("");

  const [networkName, setNetworkName] = useState("friends-net");
  const [networkId, setNetworkId] = useState("");
  const [joinNetworkId, setJoinNetworkId] = useState("");
  const [peers, setPeers] = useState<PeerIdentity[]>([]);
  const [activeNetwork, setActiveNetwork] = useState<NetworkSummary | null>(null);

  const [peerUsername, setPeerUsername] = useState("bob");
  const [stunServersCsv, setStunServersCsv] = useState("74.125.250.129:19302");
  const [localBindAddr, setLocalBindAddr] = useState("0.0.0.0:7001");
  const [sessionId, setSessionId] = useState("");
  const [sessionSummary, setSessionSummary] = useState<SessionSummary | null>(null);
  const [runSummary, setRunSummary] = useState<NegotiationRunSummary | null>(null);

  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [eventLog, setEventLog] = useState<string[]>([]);

  const canUseAuthedActions = accessToken.trim().length > 0;

  const parsedStunServers = useMemo(
    () =>
      stunServersCsv
        .split(",")
        .map((item) => item.trim())
        .filter((item) => item.length > 0),
    [stunServersCsv]
  );

  function appendLog(entry: string) {
    setEventLog((current) => [`${new Date().toISOString()} ${entry}`, ...current].slice(0, 18));
  }

  async function runAction<T>(label: string, operation: () => Promise<T>, onSuccess: (value: T) => void) {
    setBusy(label);
    setError(null);

    try {
      const value = await operation();
      onSuccess(value);
      appendLog(`${label}: success`);
    } catch (err) {
      const message = err instanceof Error ? err.message : "Unexpected error";
      setError(message);
      appendLog(`${label}: failed (${message})`);
    } finally {
      setBusy(null);
    }
  }

  function requireAuth(): boolean {
    if (!canUseAuthedActions) {
      setError("Login first to run authenticated actions.");
      return false;
    }
    return true;
  }

  async function onCheckHealth() {
    await runAction("Health check", () => pingControlPlane(controlPlaneUrl), (response) => {
      setApiStatus(`${response.status} at ${response.timestamp}`);
    });
  }

  async function onGenerateKeys() {
    await runAction("Generate WireGuard identity", () => generateWireguardIdentity(), (identity) => {
      setPublicKey(identity.public_key);
      setPrivateKey(identity.private_key);
    });
  }

  async function onRegister(event: FormEvent) {
    event.preventDefault();
    await runAction(
      "Register user",
      () =>
        registerUser({
          control_plane_url: controlPlaneUrl,
          username: registerUsername,
          password: registerPassword,
          public_key: publicKey
        }),
      (response) => {
        setLoginUsername(response.username);
      }
    );
  }

  async function onLogin(event: FormEvent) {
    event.preventDefault();
    await runAction(
      "Login user",
      () =>
        loginUser({
          control_plane_url: controlPlaneUrl,
          username: loginUsername,
          password: loginPassword
        }),
      (response) => {
        setAccessToken(response.access_token);
        setTokenExpiresAt(response.expires_at);
      }
    );
  }

  async function onCreateNetwork(event: FormEvent) {
    event.preventDefault();
    if (!requireAuth()) return;

    await runAction(
      "Create network",
      () =>
        createNetwork({
          control_plane_url: controlPlaneUrl,
          access_token: accessToken,
          name: networkName
        }),
      (response) => {
        setActiveNetwork(response);
        setNetworkId(response.network_id);
        setJoinNetworkId(response.network_id);
      }
    );
  }

  async function onJoinNetwork(event: FormEvent) {
    event.preventDefault();
    if (!requireAuth()) return;

    await runAction(
      "Join network",
      () =>
        joinNetwork({
          control_plane_url: controlPlaneUrl,
          access_token: accessToken,
          network_id: joinNetworkId
        }),
      (response) => {
        setActiveNetwork(response);
        setNetworkId(response.network_id);
      }
    );
  }

  async function onListPeers() {
    if (!requireAuth()) return;
    if (!networkId) {
      setError("Set network id first.");
      return;
    }

    await runAction(
      "List peers",
      () =>
        listPeers({
          control_plane_url: controlPlaneUrl,
          access_token: accessToken,
          network_id: networkId
        }),
      (response) => {
        setPeers(response);
      }
    );
  }

  async function onOpenSession() {
    if (!requireAuth()) return;
    if (!networkId) {
      setError("Set network id first.");
      return;
    }

    await runAction(
      "Open session",
      () =>
        openSession({
          control_plane_url: controlPlaneUrl,
          access_token: accessToken,
          network_id: networkId,
          peer_username: peerUsername
        }),
      (response) => {
        setSessionSummary(response);
        setSessionId(response.session_id);
      }
    );
  }

  async function onRunNegotiation() {
    if (!requireAuth()) return;
    if (!networkId) {
      setError("Set network id first.");
      return;
    }
    if (parsedStunServers.length === 0) {
      setError("Add at least one STUN server.");
      return;
    }

    await runAction(
      "Run session negotiation",
      () =>
        runSessionProbe({
          control_plane_url: controlPlaneUrl,
          access_token: accessToken,
          network_id: networkId,
          peer_username: peerUsername,
          stun_servers: parsedStunServers,
          local_bind_addr: localBindAddr,
          session_id: sessionId || undefined
        }),
      (response) => {
        setRunSummary(response);
        setSessionId(response.session_id);
      }
    );
  }

  async function onFetchSession() {
    if (!requireAuth()) return;
    if (!networkId || !sessionId) {
      setError("Set network id and session id first.");
      return;
    }

    await runAction(
      "Fetch session",
      () =>
        getSession({
          control_plane_url: controlPlaneUrl,
          access_token: accessToken,
          network_id: networkId,
          session_id: sessionId
        }),
      (response) => {
        setSessionSummary(response);
      }
    );
  }

  return (
    <div className="page">
      <div className="blur-shape shape-a" />
      <div className="blur-shape shape-b" />
      <div className="blur-shape shape-c" />

      <main className="shell">
        <header className="hero card">
          <p className="eyebrow">Kakachi Desktop</p>
          <h1>Control Plane + Agent In One Desktop Surface</h1>
          <p>
            Register users, create networks, open sessions, and run live STUN-backed session reports
            directly from the app.
          </p>
        </header>

        <section className="card grid-row">
          <label>
            Control Plane URL
            <input
              value={controlPlaneUrl}
              onChange={(event) => setControlPlaneUrl(event.target.value)}
              placeholder="http://127.0.0.1:8080"
            />
          </label>
          <button disabled={!!busy} onClick={onCheckHealth}>
            {busy === "Health check" ? "Checking..." : "Check API Health"}
          </button>
          <p className="inline-note">Status: {apiStatus}</p>
        </section>

        <section className="cluster">
          <article className="card">
            <h2>Identity</h2>
            <button disabled={!!busy} onClick={onGenerateKeys}>
              {busy === "Generate WireGuard identity" ? "Generating..." : "Generate WireGuard Keypair"}
            </button>
            <label>
              Public Key
              <textarea value={publicKey} onChange={(event) => setPublicKey(event.target.value)} rows={3} />
            </label>
            <label>
              Private Key
              <textarea value={privateKey} readOnly rows={3} />
            </label>

            <form onSubmit={onRegister}>
              <label>
                Username
                <input
                  value={registerUsername}
                  onChange={(event) => setRegisterUsername(event.target.value)}
                />
              </label>
              <label>
                Password
                <input
                  type="password"
                  value={registerPassword}
                  onChange={(event) => setRegisterPassword(event.target.value)}
                />
              </label>
              <button disabled={!!busy || !publicKey.trim()} type="submit">
                {busy === "Register user" ? "Registering..." : "Register User"}
              </button>
            </form>

            <form onSubmit={onLogin}>
              <label>
                Login Username
                <input value={loginUsername} onChange={(event) => setLoginUsername(event.target.value)} />
              </label>
              <label>
                Login Password
                <input
                  type="password"
                  value={loginPassword}
                  onChange={(event) => setLoginPassword(event.target.value)}
                />
              </label>
              <button disabled={!!busy} type="submit">
                {busy === "Login user" ? "Logging in..." : "Login"}
              </button>
            </form>
            <p className="inline-note">Token expires: {tokenExpiresAt || "not logged in"}</p>
          </article>

          <article className="card">
            <h2>Network</h2>
            <form onSubmit={onCreateNetwork}>
              <label>
                Network Name
                <input value={networkName} onChange={(event) => setNetworkName(event.target.value)} />
              </label>
              <button disabled={!!busy || !canUseAuthedActions} type="submit">
                {busy === "Create network" ? "Creating..." : "Create Network"}
              </button>
            </form>

            <form onSubmit={onJoinNetwork}>
              <label>
                Network ID
                <input value={joinNetworkId} onChange={(event) => setJoinNetworkId(event.target.value)} />
              </label>
              <button disabled={!!busy || !canUseAuthedActions} type="submit">
                {busy === "Join network" ? "Joining..." : "Join Network"}
              </button>
            </form>

            <div className="row-actions">
              <button disabled={!!busy || !canUseAuthedActions} onClick={onListPeers}>
                {busy === "List peers" ? "Loading..." : "List Peers"}
              </button>
              <label>
                Active Network ID
                <input value={networkId} onChange={(event) => setNetworkId(event.target.value)} />
              </label>
            </div>

            <pre>{JSON.stringify(activeNetwork, null, 2)}</pre>
            <pre>{JSON.stringify(peers, null, 2)}</pre>
          </article>
        </section>

        <section className="card">
          <h2>Session Negotiation</h2>
          <div className="cluster split">
            <label>
              Peer Username
              <input value={peerUsername} onChange={(event) => setPeerUsername(event.target.value)} />
            </label>
            <label>
              STUN Servers (comma separated)
              <input
                value={stunServersCsv}
                onChange={(event) => setStunServersCsv(event.target.value)}
                placeholder="74.125.250.129:19302"
              />
            </label>
            <label>
              Local Bind Addr
              <input value={localBindAddr} onChange={(event) => setLocalBindAddr(event.target.value)} />
            </label>
            <label>
              Session ID (optional)
              <input value={sessionId} onChange={(event) => setSessionId(event.target.value)} />
            </label>
          </div>

          <div className="row-actions">
            <button disabled={!!busy || !canUseAuthedActions} onClick={onOpenSession}>
              {busy === "Open session" ? "Opening..." : "Open Session"}
            </button>
            <button disabled={!!busy || !canUseAuthedActions} onClick={onRunNegotiation}>
              {busy === "Run session negotiation" ? "Running..." : "Run Live Negotiation"}
            </button>
            <button disabled={!!busy || !canUseAuthedActions} onClick={onFetchSession}>
              {busy === "Fetch session" ? "Fetching..." : "Fetch Session State"}
            </button>
          </div>

          <pre>{JSON.stringify(runSummary, null, 2)}</pre>
          <pre>{JSON.stringify(sessionSummary, null, 2)}</pre>
        </section>

        <section className="card stack">
          <h2>Runtime</h2>
          {error ? <p className="error-banner">{error}</p> : null}
          <p className="inline-note">Current action: {busy ?? "idle"}</p>
          <pre>{eventLog.join("\n")}</pre>
          <p className="inline-note token">JWT: {accessToken || "none"}</p>
        </section>
      </main>
    </div>
  );
}
