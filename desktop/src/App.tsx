import { FormEvent, useEffect, useMemo, useState } from "react";
import {
  createNetwork,
  generateWireguardIdentity,
  joinNetwork,
  listPeers,
  loginUser,
  registerUser,
  runSessionProbe,
  type NegotiationRunSummary,
  type NetworkSummary,
  type PeerIdentity
} from "./lib/tauri";

type AuthView = "login" | "register";

interface SavedLogin {
  controlPlaneUrl: string;
  username: string;
  accessToken: string;
  expiresAt: string;
}

const SAVED_LOGIN_KEY = "kakachi.saved-login.v1";
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function toFriendlyError(rawMessage: string): string {
  const message = rawMessage.trim();
  const normalized = message.toLowerCase();

  if (normalized.includes("no_peers_available")) {
    return "No friends are online in this network yet. Ask them to join and try again.";
  }

  if (
    normalized.includes("401") ||
    normalized.includes("unauthorized") ||
    normalized.includes("invalid token") ||
    normalized.includes("expired")
  ) {
    return "Your sign-in session expired. Please sign in again.";
  }

  if (normalized.includes("network_id") && normalized.includes("uuid")) {
    return "That invite code is not valid. Check the network ID and try again.";
  }

  if (normalized.includes("control_plane_url") || normalized.includes("http/https/ws/wss")) {
    return "The server address looks invalid. Use something like http://127.0.0.1:8080.";
  }

  if (
    normalized.includes("connection refused") ||
    normalized.includes("dns") ||
    normalized.includes("timed out") ||
    normalized.includes("failed to send request")
  ) {
    return "Kakachi could not reach the server. Check if backend is running and your address is correct.";
  }

  if (normalized.includes("already exists") || normalized.includes("duplicate")) {
    return "This username is already taken. Choose another username.";
  }

  if (normalized.includes("peer") && normalized.includes("not")) {
    return "Could not find this friend in your network. Refresh peers and try again.";
  }

  if (normalized.includes("stun")) {
    return "Could not establish a direct path right now. Kakachi can still try relay mode.";
  }

  return message || "Something went wrong. Please try again.";
}

function readSavedLogin(): SavedLogin | null {
  if (typeof window === "undefined") {
    return null;
  }

  const raw = window.localStorage.getItem(SAVED_LOGIN_KEY);
  if (!raw) {
    return null;
  }

  try {
    const parsed = JSON.parse(raw) as Partial<SavedLogin>;
    if (
      typeof parsed.controlPlaneUrl === "string" &&
      typeof parsed.username === "string" &&
      typeof parsed.accessToken === "string" &&
      typeof parsed.expiresAt === "string"
    ) {
      return {
        controlPlaneUrl: parsed.controlPlaneUrl,
        username: parsed.username,
        accessToken: parsed.accessToken,
        expiresAt: parsed.expiresAt
      };
    }
  } catch {
    window.localStorage.removeItem(SAVED_LOGIN_KEY);
  }

  return null;
}

function writeSavedLogin(payload: SavedLogin) {
  if (typeof window === "undefined") {
    return;
  }

  window.localStorage.setItem(SAVED_LOGIN_KEY, JSON.stringify(payload));
}

function clearSavedLogin() {
  if (typeof window === "undefined") {
    return;
  }

  window.localStorage.removeItem(SAVED_LOGIN_KEY);
}

export default function App() {
  const [authView, setAuthView] = useState<AuthView>("login");
  const [controlPlaneUrl, setControlPlaneUrl] = useState("http://127.0.0.1:8080");
  const [statusMessage, setStatusMessage] = useState("Sign in to start your virtual LAN.");

  const [registerUsername, setRegisterUsername] = useState("");
  const [registerEmail, setRegisterEmail] = useState("");
  const [registerPassword, setRegisterPassword] = useState("");
  const [registerConfirmPassword, setRegisterConfirmPassword] = useState("");

  const [loginUsername, setLoginUsername] = useState("");
  const [loginPassword, setLoginPassword] = useState("");
  const [saveLogin, setSaveLogin] = useState(true);
  const [savedLogin, setSavedLogin] = useState<SavedLogin | null>(null);
  const [currentUsername, setCurrentUsername] = useState("");
  const [accessToken, setAccessToken] = useState("");
  const [tokenExpiresAt, setTokenExpiresAt] = useState("");

  const [networkName, setNetworkName] = useState("friends-network");
  const [networkId, setNetworkId] = useState("");
  const [joinNetworkId, setJoinNetworkId] = useState("");
  const [peers, setPeers] = useState<PeerIdentity[]>([]);
  const [activeNetwork, setActiveNetwork] = useState<NetworkSummary | null>(null);

  const [peerUsername, setPeerUsername] = useState("");
  const [connectIntent, setConnectIntent] = useState<"lan" | "vpn">("lan");
  const [stunServersCsv, setStunServersCsv] = useState("74.125.250.129:19302");
  const [localBindAddr, setLocalBindAddr] = useState("0.0.0.0:7001");
  const [runSummary, setRunSummary] = useState<NegotiationRunSummary | null>(null);

  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const canUseAuthedActions = accessToken.trim().length > 0 && currentUsername.trim().length > 0;

  useEffect(() => {
    const saved = readSavedLogin();
    if (!saved) {
      return;
    }

    setSavedLogin(saved);
    setControlPlaneUrl(saved.controlPlaneUrl);
    setLoginUsername(saved.username);
    setStatusMessage(`Saved login found for ${saved.username}.`);
  }, []);

  const parsedStunServers = useMemo(
    () =>
      stunServersCsv
        .split(",")
        .map((item) => item.trim())
        .filter((item) => item.length > 0),
    [stunServersCsv]
  );

  const visiblePeers = useMemo(
    () => peers.filter((peer) => peer.username !== currentUsername),
    [peers, currentUsername]
  );

  const connectionLabel = useMemo(() => {
    if (!runSummary) {
      return "Not connected yet";
    }

    return runSummary.final_path === "direct" ? "Direct LAN tunnel ready" : "Connected through relay";
  }, [runSummary]);

  const connectIntentLabel = connectIntent === "lan" ? "LAN party mode" : "Remote VPN mode";

  function resetNetworkState() {
    setNetworkId("");
    setJoinNetworkId("");
    setPeers([]);
    setPeerUsername("");
    setRunSummary(null);
    setActiveNetwork(null);
  }

  async function runAction<T>(label: string, operation: () => Promise<T>, onSuccess: (value: T) => void) {
    setBusy(label);
    setError(null);

    try {
      const value = await operation();
      onSuccess(value);
    } catch (err) {
      const technicalMessage = err instanceof Error ? err.message : "Unexpected error";
      const friendlyMessage = toFriendlyError(technicalMessage);
      setError(friendlyMessage);
      setStatusMessage(`${label} failed. ${friendlyMessage}`);
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

  async function onRegister(event: FormEvent) {
    event.preventDefault();

    const username = registerUsername.trim();
    const email = registerEmail.trim();

    if (!username) {
      setError("Username is required.");
      return;
    }

    if (!EMAIL_PATTERN.test(email)) {
      setError("Enter a valid email address.");
      return;
    }

    if (registerPassword.length < 12) {
      setError("Password must have at least 12 characters.");
      return;
    }

    if (registerPassword !== registerConfirmPassword) {
      setError("Password and confirm password must match.");
      return;
    }

    await runAction(
      "Create account",
      async () => {
        const identity = await generateWireguardIdentity();

        return registerUser({
          control_plane_url: controlPlaneUrl,
          username,
          email,
          password: registerPassword,
          public_key: identity.public_key
        });
      },
      (response) => {
        setAuthView("login");
        setLoginUsername(response.username);
        setRegisterUsername("");
        setRegisterEmail("");
        setRegisterPassword("");
        setRegisterConfirmPassword("");
        setStatusMessage("Account created. Sign in to continue.");
      }
    );
  }

  async function onLogin(event: FormEvent) {
    event.preventDefault();

    const username = loginUsername.trim();
    if (!username || !loginPassword) {
      setError("Username and password are required.");
      return;
    }

    await runAction(
      "Sign in",
      () =>
        loginUser({
          control_plane_url: controlPlaneUrl,
          username,
          password: loginPassword
        }),
      (response) => {
        setAccessToken(response.access_token);
        setTokenExpiresAt(response.expires_at);
        setCurrentUsername(username);
        setLoginPassword("");
        setStatusMessage(`Welcome, ${username}.`);

        if (saveLogin) {
          const payload = {
            controlPlaneUrl,
            username,
            accessToken: response.access_token,
            expiresAt: response.expires_at
          };

          setSavedLogin(payload);
          writeSavedLogin({
            controlPlaneUrl,
            username,
            accessToken: response.access_token,
            expiresAt: response.expires_at
          });
        } else {
          clearSavedLogin();
          setSavedLogin(null);
        }
      }
    );
  }

  function onUseSavedLogin() {
    if (!savedLogin) {
      return;
    }

    const expiresAtMs = Date.parse(savedLogin.expiresAt);
    if (Number.isFinite(expiresAtMs) && expiresAtMs < Date.now()) {
      clearSavedLogin();
      setSavedLogin(null);
      setError("Saved login expired. Sign in with password again.");
      return;
    }

    setCurrentUsername(savedLogin.username);
    setAccessToken(savedLogin.accessToken);
    setTokenExpiresAt(savedLogin.expiresAt);
    setControlPlaneUrl(savedLogin.controlPlaneUrl);
    setError(null);
    setStatusMessage(`Welcome back, ${savedLogin.username}.`);
  }

  function onLogout() {
    setAccessToken("");
    setTokenExpiresAt("");
    setCurrentUsername("");
    setLoginPassword("");
    setError(null);
    setStatusMessage("Signed out.");
    resetNetworkState();
    clearSavedLogin();
    setSavedLogin(null);
  }

  async function onCopyNetworkId() {
    if (!networkId) {
      return;
    }

    try {
      await navigator.clipboard.writeText(networkId);
      setStatusMessage("Network ID copied. Share it with your friend.");
    } catch {
      setError("Could not copy network ID. Copy it manually.");
    }
  }

  function onChangeNetwork() {
    resetNetworkState();
    setStatusMessage("Choose or create a network.");
  }

  async function onCreateNetwork(event: FormEvent) {
    event.preventDefault();
    if (!requireAuth()) return;

    const trimmedName = networkName.trim();
    if (!trimmedName) {
      setError("Network name is required.");
      return;
    }

    await runAction(
      "Create network",
      () =>
        createNetwork({
          control_plane_url: controlPlaneUrl,
          access_token: accessToken,
          name: trimmedName
        }),
      (response) => {
        setActiveNetwork(response);
        setNetworkId(response.network_id);
        setJoinNetworkId(response.network_id);
        setStatusMessage(`Network ${response.name} is ready.`);
      }
    );
  }

  async function onJoinNetwork(event: FormEvent) {
    event.preventDefault();
    if (!requireAuth()) return;

    const trimmedNetworkId = joinNetworkId.trim();
    if (!trimmedNetworkId) {
      setError("Network ID is required.");
      return;
    }

    await runAction(
      "Join network",
      () =>
        joinNetwork({
          control_plane_url: controlPlaneUrl,
          access_token: accessToken,
          network_id: trimmedNetworkId
        }),
      (response) => {
        setActiveNetwork(response);
        setNetworkId(response.network_id);
        setStatusMessage(`Joined network ${response.name}.`);
      }
    );
  }

  async function onRefreshPeers() {
    if (!requireAuth()) return;
    if (!networkId) {
      setError("Create or join a network first.");
      return;
    }

    await runAction(
      "Refresh peers",
      () =>
        listPeers({
          control_plane_url: controlPlaneUrl,
          access_token: accessToken,
          network_id: networkId
        }),
      (response) => {
        setPeers(response);
        if (response.length === 0) {
          setStatusMessage("No peers in this network yet.");
        } else {
          setStatusMessage(`Found ${response.length} peer(s) in your network.`);
        }
      }
    );
  }

  async function onQuickConnect() {
    if (!requireAuth()) return;
    if (!networkId) {
      setError("Create or join a network first.");
      return;
    }

    if (parsedStunServers.length === 0) {
      setError("Add at least one STUN server in advanced settings.");
      return;
    }

    await runAction(
      "Quick connect",
      async () => {
        const peerList = await listPeers({
          control_plane_url: controlPlaneUrl,
          access_token: accessToken,
          network_id: networkId
        });

        const candidates = peerList.filter((peer) => peer.username !== currentUsername);
        if (candidates.length === 0) {
          throw new Error("NO_PEERS_AVAILABLE");
        }

        const selectedPeer = peerUsername.trim() || candidates[0].username;
        const summary = await runSessionProbe({
          control_plane_url: controlPlaneUrl,
          access_token: accessToken,
          network_id: networkId,
          peer_username: selectedPeer,
          stun_servers: parsedStunServers,
          local_bind_addr: localBindAddr,
          session_id: runSummary?.session_id
        });

        return { selectedPeer, summary, peerList };
      },
      ({ selectedPeer, summary, peerList }) => {
        setPeers(peerList);
        setPeerUsername(selectedPeer);
        setRunSummary(summary);
        const pathLabel = summary.final_path === "direct" ? "direct LAN tunnel" : "relay tunnel";
        const usage = connectIntent === "lan" ? "LAN apps" : "VPN traffic";
        setStatusMessage(`Connected to ${selectedPeer} for ${usage} using ${pathLabel}.`);
      }
    );
  }

  async function onConnectPeer() {
    if (!requireAuth()) return;
    if (!networkId) {
      setError("Create or join a network first.");
      return;
    }

    const trimmedPeer = peerUsername.trim();
    if (!trimmedPeer) {
      setError("Peer username is required.");
      return;
    }

    if (parsedStunServers.length === 0) {
      setError("Add at least one STUN server in advanced settings.");
      return;
    }

    await runAction(
      "Connect",
      () =>
        runSessionProbe({
          control_plane_url: controlPlaneUrl,
          access_token: accessToken,
          network_id: networkId,
          peer_username: trimmedPeer,
          stun_servers: parsedStunServers,
          local_bind_addr: localBindAddr,
          session_id: runSummary?.session_id
        }),
      (response) => {
        setRunSummary(response);
        const pathLabel = response.final_path === "direct" ? "direct LAN tunnel" : "relay tunnel";
        const usage = connectIntent === "lan" ? "LAN apps" : "VPN traffic";
        setStatusMessage(`Connected to ${trimmedPeer} for ${usage} using ${pathLabel}.`);
      }
    );
  }

  if (!canUseAuthedActions) {
    return (
      <div className="page">
        <div className="backdrop" />
        <main className="auth-shell">
          <section className="panel auth-panel">
            <p className="badge">KAKACHI</p>
            <h1>Virtual LAN for real people</h1>
            <p className="supporting-copy">Sign in, pick a network, and connect like you are on the same router.</p>

            <label>
              Server address
              <input
                value={controlPlaneUrl}
                onChange={(event) => setControlPlaneUrl(event.target.value)}
                placeholder="http://127.0.0.1:8080"
              />
            </label>

            {authView === "login" ? (
              <form onSubmit={onLogin} className="form-stack">
                <label>
                  Username
                  <input value={loginUsername} onChange={(event) => setLoginUsername(event.target.value)} />
                </label>
                <label>
                  Password
                  <input
                    type="password"
                    value={loginPassword}
                    onChange={(event) => setLoginPassword(event.target.value)}
                  />
                </label>
                <label className="checkbox-row">
                  <input
                    type="checkbox"
                    checked={saveLogin}
                    onChange={(event) => setSaveLogin(event.target.checked)}
                  />
                  Save login on this device
                </label>
                <button disabled={!!busy} type="submit">
                  {busy === "Sign in" ? "Signing in..." : "Sign in"}
                </button>
                {savedLogin ? (
                  <button className="secondary" type="button" onClick={onUseSavedLogin} disabled={!!busy}>
                    Continue as {savedLogin.username}
                  </button>
                ) : null}
              </form>
            ) : (
              <form onSubmit={onRegister} className="form-stack">
                <label>
                  Username
                  <input
                    value={registerUsername}
                    onChange={(event) => setRegisterUsername(event.target.value)}
                  />
                </label>
                <label>
                  Email
                  <input value={registerEmail} onChange={(event) => setRegisterEmail(event.target.value)} />
                </label>
                <label>
                  Password
                  <input
                    type="password"
                    value={registerPassword}
                    onChange={(event) => setRegisterPassword(event.target.value)}
                  />
                </label>
                <label>
                  Confirm password
                  <input
                    type="password"
                    value={registerConfirmPassword}
                    onChange={(event) => setRegisterConfirmPassword(event.target.value)}
                  />
                </label>
                <button disabled={!!busy} type="submit">
                  {busy === "Create account" ? "Creating account..." : "Create account"}
                </button>
              </form>
            )}

            <button
              className="link-button"
              disabled={!!busy}
              onClick={() => {
                setAuthView((current) => (current === "login" ? "register" : "login"));
                setError(null);
              }}
            >
              {authView === "login" ? "Create account" : "Back to sign in"}
            </button>

            {error ? <p className="banner error">{error}</p> : null}
            <p className="banner status">{statusMessage}</p>
          </section>
        </main>
      </div>
    );
  }

  return (
    <div className="page">
      <div className="backdrop" />
      <main className="app-shell">
        <header className="topbar panel">
          <div>
            <p className="badge">KAKACHI</p>
            <h1>Your Private LAN</h1>
            <p className="supporting-copy">Signed in as {currentUsername}</p>
          </div>
          <button className="secondary" onClick={onLogout}>
            Log out
          </button>
        </header>

        <section className="grid">
          <article className="panel">
            <h2>Network</h2>
            <p className="inline-info">Step 1: create a network or join with an invite code.</p>
            <form onSubmit={onCreateNetwork} className="form-stack">
              <label>
                New network name
                <input value={networkName} onChange={(event) => setNetworkName(event.target.value)} />
              </label>
              <button disabled={!!busy} type="submit">
                {busy === "Create network" ? "Creating..." : "Create network"}
              </button>
            </form>

            <form onSubmit={onJoinNetwork} className="form-stack">
              <label>
                Join with network ID
                <input value={joinNetworkId} onChange={(event) => setJoinNetworkId(event.target.value)} />
              </label>
              <button disabled={!!busy} type="submit">
                {busy === "Join network" ? "Joining..." : "Join network"}
              </button>
            </form>

            <p className="inline-info">Active network: {networkId || "none"}</p>
            {activeNetwork ? <p className="inline-info">Owner: {activeNetwork.owner}</p> : null}
            {networkId ? (
              <div className="action-row compact">
                <button className="secondary" type="button" onClick={onCopyNetworkId}>
                  Copy invite code
                </button>
                <button className="secondary" type="button" onClick={onChangeNetwork}>
                  Switch network
                </button>
              </div>
            ) : null}
          </article>

          {networkId ? (
            <article className="panel">
              <h2>Connect</h2>
              <p className="inline-info">Step 2: choose what you need and connect to a friend.</p>

              <div className="intent-row">
                <button
                  type="button"
                  className={`intent-btn ${connectIntent === "lan" ? "active" : ""}`}
                  onClick={() => setConnectIntent("lan")}
                >
                  LAN game/app
                </button>
                <button
                  type="button"
                  className={`intent-btn ${connectIntent === "vpn" ? "active" : ""}`}
                  onClick={() => setConnectIntent("vpn")}
                >
                  Remote VPN
                </button>
              </div>
              <p className="inline-info">Mode: {connectIntentLabel}</p>

              <button className="quick-connect" disabled={!!busy} onClick={onQuickConnect}>
                {busy === "Quick connect" ? "Connecting..." : "Quick connect"}
              </button>
              <p className="inline-info">This automatically finds online friends and connects with safest path.</p>

              <p className={`connection-pill ${runSummary?.final_path ?? "idle"}`}>{connectionLabel}</p>
              {runSummary ? <p className="inline-info">Reason: {runSummary.final_reason}</p> : null}

              <details>
                <summary>Manual friend selection</summary>
                <label>
                  Friend username
                  <input value={peerUsername} onChange={(event) => setPeerUsername(event.target.value)} />
                </label>

                <div className="action-row">
                  <button disabled={!!busy} onClick={onRefreshPeers}>
                    {busy === "Refresh peers" ? "Refreshing..." : "Refresh peers"}
                  </button>
                  <button disabled={!!busy} onClick={onConnectPeer}>
                    {busy === "Connect" ? "Connecting..." : "Connect manually"}
                  </button>
                </div>

                <div className="peer-list">
                  {visiblePeers.length === 0 ? (
                    <p className="inline-info">No peers available yet.</p>
                  ) : (
                    visiblePeers.map((peer) => (
                      <button
                        key={peer.username}
                        className="peer-item"
                        onClick={() => setPeerUsername(peer.username)}
                      >
                        {peer.username}
                      </button>
                    ))
                  )}
                </div>
              </details>

              <details>
                <summary>Advanced connection settings</summary>
                <div className="form-stack advanced-grid">
                  <label>
                    STUN servers (comma separated)
                    <input value={stunServersCsv} onChange={(event) => setStunServersCsv(event.target.value)} />
                  </label>
                  <label>
                    Local bind address
                    <input value={localBindAddr} onChange={(event) => setLocalBindAddr(event.target.value)} />
                  </label>
                </div>
              </details>
            </article>
          ) : (
            <article className="panel muted-panel">
              <h2>Connect</h2>
              <p className="inline-info">Create or join a network first, then this section unlocks.</p>
            </article>
          )}
        </section>

        {error ? <p className="banner error">{error}</p> : null}
        <p className="banner status">{statusMessage}</p>
        <p className="inline-info">Session expires at: {tokenExpiresAt}</p>
      </main>
    </div>
  );
}
