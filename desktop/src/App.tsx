import { FormEvent, useEffect, useMemo, useState } from "react";
import {
  clearLoginSession,
  createNetwork,
  generateWireguardIdentity,
  getLocalAddresses,
  joinNetwork,
  listPeerEndpointBundles,
  listPeers,
  loadLoginSession,
  loginUser,
  registerUser,
  saveLoginSession,
  type LocalAddressSummary,
  type NetworkSummary,
  type PeerEndpointBundle,
  type PeerIdentity,
  type SavedLoginSession
} from "./lib/tauri";

type AuthView = "login" | "register";
type SecureStorageState = "unknown" | "available" | "unavailable";

interface PeerPresence {
  online: boolean;
  lastSeenAt: string | null;
}

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function toFriendlyError(rawMessage: string): string {
  const message = rawMessage.trim();
  const normalized = message.toLowerCase();

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

  if (
    normalized.includes("connection refused") ||
    normalized.includes("dns") ||
    normalized.includes("timed out") ||
    normalized.includes("failed to send request")
  ) {
    return "Kakachi could not reach the server. Check if backend is running.";
  }

  if (normalized.includes("keyring") || normalized.includes("secret service")) {
    return "Secure saved login is unavailable on this device. You can still use normal sign in.";
  }

  return message || "Something went wrong. Please try again.";
}

function buildPresenceMap(endpointBundles: PeerEndpointBundle[]): Record<string, PeerPresence> {
  const nowMs = Date.now();
  const map: Record<string, PeerPresence> = {};

  for (const bundle of endpointBundles) {
    let freshestAtMs: number | null = null;

    for (const candidate of bundle.candidates) {
      const parsed = Date.parse(candidate.observed_at);
      if (!Number.isFinite(parsed)) {
        continue;
      }

      freshestAtMs = freshestAtMs === null ? parsed : Math.max(freshestAtMs, parsed);
    }

    if (freshestAtMs === null) {
      map[bundle.username] = { online: false, lastSeenAt: null };
      continue;
    }

    const ageSeconds = Math.max(0, Math.floor((nowMs - freshestAtMs) / 1000));
    map[bundle.username] = {
      online: ageSeconds <= 120,
      lastSeenAt: new Date(freshestAtMs).toISOString()
    };
  }

  return map;
}

function formatLastSeen(lastSeenAt: string | null): string {
  if (!lastSeenAt) {
    return "No recent signal";
  }

  const lastSeenMs = Date.parse(lastSeenAt);
  if (!Number.isFinite(lastSeenMs)) {
    return "No recent signal";
  }

  const ageSeconds = Math.max(0, Math.floor((Date.now() - lastSeenMs) / 1000));
  if (ageSeconds < 60) {
    return `${ageSeconds}s ago`;
  }

  const ageMinutes = Math.floor(ageSeconds / 60);
  if (ageMinutes < 60) {
    return `${ageMinutes}m ago`;
  }

  const ageHours = Math.floor(ageMinutes / 60);
  if (ageHours < 24) {
    return `${ageHours}h ago`;
  }

  const ageDays = Math.floor(ageHours / 24);
  return `${ageDays}d ago`;
}

function upsertServerList(current: NetworkSummary[], summary: NetworkSummary): NetworkSummary[] {
  const existing = current.filter((item) => item.network_id !== summary.network_id);
  return [summary, ...existing];
}

export default function App() {
  const [authView, setAuthView] = useState<AuthView>("login");
  const [controlPlaneUrl, setControlPlaneUrl] = useState("http://127.0.0.1:8080");
  const [statusMessage, setStatusMessage] = useState("");

  const [registerUsername, setRegisterUsername] = useState("");
  const [registerEmail, setRegisterEmail] = useState("");
  const [registerPassword, setRegisterPassword] = useState("");
  const [registerConfirmPassword, setRegisterConfirmPassword] = useState("");

  const [loginUsername, setLoginUsername] = useState("");
  const [loginPassword, setLoginPassword] = useState("");
  const [saveLogin, setSaveLogin] = useState(true);
  const [savedLogin, setSavedLogin] = useState<SavedLoginSession | null>(null);

  const [currentUsername, setCurrentUsername] = useState("");
  const [accessToken, setAccessToken] = useState("");
  const [secureStorageState, setSecureStorageState] = useState<SecureStorageState>("unknown");

  const [isPowerOn, setIsPowerOn] = useState(true);
  const [localAddresses, setLocalAddresses] = useState<LocalAddressSummary>({ ipv4: [], ipv6: [] });

  const [networkName, setNetworkName] = useState("friends-network");
  const [joinNetworkId, setJoinNetworkId] = useState("");
  const [serverList, setServerList] = useState<NetworkSummary[]>([]);
  const [activeServerId, setActiveServerId] = useState("");

  const [peers, setPeers] = useState<PeerIdentity[]>([]);
  const [peerPresence, setPeerPresence] = useState<Record<string, PeerPresence>>({});

  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const isAuthenticated = accessToken.trim().length > 0 && currentUsername.trim().length > 0;

  const activeServer = useMemo(
    () => serverList.find((server) => server.network_id === activeServerId) ?? null,
    [serverList, activeServerId]
  );

  const displayedMembers = useMemo(() => {
    if (!activeServer) {
      return [] as PeerIdentity[];
    }

    if (peers.length > 0) {
      return peers;
    }

    return activeServer.members;
  }, [activeServer, peers]);

  useEffect(() => {
    let active = true;

    async function hydrateSavedSession() {
      try {
        const session = await loadLoginSession();
        if (!active || !session) {
          return;
        }

        setSavedLogin(session);
        setLoginUsername(session.username);
        setControlPlaneUrl(session.control_plane_url);
        setSecureStorageState("available");
      } catch {
        if (!active) {
          return;
        }

        setSecureStorageState("unavailable");
      }
    }

    void hydrateSavedSession();

    return () => {
      active = false;
    };
  }, []);

  async function runAction<T>(label: string, operation: () => Promise<T>, onSuccess: (value: T) => void) {
    setBusy(label);
    setError(null);

    try {
      const value = await operation();
      onSuccess(value);
    } catch (err) {
      const raw = err instanceof Error ? err.message : "Unexpected error";
      const friendly = toFriendlyError(raw);
      setError(friendly);
      setStatusMessage(`${label} failed. ${friendly}`);
    } finally {
      setBusy(null);
    }
  }

  function requireAuth(): boolean {
    if (!isAuthenticated) {
      setError("Sign in first.");
      return false;
    }

    return true;
  }

  function requirePowerOn(): boolean {
    if (!isPowerOn) {
      setError("Turn power on first.");
      return false;
    }

    return true;
  }

  async function refreshLocalAddresses() {
    try {
      const summary = await getLocalAddresses();
      setLocalAddresses(summary);
    } catch {
      setLocalAddresses({ ipv4: [], ipv6: [] });
    }
  }

  async function refreshMembers(networkId: string) {
    if (!isAuthenticated || !networkId) {
      return;
    }

    const [peerList, endpointBundles] = await Promise.all([
      listPeers({
        control_plane_url: controlPlaneUrl,
        access_token: accessToken,
        network_id: networkId
      }),
      listPeerEndpointBundles({
        control_plane_url: controlPlaneUrl,
        access_token: accessToken,
        network_id: networkId
      }).catch(() => [])
    ]);

    const nextPresence = buildPresenceMap(endpointBundles);
    nextPresence[currentUsername] = {
      online: isPowerOn,
      lastSeenAt: nextPresence[currentUsername]?.lastSeenAt ?? null
    };

    setPeers(peerList);
    setPeerPresence(nextPresence);
    setServerList((current) =>
      current.map((server) =>
        server.network_id === networkId
          ? {
              ...server,
              members: peerList
            }
          : server
      )
    );
  }

  function onTogglePower() {
    const nextState = !isPowerOn;
    setIsPowerOn(nextState);

    if (!nextState) {
      setStatusMessage("Power off. Presence updates paused.");
      setPeers([]);
      setPeerPresence({});
      return;
    }

    setStatusMessage("Power on.");
    void refreshLocalAddresses();
    if (activeServerId) {
      void refreshMembers(activeServerId);
    }
  }

  function onSelectServer(server: NetworkSummary) {
    setActiveServerId(server.network_id);
    setPeers([]);
    setPeerPresence({});
    setStatusMessage(`Selected server ${server.name}.`);

    if (isPowerOn) {
      void refreshMembers(server.network_id);
    }
  }

  async function onCreateNetwork(event: FormEvent) {
    event.preventDefault();
    if (!requireAuth() || !requirePowerOn()) return;

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
      (summary) => {
        setServerList((current) => upsertServerList(current, summary));
        setActiveServerId(summary.network_id);
        setJoinNetworkId(summary.network_id);
        setStatusMessage(`Server ${summary.name} created.`);
        void refreshMembers(summary.network_id);
      }
    );
  }

  async function onJoinNetwork(event: FormEvent) {
    event.preventDefault();
    if (!requireAuth() || !requirePowerOn()) return;

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
      (summary) => {
        setServerList((current) => upsertServerList(current, summary));
        setActiveServerId(summary.network_id);
        setStatusMessage(`Joined server ${summary.name}.`);
        void refreshMembers(summary.network_id);
      }
    );
  }

  async function onRefreshActiveServerMembers() {
    if (!requireAuth() || !requirePowerOn()) return;
    if (!activeServerId) {
      setError("Select a server first.");
      return;
    }

    await runAction(
      "Refresh members",
      async () => {
        await refreshMembers(activeServerId);
      },
      () => {
        setStatusMessage("Member list refreshed.");
      }
    );
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
        const keyPair = await generateWireguardIdentity();

        return registerUser({
          control_plane_url: controlPlaneUrl,
          username,
          email,
          password: registerPassword,
          public_key: keyPair.public_key
        });
      },
      (response) => {
        setAuthView("login");
        setLoginUsername(response.username);
        setRegisterUsername("");
        setRegisterEmail("");
        setRegisterPassword("");
        setRegisterConfirmPassword("");
        setStatusMessage("Account created.");
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
        setCurrentUsername(username);
        setLoginPassword("");
        setStatusMessage("");
        setIsPowerOn(true);
        setPeers([]);
        setPeerPresence({});
        setServerList([]);
        setActiveServerId("");

        if (saveLogin) {
          const session: SavedLoginSession = {
            control_plane_url: controlPlaneUrl,
            username,
            access_token: response.access_token,
            expires_at: response.expires_at
          };

          setSavedLogin(session);
          setSecureStorageState("available");
          void saveLoginSession({ session }).catch(() => {
            setSecureStorageState("unavailable");
          });
        } else {
          setSavedLogin(null);
          void clearLoginSession();
        }

        void refreshLocalAddresses();
      }
    );
  }

  function onUseSavedLogin() {
    if (!savedLogin) {
      return;
    }

    const expiresAtMs = Date.parse(savedLogin.expires_at);
    if (Number.isFinite(expiresAtMs) && expiresAtMs < Date.now()) {
      void clearLoginSession();
      setSavedLogin(null);
      setError("Saved login expired. Sign in again.");
      return;
    }

    setCurrentUsername(savedLogin.username);
    setAccessToken(savedLogin.access_token);
    setControlPlaneUrl(savedLogin.control_plane_url);
    setStatusMessage("");
    setError(null);
    setIsPowerOn(true);
    setPeers([]);
    setPeerPresence({});
    setServerList([]);
    setActiveServerId("");
    void refreshLocalAddresses();
  }

  function onLogout() {
    setAccessToken("");
    setCurrentUsername("");
    setLoginPassword("");
    setError(null);
    setStatusMessage("Signed out.");
    setIsPowerOn(true);
    setLocalAddresses({ ipv4: [], ipv6: [] });
    setPeers([]);
    setPeerPresence({});
    setServerList([]);
    setActiveServerId("");
    void clearLoginSession();
    setSavedLogin(null);
  }

  if (!isAuthenticated) {
    return (
      <div className="page">
        <div className="backdrop" />
        <main className="auth-shell">
          <section className="panel auth-panel">
            <p className="badge">KAKACHI</p>
            <h1>Virtual LAN for real people</h1>
            <p className="supporting-copy">Normal login. Create/join servers. See members online.</p>

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
            {statusMessage ? <p className="banner status">{statusMessage}</p> : null}
            <p className="inline-info">
              Secure save login: {secureStorageState === "unknown" ? "checking..." : secureStorageState}.
            </p>
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
            <p className="supporting-copy">
              Sign in as <span className="username-accent">{currentUsername}</span>
            </p>
          </div>
          <div className="topbar-actions">
            <button
              type="button"
              className={`power-btn ${isPowerOn ? "on" : "off"}`}
              onClick={onTogglePower}
              aria-label={isPowerOn ? "Turn power off" : "Turn power on"}
            >
              <span className="power-symbol">⏻</span>
              <span>{isPowerOn ? "On" : "Off"}</span>
            </button>
            <button className="secondary" onClick={onLogout}>
              Log out
            </button>
          </div>
        </header>

        <section className="panel address-panel">
          <h2>This Device</h2>
          <div className="address-grid">
            <div className="address-item">
              <span className="address-label">IPv4</span>
              <span className="address-value">{localAddresses.ipv4[0] ?? "Not available"}</span>
            </div>
            <div className="address-item">
              <span className="address-label">IPv6</span>
              <span className="address-value">{localAddresses.ipv6[0] ?? "Not available"}</span>
            </div>
          </div>
        </section>

        <section className="grid">
          <article className="panel">
            <div className="section-head">
              <h2>Servers</h2>
              <span className={`power-state ${isPowerOn ? "on" : "off"}`}>
                {isPowerOn ? "online" : "offline"}
              </span>
            </div>

            <form onSubmit={onCreateNetwork} className="form-stack">
              <label>
                Create network
                <input value={networkName} onChange={(event) => setNetworkName(event.target.value)} />
              </label>
              <button disabled={!!busy || !isPowerOn} type="submit">
                {busy === "Create network" ? "Creating..." : "Create network"}
              </button>
            </form>

            <form onSubmit={onJoinNetwork} className="form-stack">
              <label>
                Join with network ID
                <input value={joinNetworkId} onChange={(event) => setJoinNetworkId(event.target.value)} />
              </label>
              <button disabled={!!busy || !isPowerOn} type="submit">
                {busy === "Join network" ? "Joining..." : "Join network"}
              </button>
            </form>

            <div className="server-list">
              {serverList.length === 0 ? (
                <p className="inline-info">No servers yet.</p>
              ) : (
                serverList.map((server) => (
                  <button
                    key={server.network_id}
                    type="button"
                    className={`server-item ${activeServerId === server.network_id ? "active" : ""}`}
                    onClick={() => onSelectServer(server)}
                  >
                    <span className={`server-dot ${isPowerOn ? "on" : "off"}`} />
                    <span className="server-main">
                      <span className="server-name">{server.name}</span>
                      <span className="server-sub">{server.members.length} member(s)</span>
                    </span>
                    <span className="server-tail">{server.members.length}</span>
                  </button>
                ))
              )}
            </div>
          </article>

          <article className="panel">
            <div className="section-head">
              <h2>Members</h2>
              <button
                type="button"
                className="secondary slim-btn"
                disabled={!!busy || !activeServerId || !isPowerOn}
                onClick={onRefreshActiveServerMembers}
              >
                {busy === "Refresh members" ? "Refreshing..." : "Refresh"}
              </button>
            </div>

            {activeServer ? (
              <p className="inline-info">Server: {activeServer.name}</p>
            ) : (
              <p className="inline-info">Select a server to view members.</p>
            )}

            <div className="peer-list">
              {activeServer ? (
                displayedMembers.length === 0 ? (
                  <p className="inline-info">No members visible yet.</p>
                ) : (
                  displayedMembers.map((member) => {
                    const presence = peerPresence[member.username];
                    const isOnline =
                      member.username === currentUsername ? isPowerOn : (presence?.online ?? false);

                    return (
                      <div key={member.username} className="peer-item">
                        <span className={`server-dot ${isOnline ? "on" : "off"}`} />
                        <span className="peer-details">
                          <span className="peer-name">
                            {member.username}
                            {member.username === currentUsername ? " (you)" : ""}
                          </span>
                          <span className="peer-last-seen">
                            {isOnline ? "Active now" : formatLastSeen(presence?.lastSeenAt ?? null)}
                          </span>
                        </span>
                        <span className={`peer-presence ${isOnline ? "online" : "offline"}`}>
                          {isOnline ? "online" : "offline"}
                        </span>
                      </div>
                    );
                  })
                )
              ) : null}
            </div>
          </article>
        </section>

        {error ? <p className="banner error">{error}</p> : null}
        {statusMessage ? <p className="banner status">{statusMessage}</p> : null}
      </main>
    </div>
  );
}
