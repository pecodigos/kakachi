import { FormEvent, useEffect, useMemo, useState } from "react";
import {
  clearLoginSession,
  createNetwork,
  generateWireguardIdentity,
  listPeerEndpointBundles,
  joinNetwork,
  loadLoginSession,
  listPeers,
  loginUser,
  registerUser,
  runSessionProbe,
  saveLoginSession,
  type NegotiationRunSummary,
  type NetworkSummary,
  type PeerEndpointBundle,
  type PeerIdentity,
  type SavedLoginSession
} from "./lib/tauri";

type AuthView = "login" | "register";
type PresenceState = "online" | "recent" | "unknown";
type SecureStorageState = "unknown" | "available" | "unavailable";
type QuickConnectSelectionSource = "typed" | "preferred" | "ranked";

interface PresenceHint {
  state: PresenceState;
  lastSeenAt: string | null;
  ageSeconds: number | null;
}

interface PreferredPeerRecord {
  username: string;
  lastConnectedAt: string;
}

type PreferredPeerMap = Record<string, PreferredPeerRecord>;

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const PREFERRED_PEERS_KEY = "kakachi.preferred-peers.v1";

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

  if (normalized.includes("keyring") || normalized.includes("secret service")) {
    return "Secure saved login is unavailable on this device. You can keep using Kakachi without save login.";
  }

  return message || "Something went wrong. Please try again.";
}

function readPreferredPeers(): PreferredPeerMap {
  if (typeof window === "undefined") {
    return {};
  }

  const raw = window.localStorage.getItem(PREFERRED_PEERS_KEY);
  if (!raw) {
    return {};
  }

  try {
    const parsed = JSON.parse(raw) as Record<string, Partial<PreferredPeerRecord>>;
    const safe: PreferredPeerMap = {};
    for (const [networkId, value] of Object.entries(parsed)) {
      if (
        typeof value.username === "string" &&
        value.username.trim().length > 0 &&
        typeof value.lastConnectedAt === "string"
      ) {
        safe[networkId] = {
          username: value.username,
          lastConnectedAt: value.lastConnectedAt
        };
      }
    }

    return safe;
  } catch {
    window.localStorage.removeItem(PREFERRED_PEERS_KEY);
    return {};
  }
}

function writePreferredPeers(payload: PreferredPeerMap) {
  if (typeof window === "undefined") {
    return;
  }

  window.localStorage.setItem(PREFERRED_PEERS_KEY, JSON.stringify(payload));
}

function presencePriority(state: PresenceState): number {
  if (state === "online") {
    return 0;
  }
  if (state === "recent") {
    return 1;
  }
  return 2;
}

function presenceLabel(state: PresenceState): string {
  if (state === "online") {
    return "online";
  }
  if (state === "recent") {
    return "recent";
  }
  return "unknown";
}

function presenceTimeLabel(hint: PresenceHint | undefined): string {
  if (!hint) {
    return "status unavailable";
  }

  if (hint.state === "online") {
    return "active now";
  }

  if (hint.ageSeconds === null) {
    return "last seen unknown";
  }

  if (hint.ageSeconds < 60) {
    return `${hint.ageSeconds}s ago`;
  }

  const minutes = Math.floor(hint.ageSeconds / 60);
  if (minutes < 60) {
    return `${minutes}m ago`;
  }

  const hours = Math.floor(minutes / 60);
  if (hours < 24) {
    return `${hours}h ago`;
  }

  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function buildPresenceHints(endpointBundles: PeerEndpointBundle[]): Record<string, PresenceHint> {
  const nowMs = Date.now();
  const hints: Record<string, PresenceHint> = {};

  for (const bundle of endpointBundles) {
    let freshestCandidateTs: number | null = null;

    for (const candidate of bundle.candidates) {
      const timestamp = Date.parse(candidate.observed_at);
      if (!Number.isFinite(timestamp)) {
        continue;
      }

      freshestCandidateTs = freshestCandidateTs === null ? timestamp : Math.max(freshestCandidateTs, timestamp);
    }

    if (freshestCandidateTs === null) {
      hints[bundle.username] = {
        state: "unknown",
        lastSeenAt: null,
        ageSeconds: null
      };
      continue;
    }

    const ageSeconds = Math.max(0, Math.floor((nowMs - freshestCandidateTs) / 1000));
    const state: PresenceState = ageSeconds <= 120 ? "online" : ageSeconds <= 900 ? "recent" : "unknown";

    hints[bundle.username] = {
      state,
      lastSeenAt: new Date(freshestCandidateTs).toISOString(),
      ageSeconds
    };
  }

  return hints;
}

function chooseQuickConnectPeer(
  candidates: PeerIdentity[],
  requestedPeer: string,
  preferredPeer: string | null,
  presenceHints: Record<string, PresenceHint>
): { username: string; source: QuickConnectSelectionSource } {
  const requested = requestedPeer.trim();

  if (requested && candidates.some((peer) => peer.username === requested)) {
    return { username: requested, source: "typed" };
  }

  if (preferredPeer && candidates.some((peer) => peer.username === preferredPeer)) {
    return {
      username: preferredPeer,
      source: "preferred"
    };
  }

  const ranked = [...candidates].sort((a, b) => {
    const hintA = presenceHints[a.username];
    const hintB = presenceHints[b.username];

    const priorityDelta =
      presencePriority(hintA?.state ?? "unknown") - presencePriority(hintB?.state ?? "unknown");
    if (priorityDelta !== 0) {
      return priorityDelta;
    }

    const ageA = hintA?.ageSeconds ?? Number.MAX_SAFE_INTEGER;
    const ageB = hintB?.ageSeconds ?? Number.MAX_SAFE_INTEGER;
    if (ageA !== ageB) {
      return ageA - ageB;
    }

    return a.username.localeCompare(b.username);
  });

  return {
    username: ranked[0].username,
    source: "ranked"
  };
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
  const [tokenExpiresAt, setTokenExpiresAt] = useState("");
  const [preferredPeers, setPreferredPeers] = useState<PreferredPeerMap>(() => readPreferredPeers());

  const [networkName, setNetworkName] = useState("friends-network");
  const [networkId, setNetworkId] = useState("");
  const [joinNetworkId, setJoinNetworkId] = useState("");
  const [serverList, setServerList] = useState<NetworkSummary[]>([]);
  const [peers, setPeers] = useState<PeerIdentity[]>([]);
  const [peerPresence, setPeerPresence] = useState<Record<string, PresenceHint>>({});
  const [activeNetwork, setActiveNetwork] = useState<NetworkSummary | null>(null);

  const [peerUsername, setPeerUsername] = useState("");
  const [connectIntent, setConnectIntent] = useState<"lan" | "vpn">("lan");
  const [stunServersCsv, setStunServersCsv] = useState("74.125.250.129:19302");
  const [localBindAddr, setLocalBindAddr] = useState("0.0.0.0:7001");
  const [runSummary, setRunSummary] = useState<NegotiationRunSummary | null>(null);

  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [secureStorageState, setSecureStorageState] = useState<SecureStorageState>("unknown");
  const [isPowerOn, setIsPowerOn] = useState(true);

  const canUseAuthedActions = accessToken.trim().length > 0 && currentUsername.trim().length > 0;

  useEffect(() => {
    let active = true;

    async function hydrateSavedLogin() {
      try {
        const saved = await loadLoginSession();
        if (!active || !saved) {
          return;
        }

        setSavedLogin(saved);
        setControlPlaneUrl(saved.control_plane_url);
        setLoginUsername(saved.username);
        setSecureStorageState("available");
        setStatusMessage(`Saved login found for ${saved.username}.`);
      } catch {
        if (!active) {
          return;
        }

        setSecureStorageState("unavailable");
        setStatusMessage("Secure saved login is unavailable. Sign in with username and password.");
      }
    }

    void hydrateSavedLogin();

    return () => {
      active = false;
    };
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
  const preferredPeer = networkId ? preferredPeers[networkId] : undefined;
  const activeServer =
    (networkId ? serverList.find((server) => server.network_id === networkId) : undefined) ?? activeNetwork;

  function resetNetworkState() {
    setNetworkId("");
    setJoinNetworkId("");
    setPeers([]);
    setPeerPresence({});
    setPeerUsername("");
    setRunSummary(null);
    setActiveNetwork(null);
  }

  function upsertServer(summary: NetworkSummary) {
    setServerList((current) => {
      const existing = current.filter((item) => item.network_id !== summary.network_id);
      return [summary, ...existing];
    });
  }

  function requirePowerOn(): boolean {
    if (!isPowerOn) {
      setError("Turn on power to manage or connect servers.");
      return false;
    }

    return true;
  }

  function onTogglePower() {
    const nextPowerState = !isPowerOn;
    setIsPowerOn(nextPowerState);
    setError(null);

    if (!nextPowerState) {
      setRunSummary(null);
      setStatusMessage("Power off. Server sessions are paused.");
      return;
    }

    setStatusMessage("Power on. Ready to connect.");
  }

  function onSelectServer(server: NetworkSummary) {
    setActiveNetwork(server);
    setNetworkId(server.network_id);
    setJoinNetworkId(server.network_id);
    setPeerUsername("");
    setRunSummary(null);
    setStatusMessage(`Selected server ${server.name}.`);

    if (isPowerOn) {
      void onRefreshPeers(server.network_id);
    }
  }

  function rememberPreferredPeer(currentNetworkId: string, username: string) {
    if (!currentNetworkId || !username) {
      return;
    }

    setPreferredPeers((current) => {
      const next = {
        ...current,
        [currentNetworkId]: {
          username,
          lastConnectedAt: new Date().toISOString()
        }
      };

      writePreferredPeers(next);
      return next;
    });
  }

  async function runAction<T>(label: string, operation: () => Promise<T>, onSuccess: (value: T) => void) {
    setBusy(label);
    setError(null);

    try {
      const value = await operation();
      onSuccess(value);
    } catch (err) {
      const technicalMessage = err instanceof Error ? err.message : "Unexpected error";
      if (technicalMessage === "USER_CANCELLED") {
        setStatusMessage(`${label} canceled.`);
        return;
      }

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
        setStatusMessage("");

        if (saveLogin) {
          const session: SavedLoginSession = {
            control_plane_url: controlPlaneUrl,
            username,
            access_token: response.access_token,
            expires_at: response.expires_at
          };

          setSavedLogin(session);
          void saveLoginSession({ session }).catch(() => {
            setSecureStorageState("unavailable");
            setStatusMessage("Signed in, but secure save login is unavailable on this device.");
          });
          setSecureStorageState("available");
        } else {
          setSavedLogin(null);
          void clearLoginSession();
        }
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
      setError("Saved login expired. Sign in with password again.");
      return;
    }

    setCurrentUsername(savedLogin.username);
    setAccessToken(savedLogin.access_token);
    setTokenExpiresAt(savedLogin.expires_at);
    setControlPlaneUrl(savedLogin.control_plane_url);
    setError(null);
    setStatusMessage("");
  }

  function onLogout() {
    setAccessToken("");
    setTokenExpiresAt("");
    setCurrentUsername("");
    setLoginPassword("");
    setServerList([]);
    setIsPowerOn(true);
    setError(null);
    setStatusMessage("Signed out.");
    resetNetworkState();
    void clearLoginSession();
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
    if (!requirePowerOn()) return;

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
        upsertServer(response);
        setActiveNetwork(response);
        setNetworkId(response.network_id);
        setJoinNetworkId(response.network_id);
        setPeerPresence({});
        setStatusMessage(`Network ${response.name} is ready.`);
      }
    );
  }

  async function onJoinNetwork(event: FormEvent) {
    event.preventDefault();
    if (!requireAuth()) return;
    if (!requirePowerOn()) return;

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
        upsertServer(response);
        setActiveNetwork(response);
        setNetworkId(response.network_id);
        setPeerPresence({});
        setStatusMessage(`Joined network ${response.name}.`);
      }
    );
  }

  async function onRefreshPeers(targetNetworkId?: string) {
    if (!requireAuth()) return;
    if (!requirePowerOn()) return;
    const selectedNetworkId = targetNetworkId ?? networkId;
    if (!selectedNetworkId) {
      setError("Create or join a network first.");
      return;
    }

    await runAction(
      "Refresh peers",
      async () => {
        const peerList = await listPeers({
          control_plane_url: controlPlaneUrl,
          access_token: accessToken,
          network_id: selectedNetworkId
        });

        let endpointBundles: PeerEndpointBundle[] = [];
        try {
          endpointBundles = await listPeerEndpointBundles({
            control_plane_url: controlPlaneUrl,
            access_token: accessToken,
            network_id: selectedNetworkId
          });
        } catch {
          endpointBundles = [];
        }

        return {
          peerList,
          presenceHints: buildPresenceHints(endpointBundles)
        };
      },
      ({ peerList, presenceHints }) => {
        setPeers(peerList);
        setPeerPresence(presenceHints);

        const otherPeers = peerList.filter((peer) => peer.username !== currentUsername);
        const onlineCount = otherPeers.filter(
          (peer) => (presenceHints[peer.username]?.state ?? "unknown") === "online"
        ).length;

        if (otherPeers.length === 0) {
          setStatusMessage("No peers in this network yet.");
        } else if (onlineCount > 0) {
          setStatusMessage(`Found ${otherPeers.length} peer(s). ${onlineCount} online now.`);
        } else {
          setStatusMessage(`Found ${otherPeers.length} peer(s). None marked online yet.`);
        }
      }
    );
  }

  async function onQuickConnect() {
    if (!requireAuth()) return;
    if (!requirePowerOn()) return;
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

        const candidates = peerList.filter((peer) => peer.username !== currentUsername);
        if (candidates.length === 0) {
          throw new Error("NO_PEERS_AVAILABLE");
        }

        const presenceHints = buildPresenceHints(endpointBundles);
        const selection = chooseQuickConnectPeer(
          candidates,
          peerUsername,
          preferredPeers[networkId]?.username ?? null,
          presenceHints
        );

        if (selection.source !== "typed") {
          const sourceText =
            selection.source === "preferred" ? "your preferred friend" : "the best online match";
          const approved = window.confirm(
            `Quick connect selected ${selection.username} (${sourceText}). Continue?`
          );

          if (!approved) {
            throw new Error("USER_CANCELLED");
          }
        }

        const summary = await runSessionProbe({
          control_plane_url: controlPlaneUrl,
          access_token: accessToken,
          network_id: networkId,
          peer_username: selection.username,
          stun_servers: parsedStunServers,
          local_bind_addr: localBindAddr,
          session_id: runSummary?.session_id
        });

        return {
          selectedPeer: selection.username,
          summary,
          peerList,
          presenceHints
        };
      },
      ({ selectedPeer, summary, peerList, presenceHints }) => {
        setPeers(peerList);
        setPeerPresence(presenceHints);
        setPeerUsername(selectedPeer);
        setRunSummary(summary);
        rememberPreferredPeer(networkId, selectedPeer);
        const pathLabel = summary.final_path === "direct" ? "direct LAN tunnel" : "relay tunnel";
        const usage = connectIntent === "lan" ? "LAN apps" : "VPN traffic";
        setStatusMessage(`Connected to ${selectedPeer} for ${usage} using ${pathLabel}.`);
      }
    );
  }

  async function onConnectPeer() {
    if (!requireAuth()) return;
    if (!requirePowerOn()) return;
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
        rememberPreferredPeer(networkId, trimmedPeer);
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

        <section className="grid">
          <article className="panel">
            <div className="section-head">
              <h2>Servers</h2>
              <span className={`power-state ${isPowerOn ? "on" : "off"}`}>
                {isPowerOn ? "Online" : "Offline"}
              </span>
            </div>
            <p className="inline-info">Create or join a network, then pick it from the list.</p>
            <form onSubmit={onCreateNetwork} className="form-stack">
              <label>
                New network name
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
                <p className="inline-info">No servers yet. Create or join your first one.</p>
              ) : (
                serverList.map((server) => (
                  <button
                    key={server.network_id}
                    type="button"
                    className={`server-item ${networkId === server.network_id ? "active" : ""}`}
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

            {networkId ? (
              <div className="action-row compact">
                <button className="secondary" type="button" onClick={onChangeNetwork}>
                  Clear active server
                </button>
                <button className="secondary" type="button" onClick={onCopyNetworkId}>
                  Copy invite code
                </button>
              </div>
            ) : null}
          </article>

          {networkId && activeServer ? (
            <article className="panel">
              <h2>Connect</h2>
              <p className="inline-info">Active server: {activeServer.name}</p>

              <div className="action-row compact">
                <button disabled={!!busy || !isPowerOn} onClick={() => onRefreshPeers()}>
                  {busy === "Refresh peers" ? "Refreshing..." : "Refresh peers"}
                </button>
                <button className="secondary" type="button" onClick={onCopyNetworkId}>
                  Copy invite code
                </button>
              </div>

              {!isPowerOn ? (
                <p className="inline-info">Power is off. Turn it on to connect to this server.</p>
              ) : null}

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

              <label>
                Friend username
                <input value={peerUsername} onChange={(event) => setPeerUsername(event.target.value)} />
              </label>

              <div className="peer-list">
                {visiblePeers.length === 0 ? (
                  <p className="inline-info">No peers available yet.</p>
                ) : (
                  visiblePeers.map((peer) => {
                    const hint = peerPresence[peer.username];
                    const status = hint?.state ?? "unknown";
                    return (
                      <button
                        key={peer.username}
                        type="button"
                        className="peer-item"
                        onClick={() => setPeerUsername(peer.username)}
                      >
                        <span className="server-dot on" />
                        <span className="peer-details">
                          <span className="peer-name">{peer.username}</span>
                          <span className="peer-last-seen">{presenceTimeLabel(hint)}</span>
                        </span>
                        <span className={`peer-presence ${status}`}>{presenceLabel(status)}</span>
                      </button>
                    );
                  })
                )}
              </div>

              <button className="quick-connect" disabled={!!busy || !isPowerOn} onClick={onQuickConnect}>
                {busy === "Quick connect" ? "Connecting..." : "Quick connect"}
              </button>
              <p className="inline-info">
                This picks the typed friend, then your preferred friend, then the best online candidate.
              </p>
              <p className="inline-info">Kakachi asks for confirmation before auto-connecting to a selected friend.</p>
              {preferredPeer ? (
                <p className="inline-info">
                  Preferred friend for this network: {preferredPeer.username}.
                </p>
              ) : null}

              <p className={`connection-pill ${runSummary?.final_path ?? "idle"}`}>{connectionLabel}</p>
              {runSummary ? <p className="inline-info">Reason: {runSummary.final_reason}</p> : null}

              <details>
                <summary>Manual controls</summary>

                <div className="action-row">
                  <button disabled={!!busy || !isPowerOn} onClick={() => onRefreshPeers()}>
                    {busy === "Refresh peers" ? "Refreshing..." : "Refresh peers"}
                  </button>
                  <button disabled={!!busy || !isPowerOn} onClick={onConnectPeer}>
                    {busy === "Connect" ? "Connecting..." : "Connect manually"}
                  </button>
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
              <p className="inline-info">Create or join a server, then select it from the list.</p>
            </article>
          )}
        </section>

        {error ? <p className="banner error">{error}</p> : null}
        {statusMessage ? <p className="banner status">{statusMessage}</p> : null}
        <p className="inline-info">Session expires at: {tokenExpiresAt}</p>
      </main>
    </div>
  );
}
