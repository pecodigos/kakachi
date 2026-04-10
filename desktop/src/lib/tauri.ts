import { invoke } from "@tauri-apps/api/core";

export interface HealthResponse {
  status: string;
  timestamp: string;
}

export interface GeneratedKeyPair {
  public_key: string;
  private_key: string;
}

export interface RegisterResponse {
  username: string;
  public_key: string;
  created_at: string;
}

export interface LoginResponse {
  access_token: string;
  expires_at: string;
}

export interface PeerIdentity {
  username: string;
  public_key: string;
}

export interface NetworkSummary {
  network_id: string;
  name: string;
  owner: string;
  members: PeerIdentity[];
  created_at: string;
}

export interface SessionPeerReport {
  username: string;
  nat_type: string;
  attempt: number;
  candidate_count: number;
  direct_ready: boolean;
  reported_at: string;
}

export interface SessionSummary {
  session_id: string;
  network_id: string;
  initiator: string;
  responder: string;
  state: "negotiating_direct" | "direct_ready" | "relay_required";
  path: "direct" | "relay";
  reason: string;
  reports: SessionPeerReport[];
}

export interface NegotiationRunSummary {
  session_id: string;
  final_state: "negotiating_direct" | "direct_ready" | "relay_required";
  final_path: "direct" | "relay";
  final_reason: string;
  attempts_sent: number;
  last_report: {
    nat_type: string;
    attempt: number;
    candidate_count: number;
    direct_ready: boolean;
  } | null;
  last_candidates: string[];
  hole_punch: HolePunchTelemetry | null;
}

export interface HolePunchAttempt {
  attempt: number;
  peer_candidates: string[];
  ack_endpoint: string | null;
  acknowledged: boolean;
  latency_ms: number | null;
  send_errors: string[];
}

export interface HolePunchTelemetry {
  success: boolean;
  attempts: HolePunchAttempt[];
}

export interface ApiIdentity {
  control_plane_url: string;
  access_token: string;
}

function mapError(error: unknown): Error {
  if (error instanceof Error) {
    return error;
  }

  if (typeof error === "string") {
    return new Error(error);
  }

  return new Error("Unexpected desktop bridge error");
}

async function invokeTyped<T>(command: string, payload?: Record<string, unknown>): Promise<T> {
  try {
    return await invoke<T>(command, payload);
  } catch (error) {
    throw mapError(error);
  }
}

export function pingControlPlane(controlPlaneUrl: string): Promise<HealthResponse> {
  return invokeTyped("health_check", {
    input: {
      control_plane_url: controlPlaneUrl,
    },
  });
}

export function generateWireguardIdentity(): Promise<GeneratedKeyPair> {
  return invokeTyped("generate_wireguard_identity");
}

export function registerUser(input: {
  control_plane_url: string;
  username: string;
  password: string;
  public_key: string;
}): Promise<RegisterResponse> {
  return invokeTyped("register_user", { input });
}

export function loginUser(input: {
  control_plane_url: string;
  username: string;
  password: string;
}): Promise<LoginResponse> {
  return invokeTyped("login_user", { input });
}

export function createNetwork(input: {
  control_plane_url: string;
  access_token: string;
  name: string;
}): Promise<NetworkSummary> {
  return invokeTyped("create_network", { input });
}

export function joinNetwork(input: {
  control_plane_url: string;
  access_token: string;
  network_id: string;
}): Promise<NetworkSummary> {
  return invokeTyped("join_network", { input });
}

export function listPeers(input: {
  control_plane_url: string;
  access_token: string;
  network_id: string;
}): Promise<PeerIdentity[]> {
  return invokeTyped("list_peers", { input });
}

export function openSession(input: {
  control_plane_url: string;
  access_token: string;
  network_id: string;
  peer_username: string;
}): Promise<SessionSummary> {
  return invokeTyped("open_session_negotiation", { input });
}

export function getSession(input: {
  control_plane_url: string;
  access_token: string;
  network_id: string;
  session_id: string;
}): Promise<SessionSummary> {
  return invokeTyped("get_session_negotiation", { input });
}

export function runSessionProbe(input: {
  control_plane_url: string;
  access_token: string;
  network_id: string;
  peer_username: string;
  stun_servers: string[];
  local_bind_addr: string;
  session_id?: string;
}): Promise<NegotiationRunSummary> {
  return invokeTyped("run_session_negotiation", { input });
}
