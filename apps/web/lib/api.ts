import type {
  AdaptiveRun,
  ArchivedRunDetail,
  ArchivedRunSummary,
  AuthSession,
  BenignBenchmark,
  Catalog,
  CredentialCheck,
  LabMessageResult,
  LabSession,
  LabSessionDetail,
  LabSubmissionResult,
  MatrixEstimate,
  MatrixRun,
} from "./types";

let authToken = "";

export function setApiAuthToken(token: string | null): void {
  authToken = token ?? "";
}

function apiHeaders(extra: HeadersInit = {}): HeadersInit {
  return {
    ...extra,
    ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
  };
}

async function parseResponse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    const payload = (await response.json().catch(() => null)) as { detail?: string } | null;
    throw new Error(payload?.detail ?? `API request failed (${response.status})`);
  }
  return response.json() as Promise<T>;
}

export async function login(username: string, password: string): Promise<AuthSession> {
  const response = await fetch("/api/v1/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  return parseResponse<AuthSession>(response);
}

export async function signup(username: string, password: string): Promise<AuthSession> {
  const response = await fetch("/api/v1/auth/signup", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  return parseResponse<AuthSession>(response);
}

export async function fetchCurrentUser(signal?: AbortSignal): Promise<AuthSession> {
  const response = await fetch("/api/v1/auth/me", {
    signal,
    cache: "no-store",
    headers: apiHeaders(),
  });
  return parseResponse<AuthSession>(response);
}

export async function fetchCatalog(signal?: AbortSignal): Promise<Catalog> {
  const response = await fetch("/api/v1/catalog", {
    signal,
    cache: "no-store",
    headers: apiHeaders(),
  });
  return parseResponse<Catalog>(response);
}

export async function fetchRunArchive(signal?: AbortSignal): Promise<ArchivedRunSummary[]> {
  const response = await fetch("/api/v1/runs?limit=200", {
    signal,
    cache: "no-store",
    headers: apiHeaders(),
  });
  return parseResponse<ArchivedRunSummary[]>(response);
}

export async function fetchArchivedRun(runId: string): Promise<ArchivedRunDetail> {
  const response = await fetch(`/api/v1/runs/${runId}`, {
    cache: "no-store",
    headers: apiHeaders(),
  });
  return parseResponse<ArchivedRunDetail>(response);
}

export async function deleteArchivedRun(runId: string): Promise<void> {
  const response = await fetch(`/api/v1/runs/${runId}`, {
    method: "DELETE",
    headers: apiHeaders(),
  });
  if (!response.ok) {
    const payload = (await response.json().catch(() => null)) as { detail?: string } | null;
    throw new Error(payload?.detail ?? `API request failed (${response.status})`);
  }
}

export async function exportArchivedRun(runId: string, format: "csv" | "json"): Promise<Blob> {
  const response = await fetch(`/api/v1/runs/${runId}/export?format=${format}`, {
    headers: apiHeaders(),
  });
  if (!response.ok) {
    const payload = (await response.json().catch(() => null)) as { detail?: string } | null;
    throw new Error(payload?.detail ?? `API request failed (${response.status})`);
  }
  return response.blob();
}

export async function runBenignBenchmark(payload: {
  target_ids: string[];
  defense_column_ids: string[];
}): Promise<BenignBenchmark> {
  const response = await fetch("/api/v1/benchmarks/benign", {
    method: "POST",
    headers: apiHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify(payload),
  });
  return parseResponse<BenignBenchmark>(response);
}

export async function estimateMatrix(
  payload: {
    target_ids: string[];
    attack_ids: string[];
    model_ids: string[];
    defense_column_ids: string[];
    trials: number;
    max_turns: number;
  },
  signal?: AbortSignal,
): Promise<MatrixEstimate> {
  const response = await fetch("/api/v1/matrix/estimate", {
    method: "POST",
    headers: apiHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify(payload),
    signal,
  });
  return parseResponse<MatrixEstimate>(response);
}

export async function runStaticMatrix(payload: {
  target_id: string;
  attack_ids: string[];
  model_ids: string[];
  defense_column_ids: string[];
  corpus_mode: "full";
  temperature: number;
  credentials: Record<string, string>;
}): Promise<MatrixRun> {
  const response = await fetch("/api/v1/matrix/run-static", {
    method: "POST",
    headers: apiHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify(payload),
  });
  return parseResponse<MatrixRun>(response);
}

export async function runAdaptiveMatrix(payload: {
  target_id: string;
  attack_id: "decomposition" | "crescendo" | "pair" | "tap";
  model_ids: string[];
  attacker_model_id?: string | null;
  defense_column_ids: string[];
  trials: number;
  temperature: number;
  max_queries: number;
  max_attacker_queries: number;
  max_submissions: number;
  max_branches: number;
  credentials: Record<string, string>;
}): Promise<AdaptiveRun> {
  const response = await fetch("/api/v1/matrix/run-adaptive", {
    method: "POST",
    headers: apiHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify(payload),
  });
  return parseResponse<AdaptiveRun>(response);
}

export async function checkCredential(providerId: string, apiKey: string): Promise<CredentialCheck> {
  const response = await fetch(`/api/v1/providers/${providerId}/credential-check`, {
    method: "POST",
    headers: apiHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({ api_key: apiKey }),
  });
  return parseResponse<CredentialCheck>(response);
}

export async function createLabSession(payload: {
  target_id: string;
  provider_id: string;
  model_id: string;
  temperature: number;
  defense_column_id: string;
}): Promise<LabSession> {
  const response = await fetch("/api/v1/lab/sessions", {
    method: "POST",
    headers: apiHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify(payload),
  });
  return parseResponse<LabSession>(response);
}

export async function fetchLabSessions(signal?: AbortSignal): Promise<LabSession[]> {
  const response = await fetch("/api/v1/lab/sessions", {
    signal,
    cache: "no-store",
    headers: apiHeaders(),
  });
  return parseResponse<LabSession[]>(response);
}

export async function fetchLabSession(sessionId: string): Promise<LabSessionDetail> {
  const response = await fetch(`/api/v1/lab/sessions/${sessionId}`, {
    cache: "no-store",
    headers: apiHeaders(),
  });
  return parseResponse<LabSessionDetail>(response);
}

export async function sendLabMessage(
  sessionId: string,
  apiKey: string | null,
  content: string,
): Promise<LabMessageResult> {
  const response = await fetch(`/api/v1/lab/sessions/${sessionId}/messages`, {
    method: "POST",
    headers: apiHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({ api_key: apiKey || null, content }),
  });
  return parseResponse<LabMessageResult>(response);
}

export async function submitLabCandidate(
  sessionId: string,
  candidate: string,
): Promise<LabSubmissionResult> {
  const response = await fetch(`/api/v1/lab/sessions/${sessionId}/submit`, {
    method: "POST",
    headers: apiHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({ candidate }),
  });
  return parseResponse<LabSubmissionResult>(response);
}

export async function closeLabSession(sessionId: string): Promise<LabSession> {
  const response = await fetch(`/api/v1/lab/sessions/${sessionId}/close`, {
    method: "POST",
    headers: apiHeaders(),
  });
  return parseResponse<LabSession>(response);
}

export async function deleteLabSession(sessionId: string): Promise<void> {
  const response = await fetch(`/api/v1/lab/sessions/${sessionId}`, {
    method: "DELETE",
    headers: apiHeaders(),
  });
  if (!response.ok) {
    const payload = (await response.json().catch(() => null)) as { detail?: string } | null;
    throw new Error(payload?.detail ?? `API request failed (${response.status})`);
  }
}
