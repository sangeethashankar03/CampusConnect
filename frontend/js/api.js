function parseServerTimestamp(ts) {
  // Handles both plain "YYYY-MM-DD HH:MM:SS" style timestamps and proper
  // ISO 8601 strings with "T" and a timezone offset -- different backends
  // format these differently, so don't assume just one.
  if (ts.includes("T")) return new Date(ts);
  return new Date(ts.replace(" ", "T") + "Z");
}

const API_BASE = "/api";

function getToken() {
  return localStorage.getItem("access_token");
}

function setToken(token) {
  localStorage.setItem("access_token", token);
}

function clearToken() {
  localStorage.removeItem("access_token");
}

async function apiFetch(path, options = {}) {
  const token = getToken();
  const headers = {
    "Content-Type": "application/json",
    ...(options.headers || {}),
  };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const response = await fetch(`${API_BASE}${path}`, { ...options, headers });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || `Request failed with status ${response.status}`);
  }
  return data;
}

async function apiFetchForm(path, formData, options = {}) {
  const token = getToken();
  const headers = { ...(options.headers || {}) };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    method: options.method || "POST",
    headers,
    body: formData,
  });
  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    throw new Error(data.error || `Request failed with status ${response.status}`);
  }
  return response;
}