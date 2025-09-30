const { contextBridge } = require("electron");
const fs = require("fs");
const path = require("path");

const API_BASE = "http://127.0.0.1:8787";
const SESSION_FILE = path.join(__dirname, "session.json");

function saveSession(session) {
  fs.writeFileSync(SESSION_FILE, JSON.stringify(session, null, 2));
}
function loadSession() {
  if (fs.existsSync(SESSION_FILE)) {
    return JSON.parse(fs.readFileSync(SESSION_FILE, "utf-8"));
  }
  return null;
}
function clearSession() {
  if (fs.existsSync(SESSION_FILE)) {
    fs.unlinkSync(SESSION_FILE);
  }
}

async function apiFetch(url, opts = {}) {
  const res = await fetch(API_BASE + url, {
    ...opts,
    headers: {
      "Content-Type": "application/json",
      ...(opts.headers || {}),
    },
  });

  const text = await res.text();

  if (!res.ok) {
    throw new Error(text || res.statusText);
  }

  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

contextBridge.exposeInMainWorld("api", {
  health: async () => {
    const res = await fetch(`${API_BASE}/healthz`);
    return res.text();
  },

  register: async (email, password) => {
    const data = await apiFetch("/register", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    });
    saveSession(data);
    return data;
  },

  login: async (email, password) => {
    const data = await apiFetch("/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    });
    saveSession(data);
    return data;
  },

  session: () => loadSession(),
  logout: () => clearSession(),

  createVault: async (orgId, name) => {
    const session = loadSession();
    if (!session?.access_token) throw new Error("Not logged in");

    await apiFetch(`/orgs/${orgId}/vaults`, {
      method: "POST",
      headers: { Authorization: `Bearer ${session.access_token}` },
      body: JSON.stringify({ name }),
    });

    const vault = {
      id: crypto.randomUUID(),
      name,
      org_id: orgId,
      org_name:
        session.vaults.find((v) => v.org_id === orgId)?.org_name ||
        "Unknown org",
      org_kind:
        session.vaults.find((v) => v.org_id === orgId)?.org_kind || "unknown",
    };

    session.vaults.push(vault);
    saveSession(session);
    return vault;
  },

  // --- Item APIs ---
  createItem: async (vaultId, encrypted) => {
    const session = loadSession();
    if (!session?.access_token) throw new Error("Not logged in");

    return apiFetch(`/vaults/${vaultId}/items`, {
      method: "POST",
      headers: { Authorization: `Bearer ${session.access_token}` },
      body: JSON.stringify(encrypted),
    });
  },

  listItems: async (vaultId) => {
    const session = loadSession();
    if (!session?.access_token) throw new Error("Not logged in");

    return apiFetch(`/vaults/${vaultId}/items`, {
      headers: { Authorization: `Bearer ${session.access_token}` },
    });
  },

  updateItem: async (vaultId, itemId, encrypted) => {
    const session = loadSession();
    if (!session?.access_token) throw new Error("Not logged in");

    return apiFetch(`/vaults/${vaultId}/items/${itemId}`, {
      method: "PUT",
      headers: { Authorization: `Bearer ${session.access_token}` },
      body: JSON.stringify(encrypted),
    });
  },

  deleteItem: async (vaultId, itemId) => {
    const session = loadSession();
    if (!session?.access_token) throw new Error("Not logged in");

    return apiFetch(`/vaults/${vaultId}/items/${itemId}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${session.access_token}` },
    });
  },
});
