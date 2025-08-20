const { contextBridge } = require("electron");

const API_BASE = "http://127.0.0.1:8787";

console.log(">>> preload loaded");

contextBridge.exposeInMainWorld("api", {
  health: async () => {
    const res = await fetch(`${API_BASE}/healthz`);
    return res.text();
  },
  ping: () => "pong",
});
