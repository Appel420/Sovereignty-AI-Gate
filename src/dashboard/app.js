/**
 * app.js — Sovereignty AI Gate Dashboard application.
 *
 * Offline-first. No framework. No nondeterministic randomness.
 * All entropy via crypto.getRandomValues() or deterministic hashing.
 */

"use strict";

import compliance from "./deterministic/compliance.js";
import threatFeed from "./deterministic/threat_feed.js";

// ── Helpers ──────────────────────────────────────────────────────────────────

async function sha512Hex(str) {
  const encoded = new TextEncoder().encode(str);
  const digest = await crypto.subtle.digest("SHA-512", encoded);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function setText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

function renderComplianceTable(snapshot) {
  const tbody = document.getElementById("compliance-body");
  if (!tbody) return;
  tbody.innerHTML = "";
  for (const [rfc, data] of Object.entries(snapshot)) {
    const tr = document.createElement("tr");
    tr.className = `compliance-row ${data.result}`;
    tr.innerHTML = `
      <td>${rfc}</td>
      <td class="status-badge ${data.result}">${data.result.toUpperCase()}</td>
      <td>${new Date(data.recordedAt).toLocaleString()}</td>
    `;
    tbody.appendChild(tr);
  }
}

function renderAuditList(entries) {
  const list = document.getElementById("audit-list");
  if (!list) return;
  list.innerHTML = "";
  for (const entry of [...entries].reverse().slice(0, 20)) {
    const li = document.createElement("li");
    li.textContent = `[${entry.timestamp}] ${entry.event_type} — ${entry.actor_id}`;
    list.appendChild(li);
  }
}

function renderBoundaries(boundaries) {
  const ul = document.getElementById("boundaries-list");
  if (!ul) return;
  ul.innerHTML = "";
  for (const b of boundaries) {
    const li = document.createElement("li");
    li.textContent = `${b.boundary_id} (${b.boundary_type}) — ${b.model_id}`;
    ul.appendChild(li);
  }
}

// ── Initialization ────────────────────────────────────────────────────────────

async function init() {
  // Load state from localStorage (persisted offline state)
  let state = {};
  try {
    const raw = localStorage.getItem("sia_dashboard_state");
    if (raw) state = JSON.parse(raw);
  } catch (_) {
    // Fresh state
  }

  // Load compliance snapshot if available
  const complianceData = state.compliance_status || {};
  if (Object.keys(complianceData).length > 0) {
    compliance.loadSnapshot(complianceData);
  }

  // Render
  const indicator = document.getElementById("status-indicator");
  if (indicator) {
    indicator.textContent = "Online (Offline Mode)";
    indicator.className = "status-indicator active";
  }

  renderComplianceTable(compliance.snapshot());
  renderAuditList(state.audit_entries || []);
  renderBoundaries(state.boundaries || []);

  // Compute deterministic state hash
  const stateStr = JSON.stringify(state);
  const stateHash = await sha512Hex(stateStr);
  setText("state-hash", `State: ${stateHash.slice(0, 16)}…`);
}

document.addEventListener("DOMContentLoaded", init);
