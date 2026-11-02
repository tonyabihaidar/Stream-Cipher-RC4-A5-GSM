// Application shell: tracks the selected algorithm and view, and starts each mode.

import { api } from "./api.js";
import { initDirectMode } from "./direct_mode.js";
import { initVisualizationMode } from "./visualization_mode.js";

const ALGORITHM_NAMES = { rc4: "RC4", a51: "A5/1" };

class AppState {
  constructor() {
    this.algorithm = "rc4";
    this.view = "direct";
    this.examples = [];
    this.listeners = new Set();
  }

  subscribe(listener) {
    this.listeners.add(listener);
  }

  emit(change) {
    this.listeners.forEach((listener) => listener(change));
  }

  setAlgorithm(algorithm) {
    if (algorithm === this.algorithm) return;
    this.algorithm = algorithm;
    this.emit("algorithm");
  }

  setView(view) {
    if (view === this.view) return;
    this.view = view;
    this.emit("view");
  }
}

function syncShell(state) {
  document.body.dataset.algo = state.algorithm;
  document.body.dataset.view = state.view;
  document.querySelectorAll("[data-set-algo]").forEach((button) => {
    button.setAttribute("aria-pressed", String(button.dataset.setAlgo === state.algorithm));
  });
  document.querySelectorAll("[data-set-view]").forEach((button) => {
    button.setAttribute("aria-pressed", String(button.dataset.setView === state.view));
  });
  document.querySelectorAll("[data-view-panel]").forEach((panel) => {
    panel.hidden = panel.dataset.viewPanel !== state.view;
  });
  document.querySelectorAll("[data-algo-name]").forEach((tag) => {
    tag.textContent = ALGORITHM_NAMES[state.algorithm];
  });
}

async function main() {
  const state = new AppState();
  document.querySelectorAll("[data-set-algo]").forEach((button) => {
    button.addEventListener("click", () => state.setAlgorithm(button.dataset.setAlgo));
  });
  document.querySelectorAll("[data-set-view]").forEach((button) => {
    button.addEventListener("click", () => state.setView(button.dataset.setView));
  });
  state.subscribe(() => syncShell(state));
  syncShell(state);

  try {
    state.examples = (await api.examples()).examples;
  } catch {
    state.examples = [];
  }

  initDirectMode(state);
  initVisualizationMode(state);
}

main();
