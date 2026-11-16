// Step-by-step view: shown under the Encrypt and Decrypt panels when its switch is on.
// It traces the message and key from the Encrypt panel, pages steps in from the API and
// hands each step to the view for the selected algorithm.

import { api } from "./api.js";
import { createA51View } from "./a51_visualization.js";
import { clear, el, readCipherFields } from "./dom.js";
import { createRc4View } from "./rc4_visualization.js";
import { StepControls } from "./step_controls.js";

const PAGE_SIZE = { rc4: 64, a51: 128 };
const TOGGLE_STORAGE_KEY = "stream-cipher-lab.show-steps";

// Holds pages of a trace on the client, so revisiting a step needs no further request.
class TraceStore {
  constructor(request, pageSize, firstResponse) {
    this.request = request;
    this.pageSize = pageSize;
    this.total = firstResponse.total_steps;
    this.summary = firstResponse.summary;
    this.pages = new Map([[0, Promise.resolve(firstResponse.steps)]]);
  }

  static async open(request, pageSize) {
    const first = await api.visualize({ ...request, start: 0, count_steps: pageSize });
    return new TraceStore(request, pageSize, first);
  }

  loadPage(page) {
    if (!this.pages.has(page)) {
      const promise = api
        .visualize({ ...this.request, start: page * this.pageSize, count_steps: this.pageSize, include_summary: false })
        .then((response) => response.steps);
      promise.catch(() => this.pages.delete(page));
      this.pages.set(page, promise);
    }
    return this.pages.get(page);
  }

  async get(index) {
    const page = Math.floor(index / this.pageSize);
    const steps = await this.loadPage(page);
    // Fetch the next page early, so playback does not stall at a page boundary.
    const offset = index - page * this.pageSize;
    const nextStart = (page + 1) * this.pageSize;
    if (offset > this.pageSize * 0.75 && nextStart < this.total) this.loadPage(page + 1).catch(() => {});
    return steps[offset];
  }
}

function readSavedToggle() {
  try {
    return window.localStorage.getItem(TOGGLE_STORAGE_KEY) === "on";
  } catch {
    return false;
  }
}

function saveToggle(on) {
  try {
    window.localStorage.setItem(TOGGLE_STORAGE_KEY, on ? "on" : "off");
  } catch {
    // Storage can be unavailable, for example in a private window. The switch still works.
  }
}

export function initVisualizationMode(state) {
  const encryptForm = document.getElementById("encrypt-form");
  const toggle = document.getElementById("viz-toggle");
  const section = document.getElementById("viz-section");
  const workspace = document.getElementById("viz-workspace");
  const stage = document.getElementById("viz-stage");
  const loading = document.getElementById("viz-loading");
  const errorBox = document.getElementById("viz-error");
  const emptyNote = document.getElementById("viz-empty");
  const segmentField = document.getElementById("viz-segment-field");
  const segmentSelect = document.getElementById("viz-segment");
  const phaseTitle = document.getElementById("stage-phase-title");
  const phaseDesc = document.getElementById("stage-phase-desc");
  const explanation = document.getElementById("stage-explanation");
  const strideGroup = document.getElementById("ctl-stride-group");

  let enabled = false;
  let store = null;
  let view = null;
  let buildToken = 0;

  const controls = new StepControls(
    async (index, context) => {
      if (!store) return;
      let step;
      try {
        step = await store.get(index);
      } catch (error) {
        controls.pause();
        showError(error.message);
        return;
      }
      if (!context.isCurrent()) return;
      const phase = controls.currentPhase();
      phaseTitle.textContent = phase.title;
      phaseDesc.textContent = phase.description;
      explanation.textContent = step.explanation;
      strideGroup.hidden = !(state.algorithm === "a51" && step.phase === "xor");
      view.render(step, index, context);
    },
    () => enabled && state.view === "workspace",
  );

  function showError(message) {
    errorBox.textContent = message;
    errorBox.hidden = false;
  }

  function resetTrace() {
    buildToken += 1;
    controls.pause();
    controls.total = 0;
    store = null;
    if (view) view.destroy();
    view = null;
    clear(stage);
    workspace.hidden = true;
    segmentField.hidden = true;
    errorBox.hidden = true;
    emptyNote.hidden = true;
    loading.hidden = true;
  }

  const readRequest = () => ({
    ...readCipherFields(encryptForm, state.algorithm),
    plaintext: encryptForm.elements.plaintext.value,
    input_format: encryptForm.elements.input_format.value,
  });

  function fillSegments(summary) {
    clear(segmentSelect);
    if (state.algorithm !== "a51" || summary.segment_count < 2) {
      segmentField.hidden = true;
      return;
    }
    for (const segment of summary.segments) {
      segmentSelect.append(
        el("option", { value: String(segment.index), text: `Segment ${segment.index + 1} · COUNT ${segment.count_hex}` }),
      );
    }
    segmentSelect.value = String(summary.selected_segment);
    segmentField.hidden = false;
  }

  async function build(options = {}) {
    if (!enabled) return;
    const keepSegments = options.segment !== undefined;
    const previousSegmentField = segmentField.hidden;
    resetTrace();
    if (keepSegments) segmentField.hidden = previousSegmentField;
    const algorithm = state.algorithm;
    const request = readRequest();
    if (request.plaintext === "" || request.key.trim() === "") {
      emptyNote.hidden = false;
      return;
    }
    if (keepSegments) request.segment = options.segment;
    const token = buildToken;
    loading.hidden = false;
    try {
      const opened = await TraceStore.open(request, PAGE_SIZE[algorithm]);
      if (token !== buildToken) return;
      store = opened;
      view = algorithm === "rc4" ? createRc4View(stage, store.summary) : createA51View(stage, store.summary);
      fillSegments(store.summary);
      workspace.hidden = false;
      await controls.configure(store.total, store.summary.phases, options.index ?? 0);
    } catch (error) {
      if (token === buildToken) showError(error.message);
    } finally {
      if (token === buildToken) loading.hidden = true;
    }
  }

  function setEnabled(on, options = {}) {
    enabled = on;
    toggle.checked = on;
    section.hidden = !on;
    saveToggle(on);
    if (!on) {
      resetTrace();
      return;
    }
    build();
    if (options.scroll) section.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  toggle.addEventListener("change", () => setEnabled(toggle.checked, { scroll: true }));

  segmentSelect.addEventListener("change", () => {
    build({ segment: Number(segmentSelect.value), index: controls.index });
  });

  state.subscribe((change) => {
    if (change === "algorithm" || change === "inputs") {
      // A trace for other inputs or the other algorithm must not stay on screen.
      resetTrace();
      build();
    }
    if (change === "view" && state.view !== "workspace") controls.pause();
  });

  setEnabled(readSavedToggle());
  initSimplifiedDemo();
}

// The 8-element teaching demonstration. Steps also come from the Python implementation.
function initSimplifiedDemo() {
  const array = document.getElementById("toy-array");
  const equation = document.getElementById("toy-equation");
  const counter = document.getElementById("toy-counter");
  const error = document.getElementById("toy-error");
  const keyInput = document.getElementById("toy-key");
  let data = null;
  let index = -1;

  function render() {
    const step = index >= 0 ? data.steps[index] : null;
    const values = step ? step.S : data.initial;
    clear(array);
    values.forEach((value, position) => {
      const cell = el(
        "div",
        { className: "toy-cell" },
        el("span", { className: "cell-index", text: String(position) }),
        el("span", { className: "cell-value mono", text: String(value) }),
      );
      if (step && position === step.i) cell.classList.add("cell-i");
      if (step && position === step.j) cell.classList.add("cell-j");
      array.append(cell);
    });
    counter.textContent = `Iteration ${index + 1} / ${data.steps.length}`;
    equation.textContent = step
      ? `${step.equation}, then swap positions ${step.i} and ${step.j}`
      : `S = [${data.initial.join(", ")}], key = [${data.key.join(", ")}]`;
    document.getElementById("toy-prev").disabled = index < 0;
    document.getElementById("toy-next").disabled = index >= data.steps.length - 1;
  }

  async function load() {
    error.hidden = true;
    const key = keyInput.value.split(/[\s,]+/).filter(Boolean);
    try {
      data = await api.simplifiedRc4({ key });
      index = -1;
      render();
    } catch (failure) {
      error.textContent = failure.message;
      error.hidden = false;
    }
  }

  document.getElementById("toy-build").addEventListener("click", load);
  document.getElementById("toy-prev").addEventListener("click", () => {
    if (data && index >= 0) {
      index -= 1;
      render();
    }
  });
  document.getElementById("toy-next").addEventListener("click", () => {
    if (data && index < data.steps.length - 1) {
      index += 1;
      render();
    }
  });
  document.getElementById("toy-rc4").addEventListener("toggle", (event) => {
    if (event.target.open && !data) load();
  });
}
