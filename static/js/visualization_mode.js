// Visualization Mode: builds traces, pages steps in from the API and hands each step to
// the view for the selected algorithm.

import { api } from "./api.js";
import { createA51View } from "./a51_visualization.js";
import {
  clear,
  clearFormError,
  el,
  populateExamples,
  readCipherFields,
  showFormError,
  syncCountMode,
  writeCipherFields,
} from "./dom.js";
import { createRc4View } from "./rc4_visualization.js";
import { StepControls } from "./step_controls.js";

const PAGE_SIZE = { rc4: 64, a51: 128 };

const DEFAULT_INPUTS = {
  rc4: { key: "Key", key_encoding: "text", plaintext: "Plaintext", input_format: "text" },
  a51: { key: "1223456789ABCDEF", count_mode: "count", count: "0x134", fn: "", direction: "downlink", plaintext: "HI", input_format: "text" },
};

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

export function initVisualizationMode(state) {
  const form = document.getElementById("viz-form");
  const workspace = document.getElementById("viz-workspace");
  const stage = document.getElementById("viz-stage");
  const loading = document.getElementById("viz-loading");
  const exampleSelect = document.getElementById("viz-example");
  const segmentField = document.getElementById("viz-segment-field");
  const segmentSelect = document.getElementById("viz-segment");
  const phaseTitle = document.getElementById("stage-phase-title");
  const phaseDesc = document.getElementById("stage-phase-desc");
  const explanation = document.getElementById("stage-explanation");
  const strideGroup = document.getElementById("ctl-stride-group");

  let store = null;
  let view = null;
  const drafts = { rc4: { ...DEFAULT_INPUTS.rc4 }, a51: { ...DEFAULT_INPUTS.a51 } };

  const controls = new StepControls(async (index, context) => {
    if (!store) return;
    let step;
    const slow = window.setTimeout(() => {
      loading.hidden = false;
    }, 150);
    try {
      step = await store.get(index);
    } catch (error) {
      controls.pause();
      showFormError(form, error, state.algorithm);
      return;
    } finally {
      window.clearTimeout(slow);
      loading.hidden = true;
    }
    if (!context.isCurrent()) return;
    const phase = controls.currentPhase();
    phaseTitle.textContent = phase.title;
    phaseDesc.textContent = phase.description;
    explanation.textContent = step.explanation;
    strideGroup.hidden = !(state.algorithm === "a51" && step.phase === "xor");
    view.render(step, index, context);
  });

  form.elements.count_mode.addEventListener("change", () => syncCountMode(form));

  const readRequest = (algorithm) => ({
    ...readCipherFields(form, algorithm),
    plaintext: form.elements.plaintext.value,
    input_format: form.elements.input_format.value,
  });

  function writeInputs(algorithm, values) {
    writeCipherFields(form, algorithm, values);
    form.elements.plaintext.value = values.plaintext ?? "";
    form.elements.input_format.value = values.input_format ?? "text";
    form.elements.plaintext.classList.toggle("mono", form.elements.input_format.value !== "text");
  }

  function fillSegments(summary) {
    if (state.algorithm !== "a51" || summary.segment_count < 2) {
      segmentField.hidden = true;
      clear(segmentSelect);
      return;
    }
    clear(segmentSelect);
    for (const segment of summary.segments) {
      segmentSelect.append(
        el("option", { value: String(segment.index), text: `Segment ${segment.index + 1} · COUNT ${segment.count_hex}` }),
      );
    }
    segmentSelect.value = String(summary.selected_segment);
    segmentField.hidden = false;
  }

  async function build(options = {}) {
    clearFormError(form);
    const algorithm = state.algorithm;
    const request = readRequest(algorithm);
    if (options.segment !== undefined) request.segment = options.segment;
    const button = form.querySelector('button[type="submit"]');
    button.disabled = true;
    button.classList.add("is-busy");
    try {
      const opened = await TraceStore.open(request, PAGE_SIZE[algorithm]);
      if (algorithm !== state.algorithm) return;
      store = opened;
      if (view) view.destroy();
      clear(stage);
      view = algorithm === "rc4" ? createRc4View(stage, store.summary) : createA51View(stage, store.summary);
      fillSegments(store.summary);
      workspace.hidden = false;
      await controls.configure(store.total, store.summary.phases, options.index ?? 0);
    } catch (error) {
      showFormError(form, error, algorithm);
    } finally {
      button.disabled = false;
      button.classList.remove("is-busy");
    }
  }

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    controls.pause();
    build();
  });

  segmentSelect.addEventListener("change", () => {
    build({ segment: Number(segmentSelect.value), index: controls.index });
  });

  exampleSelect.addEventListener("change", () => {
    const example = state.examples.find((item) => item.id === exampleSelect.value);
    if (!example) return;
    writeInputs(example.algorithm, example.fields);
    controls.pause();
    build();
  });

  form.elements.input_format.addEventListener("change", () => {
    form.elements.plaintext.classList.toggle("mono", form.elements.input_format.value !== "text");
  });

  state.subscribe((change) => {
    if (change === "algorithm") {
      const other = state.algorithm === "rc4" ? "a51" : "rc4";
      drafts[other] = readRequest(other);
      // The previous trace belongs to the other algorithm, so it must not stay on screen.
      controls.pause();
      store = null;
      if (view) view.destroy();
      view = null;
      clear(stage);
      controls.total = 0;
      workspace.hidden = true;
      clearFormError(form);
      writeInputs(state.algorithm, drafts[state.algorithm]);
      populateExamples(exampleSelect, state.examples, state.algorithm);
      segmentField.hidden = true;
      if (state.view === "visualize") build();
    }
    if (change === "view") {
      if (state.view !== "visualize") controls.pause();
      else if (!store) build();
    }
  });

  writeInputs("rc4", DEFAULT_INPUTS.rc4);
  writeCipherFields(form, "a51", DEFAULT_INPUTS.a51);
  populateExamples(exampleSelect, state.examples, state.algorithm);
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
