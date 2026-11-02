// Direct Mode: encrypt and decrypt through the API and present the results.

import { api } from "./api.js";
import {
  clear,
  clearFormError,
  copyButton,
  el,
  populateExamples,
  readCipherFields,
  showFormError,
  syncCountMode,
  writeCipherFields,
} from "./dom.js";

const RECORD_TYPE = "eece455.stream-cipher.ciphertext";
const MAX_SEGMENT_ROWS = 16;

function outputRow(label, value, options = {}) {
  const row = el("div", { className: "output-row" });
  const head = el("div", { className: "output-head" }, el("span", { className: "output-label", text: label }));
  if (options.copy !== false) head.append(copyButton(() => value));
  const body = el("div", {
    className: `output-value${options.mono === false ? "" : " mono"}${options.tall ? " tall" : ""}`,
    text: value,
    dir: options.mono === false ? "auto" : null,
  });
  row.append(head, body);
  return row;
}

function stat(label, value) {
  return el("div", { className: "stat" }, el("span", { className: "stat-value mono", text: value }), el("span", { className: "stat-label", text: label }));
}

function plural(count, noun) {
  return `${count} ${noun}${count === 1 ? "" : "s"}`;
}

function segmentTable(result) {
  const rows = result.segments.slice(0, MAX_SEGMENT_ROWS).map((segment) =>
    el(
      "tr",
      {},
      el("td", { text: String(segment.index + 1) }),
      el("td", { text: segment.count_hex }),
      segment.fn === null ? null : el("td", { text: String(segment.fn) }),
      el("td", { text: String(segment.keystream_generated) }),
      el("td", { text: String(segment.keystream_used) }),
      el("td", { text: String(segment.keystream_unused) }),
    ),
  );
  const fnMode = result.segments[0].fn !== null;
  const heads = ["Segment", "COUNT", fnMode ? "FN" : null, "Generated", "Used", "Unused"].filter(Boolean);
  const table = el(
    "table",
    { className: "data-table mono" },
    el("thead", {}, el("tr", {}, ...heads.map((name) => el("th", { scope: "col", text: name })))),
    el("tbody", {}, ...rows),
  );
  const hidden = result.segment_count - rows.length;
  return el(
    "div",
    { className: "output-row" },
    el("div", { className: "output-head" }, el("span", { className: "output-label", text: "Frames" })),
    el("div", { className: "table-wrap" }, table),
    hidden > 0 ? el("p", { className: "hint", text: `Showing the first ${rows.length} of ${result.segment_count} segments.` }) : null,
  );
}

function fnNote(parameters) {
  if (parameters.count_mode !== "fn") return null;
  const { start_fn: fn, t1, t2, t3, start_count_hex: count } = parameters;
  return el("p", { className: "hint", text: `FN ${fn} gives T1 = ${t1}, T2 = ${t2}, T3 = ${t3}, so the first COUNT is ${count}.` });
}

function paddingNote(serialized) {
  if (!serialized.padding_bits) return null;
  return el("p", {
    className: "hint",
    text: `Hex and Base64 include ${plural(serialized.padding_bits, "padding bit")} at the end. These belong to the representation only, so keep the bit length of ${serialized.bit_length}.`,
  });
}

function a51LengthStats(result, inputLabel, outputLabel) {
  return el(
    "div",
    { className: "stats" },
    stat(inputLabel, `${result.keystream.bits_used} bits`),
    stat("Generated keystream", `${result.keystream.bits_generated} bits`),
    stat("Keystream used", `${result.keystream.bits_used} bits`),
    stat("Unused keystream", `${result.keystream.bits_unused} bits`),
    stat(outputLabel, `${result.keystream.bits_used} bits`),
    stat("Frames", String(result.segment_count)),
  );
}

function rc4LengthStats(bytes, inputLabel) {
  return el(
    "div",
    { className: "stats" },
    stat(inputLabel, plural(bytes, "byte")),
    stat(`${inputLabel} in bits`, `${bytes * 8} bits`),
    stat("Keystream used", plural(bytes, "byte")),
  );
}

function resultHeader(title, algorithmName, relation) {
  return [
    el("div", { className: "result-title" }, el("span", { className: "tick", "aria-hidden": "true", text: "✓" }), el("span", { text: `${title} with ${algorithmName}` })),
    el("p", { className: "relation mono", text: relation }),
  ];
}

function renderEncryptResult(target, result, handlers) {
  clear(target);
  const plaintextValue = result.plaintext.text ?? (result.plaintext.format === "binary" ? result.plaintext.binary : result.plaintext.hex);
  target.append(
    ...resultHeader("Encrypted", result.algorithm_name, result.relation),
    result.algorithm === "rc4"
      ? rc4LengthStats(result.plaintext.byte_length, "Plaintext")
      : a51LengthStats(result, "Plaintext length", "Ciphertext length"),
    outputRow("Plaintext", plaintextValue, { mono: result.plaintext.text === null }),
    outputRow("Ciphertext (hexadecimal)", result.ciphertext.hex),
    outputRow("Ciphertext (Base64)", result.ciphertext.base64),
    outputRow("Ciphertext (binary)", result.ciphertext.binary, { tall: true }),
    paddingNote(result.ciphertext),
    outputRow(result.algorithm === "rc4" ? "Keystream (hexadecimal)" : "Keystream used (hexadecimal)", result.keystream.hex),
    outputRow(result.algorithm === "rc4" ? "Keystream (binary)" : "Keystream used (binary)", result.keystream.binary, { tall: true }),
  );
  if (result.algorithm === "a51") {
    target.append(segmentTable(result));
    const note = fnNote(result.parameters);
    if (note) target.append(note);
  }
  target.append(
    el("p", { className: "description", text: result.description }),
    el(
      "div",
      { className: "button-row" },
      el("button", { type: "button", className: "btn btn-primary", text: "Send to Decryption", onclick: handlers.sendToDecrypt }),
      el("button", { type: "button", className: "btn", text: "Export Record", onclick: handlers.exportRecord }),
    ),
  );
}

function renderDecryptResult(target, result) {
  clear(target);
  const recovered = result.recovered;
  target.append(...resultHeader("Decrypted", result.algorithm_name, result.relation));
  target.append(
    result.algorithm === "rc4"
      ? rc4LengthStats(result.ciphertext.byte_length, "Ciphertext")
      : a51LengthStats(result, "Ciphertext length", "Recovered length"),
  );
  if (recovered.text !== null) {
    target.append(outputRow("Recovered plaintext", recovered.text, { mono: false }));
  } else {
    target.append(el("p", { className: "notice", text: recovered.message }));
  }
  target.append(
    outputRow("Recovered bytes (hexadecimal)", recovered.hex),
    outputRow("Recovered bits (binary)", recovered.binary, { tall: true }),
    outputRow(`Original ciphertext (${result.ciphertext.encoding === "base64" ? "Base64" : "hexadecimal"})`, result.ciphertext.encoding === "base64" ? result.ciphertext.base64 : result.ciphertext.hex),
    outputRow(result.algorithm === "rc4" ? "Keystream (hexadecimal)" : "Keystream used (hexadecimal)", result.keystream.hex),
  );
  if (result.algorithm === "a51") {
    target.append(segmentTable(result));
    const note = fnNote(result.parameters);
    if (note) target.append(note);
  }
  target.append(el("p", { className: "description", text: result.description }));
}

function saveJson(filename, data) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }));
  const link = el("a", { href: url, download: filename });
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

// Only for the length hint under the plaintext box. The server does the real conversion.
function lengthReadout(raw, format) {
  if (format === "text") {
    const bytes = new TextEncoder().encode(raw).length;
    return `${plural(bytes, "byte")} · ${bytes * 8} bits`;
  }
  if (format === "binary") {
    const bits = raw.replace(/\s/g, "").length;
    return `${bits} bits`;
  }
  const digits = raw.replace(/\s/g, "").length;
  return `${plural(Math.ceil(digits / 2), "byte")} · ${Math.ceil(digits / 2) * 8} bits`;
}

export function initDirectMode(state) {
  const encryptForm = document.getElementById("encrypt-form");
  const decryptForm = document.getElementById("decrypt-form");
  const encryptResult = document.getElementById("encrypt-result");
  const decryptResult = document.getElementById("decrypt-result");
  const exampleSelect = document.getElementById("enc-example");
  const exampleNote = document.getElementById("enc-example-note");
  const readout = document.getElementById("enc-length-readout");
  const plaintext = encryptForm.elements.plaintext;
  const inputFormat = encryptForm.elements.input_format;
  let lastEncrypt = null;

  const updateReadout = () => {
    readout.textContent = lengthReadout(plaintext.value, inputFormat.value);
    plaintext.classList.toggle("mono", inputFormat.value !== "text");
  };
  plaintext.addEventListener("input", updateReadout);
  inputFormat.addEventListener("change", updateReadout);

  for (const form of [encryptForm, decryptForm]) {
    form.elements.count_mode.addEventListener("change", () => syncCountMode(form));
  }

  async function submit(form, target, call, onSuccess) {
    clearFormError(form);
    const button = form.querySelector('button[type="submit"]');
    button.disabled = true;
    button.classList.add("is-busy");
    try {
      onSuccess(await call());
    } catch (error) {
      clear(target);
      showFormError(form, error, state.algorithm);
    } finally {
      button.disabled = false;
      button.classList.remove("is-busy");
    }
  }

  function sendToDecrypt() {
    const { request, result } = lastEncrypt;
    decryptForm.elements.ciphertext.value = result.ciphertext.hex;
    decryptForm.elements.ciphertext_encoding.value = "hex";
    decryptForm.elements.bit_length.value = result.ciphertext.padding_bits ? String(result.ciphertext.bit_length) : "";
    writeCipherFields(decryptForm, request.algorithm, request);
    clearFormError(decryptForm);
    clear(decryptResult);
    decryptForm.scrollIntoView({ behavior: "smooth", block: "start" });
    decryptForm.elements.ciphertext.focus({ preventScroll: true });
  }

  function exportRecord() {
    const { result } = lastEncrypt;
    saveJson(`${result.algorithm}-ciphertext-record.json`, result.record);
  }

  encryptForm.addEventListener("submit", (event) => {
    event.preventDefault();
    const request = {
      ...readCipherFields(encryptForm, state.algorithm),
      plaintext: plaintext.value,
      input_format: inputFormat.value,
    };
    submit(encryptForm, encryptResult, () => api.encrypt(request), (result) => {
      lastEncrypt = { request, result };
      renderEncryptResult(encryptResult, result, { sendToDecrypt, exportRecord });
    });
  });

  decryptForm.addEventListener("submit", (event) => {
    event.preventDefault();
    const request = {
      ...readCipherFields(decryptForm, state.algorithm),
      ciphertext: decryptForm.elements.ciphertext.value,
      ciphertext_encoding: decryptForm.elements.ciphertext_encoding.value,
    };
    if (state.algorithm === "a51") request.bit_length = decryptForm.elements.bit_length.value;
    submit(decryptForm, decryptResult, () => api.decrypt(request), (result) => renderDecryptResult(decryptResult, result));
  });

  function loadExample() {
    const example = state.examples.find((item) => item.id === exampleSelect.value);
    clearFormError(encryptForm);
    if (!example) {
      showFormError(encryptForm, { message: "Choose an example from the list first.", field: null }, state.algorithm);
      return;
    }
    plaintext.value = example.fields.plaintext;
    inputFormat.value = example.fields.input_format;
    writeCipherFields(encryptForm, example.algorithm, example.fields);
    clear(encryptResult);
    updateReadout();
    exampleNote.textContent = example.published_ciphertext
      ? `${example.description} Expected ciphertext (${example.reference}): ${example.published_ciphertext}`
      : example.description;
  }
  document.getElementById("enc-load").addEventListener("click", loadExample);
  exampleSelect.addEventListener("change", () => {
    if (exampleSelect.value) loadExample();
  });

  document.getElementById("enc-clear").addEventListener("click", () => {
    encryptForm.reset();
    syncCountMode(encryptForm);
    clear(encryptResult);
    clearFormError(encryptForm);
    exampleNote.textContent = "";
    lastEncrypt = null;
    updateReadout();
  });

  document.getElementById("dec-clear").addEventListener("click", () => {
    decryptForm.reset();
    syncCountMode(decryptForm);
    clear(decryptResult);
    clearFormError(decryptForm);
  });

  document.getElementById("dec-import").addEventListener("change", async (event) => {
    const file = event.target.files[0];
    event.target.value = "";
    if (!file) return;
    clearFormError(decryptForm);
    clear(decryptResult);
    try {
      const record = JSON.parse(await file.text());
      if (record.record_type !== RECORD_TYPE || typeof record.ciphertext !== "string") throw new Error("bad record");
      if (record.algorithm === "rc4" || record.algorithm === "a51") state.setAlgorithm(record.algorithm);
      else throw new Error("bad record");
      decryptForm.elements.ciphertext.value = record.ciphertext;
      decryptForm.elements.ciphertext_encoding.value = record.encoding === "base64" ? "base64" : "hex";
      if (record.algorithm === "a51") {
        decryptForm.elements.bit_length.value = String(record.bit_length ?? "");
        decryptForm.elements.direction.value = record.direction === "uplink" ? "uplink" : "downlink";
        decryptForm.elements.count_mode.value = record.count_mode === "fn" ? "fn" : "count";
        decryptForm.elements.count.value = record.count_mode === "fn" ? "" : `0x${Number(record.start_count).toString(16).toUpperCase()}`;
        decryptForm.elements.fn.value = record.count_mode === "fn" ? String(record.start_fn) : "";
        syncCountMode(decryptForm);
      } else {
        decryptForm.elements.key_encoding.value = record.key_encoding === "hex" ? "hex" : "text";
      }
      const keyField = record.algorithm === "rc4" ? decryptForm.elements.rc4_key : decryptForm.elements.a51_key;
      keyField.focus();
    } catch {
      showFormError(decryptForm, { message: "That file is not a valid ciphertext record.", field: null }, state.algorithm);
    }
  });

  function onAlgorithmChange() {
    populateExamples(exampleSelect, state.examples, state.algorithm);
    exampleNote.textContent = "";
    clear(encryptResult);
    clear(decryptResult);
    clearFormError(encryptForm);
    clearFormError(decryptForm);
    lastEncrypt = null;
  }

  state.subscribe((change) => {
    if (change === "algorithm") onAlgorithmChange();
  });
  onAlgorithmChange();
  updateReadout();
}
