// Small DOM helpers shared by the views. All user data goes through textContent, so
// messages can never be interpreted as markup.

export function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  applyAttrs(node, attrs);
  node.append(...children.filter((child) => child !== null && child !== undefined));
  return node;
}

const SVG_NS = "http://www.w3.org/2000/svg";

export function svg(tag, attrs = {}, ...children) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [name, value] of Object.entries(attrs)) {
    node.setAttribute(name === "className" ? "class" : name, value);
  }
  node.append(...children);
  return node;
}

function applyAttrs(node, attrs) {
  for (const [name, value] of Object.entries(attrs)) {
    if (value === null || value === undefined || value === false) continue;
    if (name === "className") node.className = value;
    else if (name === "text") node.textContent = value;
    else if (name.startsWith("on")) node.addEventListener(name.slice(2).toLowerCase(), value);
    else if (value === true) node.setAttribute(name, "");
    else node.setAttribute(name, value);
  }
}

export function clear(node) {
  node.replaceChildren();
}

export const prefersReducedMotion = () => window.matchMedia("(prefers-reduced-motion: reduce)").matches;

export function toBin8(value) {
  return value.toString(2).padStart(8, "0");
}

export function toHex2(value) {
  return value.toString(16).toUpperCase().padStart(2, "0");
}

async function writeClipboard(text) {
  if (navigator.clipboard && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(text);
      return;
    } catch {
      // The browser refused, for example because the window lacks focus. Try the older route.
    }
  }
  const area = el("textarea", { className: "visually-hidden" });
  area.value = text;
  document.body.append(area);
  area.select();
  const copied = document.execCommand("copy");
  area.remove();
  if (!copied) throw new Error("Copy was refused");
}

export function copyButton(getText, label = "Copy") {
  const button = el("button", { type: "button", className: "btn btn-small", text: label });
  button.setAttribute("aria-label", `${label} to clipboard`);
  button.addEventListener("click", async () => {
    try {
      await writeClipboard(getText());
      button.textContent = "Copied";
      button.classList.add("btn-success");
    } catch {
      button.textContent = "Copy failed";
    }
    window.setTimeout(() => {
      button.textContent = label;
      button.classList.remove("btn-success");
    }, 1400);
  });
  return button;
}

// Reads the key and frame fields rendered by the cipher_fields template macro.
export function readCipherFields(form, algorithm) {
  const value = (name) => form.elements[name].value;
  if (algorithm === "rc4") {
    return { algorithm, key: value("rc4_key"), key_encoding: value("key_encoding") };
  }
  return {
    algorithm,
    key: value("a51_key"),
    count_mode: value("count_mode"),
    count: value("count"),
    fn: value("fn"),
    direction: value("direction"),
  };
}

export function writeCipherFields(form, algorithm, fields) {
  if (algorithm === "rc4") {
    form.elements.rc4_key.value = fields.key ?? "";
    form.elements.key_encoding.value = fields.key_encoding ?? "text";
  } else {
    form.elements.a51_key.value = fields.key ?? "";
    form.elements.count_mode.value = fields.count_mode ?? "count";
    form.elements.count.value = fields.count ?? "";
    form.elements.fn.value = fields.fn ?? "";
    form.elements.direction.value = fields.direction ?? "downlink";
  }
  syncCountMode(form);
}

// Shows either the COUNT input or the FN input, never both.
export function syncCountMode(form) {
  const mode = form.elements.count_mode.value;
  form.querySelectorAll("[data-count-field]").forEach((node) => {
    node.hidden = node.dataset.countField !== mode;
  });
}

// Field names in API errors do not always match form control names.
function controlsForField(form, field, algorithm) {
  const names = {
    key: algorithm === "rc4" ? "rc4_key" : "a51_key",
    plaintext: "plaintext",
    ciphertext: "ciphertext",
    count: "count",
    fn: "fn",
    bit_length: "bit_length",
    direction: "direction",
    key_encoding: "key_encoding",
    input_format: "input_format",
  };
  const control = names[field] ? form.elements[names[field]] : null;
  return control || null;
}

export function showFormError(form, error, algorithm) {
  clearFormError(form);
  const box = form.querySelector(":scope > .form-error");
  box.textContent = error.message;
  box.hidden = false;
  const control = controlsForField(form, error.field, algorithm);
  if (control) {
    control.setAttribute("aria-invalid", "true");
    control.focus();
  }
}

export function clearFormError(form) {
  const box = form.querySelector(":scope > .form-error");
  box.textContent = "";
  box.hidden = true;
  form.querySelectorAll('[aria-invalid="true"]').forEach((node) => node.removeAttribute("aria-invalid"));
}

export function populateExamples(select, examples, algorithm) {
  clear(select);
  select.append(el("option", { value: "", text: "Choose an example…" }));
  for (const example of examples.filter((item) => item.algorithm === algorithm)) {
    select.append(el("option", { value: example.id, text: example.label }));
  }
}
