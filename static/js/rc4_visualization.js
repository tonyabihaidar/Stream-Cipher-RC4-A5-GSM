// RC4 stage: the 256-element array, the calculations for the current step, the running
// keystream and the XOR view. All numbers come from the trace supplied by Python.

import { clear, el, prefersReducedMotion, toBin8, toHex2 } from "./dom.js";

const SIZE = 256;

function variable(label, value, accent = "") {
  return el("div", { className: `variable ${accent}` }, el("span", { className: "variable-label", text: label }), el("span", { className: "variable-value mono", text: String(value) }));
}

function bitRow(label, value, note) {
  const bits = el("span", { className: "bit-row-bits" });
  for (const bit of toBin8(value)) bits.append(el("span", { className: `bit bit-${bit}`, text: bit }));
  return el(
    "div",
    { className: "bit-row" },
    el("span", { className: "bit-row-label", text: label }),
    bits,
    el("span", { className: "bit-row-note mono", text: note }),
  );
}

export function createRc4View(container, summary) {
  const keyStrip = el("div", { className: "key-strip", "aria-label": "Key bytes" });
  summary.key_bytes.forEach((byte, index) => {
    if (index < 32) keyStrip.append(el("span", { className: "key-byte mono", title: `key[${index}] = ${byte}`, text: toHex2(byte) }));
  });
  if (summary.key_bytes.length > 32) keyStrip.append(el("span", { className: "muted", text: `+ ${summary.key_bytes.length - 32} more` }));

  const grid = el("div", { className: "array-grid" });
  const cells = [];
  for (let index = 0; index < SIZE; index += 1) {
    const value = el("span", { className: "cell-value mono", text: String(index) });
    const cell = el("div", { className: "cell", title: `S[${index}]` }, el("span", { className: "cell-index", text: String(index) }), value);
    cells.push({ cell, value, current: index });
    grid.append(cell);
  }
  const gridCard = el(
    "div",
    { className: "panel array-card" },
    el(
      "div",
      { className: "array-head" },
      el("h3", { text: "State array S" }),
      el(
        "div",
        { className: "legend" },
        el("span", { className: "legend-item legend-i", text: "i" }),
        el("span", { className: "legend-item legend-j", text: "j" }),
        el("span", { className: "legend-item legend-t", text: "t" }),
        el("span", { className: "muted", text: "Small number: index. Large number: value." }),
      ),
    ),
    el("div", { className: "array-scroll" }, grid),
  );

  const xorCard = el("div", { className: "panel xor-card" });
  const calcCard = el("div", { className: "panel calc-card" });
  const keyCard = el("div", { className: "panel" }, el("h3", { text: `Key · ${summary.key_length} byte${summary.key_length === 1 ? "" : "s"}` }), keyStrip);
  const streamBody = el("div", { className: "byte-stream mono" });
  const streamCard = el("div", { className: "panel stream-card" }, el("h3", { text: "Keystream so far" }), streamBody);

  const main = el("div", { className: "rc4-main" }, gridCard, xorCard);
  const side = el("div", { className: "rc4-side" }, calcCard, keyCard, streamCard);
  const root = el("div", { className: "rc4-layout" }, main, side);
  container.append(root);

  const keyBytes = [...keyStrip.querySelectorAll(".key-byte")];
  let ghosts = [];

  function clearGhosts() {
    ghosts.forEach((ghost) => ghost.remove());
    ghosts = [];
  }

  function updateCells(state) {
    for (let index = 0; index < SIZE; index += 1) {
      const item = cells[index];
      if (item.current !== state[index]) {
        item.current = state[index];
        item.value.textContent = String(state[index]);
      }
    }
  }

  function mark(markers) {
    for (const { cell } of cells) {
      cell.classList.remove("cell-i", "cell-j", "cell-t");
      delete cell.dataset.marker;
    }
    for (const [position, className, name] of markers) {
      const { cell } = cells[position];
      cell.classList.add(className);
      cell.dataset.marker = cell.dataset.marker ? `${cell.dataset.marker}=${name}` : name;
    }
  }

  // Two values visibly trade places, then the real snapshot is what remains on screen.
  function animateSwap(first, second, firstValue, secondValue, duration) {
    clearGhosts();
    if (first === second || prefersReducedMotion() || duration < 120) return;
    const bounds = grid.getBoundingClientRect();
    const a = cells[first].cell.getBoundingClientRect();
    const b = cells[second].cell.getBoundingClientRect();
    const makeGhost = (from, to, text, className) => {
      const ghost = el("div", { className: `swap-ghost mono ${className}`, text: String(text) });
      ghost.style.left = `${from.left - bounds.left}px`;
      ghost.style.top = `${from.top - bounds.top}px`;
      ghost.style.width = `${from.width}px`;
      ghost.style.height = `${from.height}px`;
      grid.append(ghost);
      ghosts.push(ghost);
      const animation = ghost.animate(
        [{ transform: "translate(0, 0)" }, { transform: `translate(${to.left - from.left}px, ${to.top - from.top}px)` }],
        { duration, easing: "ease-in-out", fill: "forwards" },
      );
      animation.onfinish = () => ghost.remove();
    };
    makeGhost(a, b, firstValue, "ghost-i");
    makeGhost(b, a, secondValue, "ghost-j");
  }

  function renderStream(index) {
    clear(streamBody);
    if (index < 0) {
      streamBody.append(el("span", { className: "muted", text: "No keystream bytes yet. Bytes appear during PRGA." }));
      return;
    }
    summary.keystream.slice(0, index + 1).forEach((byte, position) => {
      streamBody.append(el("span", { className: position === index ? "byte latest" : "byte", title: `keystream[${position}] = ${byte}`, text: toHex2(byte) }));
    });
  }

  function renderCalc(step) {
    clear(calcCard);
    if (step.phase === "init" || step.phase === "ksa_done") {
      calcCard.append(
        el("h3", { text: step.phase === "init" ? "Starting point" : "Hand-over to PRGA" }),
        el("div", { className: "variables" }, variable("i", 0, "accent-i"), variable("j", 0, "accent-j"), variable("Array size", SIZE)),
      );
      return;
    }
    if (step.phase === "ksa") {
      calcCard.append(
        el("h3", { text: `KSA iteration ${step.iteration + 1} / 256` }),
        el("p", { className: "formula mono", text: "j = (j + S[i] + key[i mod keyLength]) mod 256" }),
        el("p", { className: "equation mono", text: step.equation }),
        el(
          "div",
          { className: "variables" },
          variable("i", step.i, "accent-i"),
          variable("Previous j", step.previous_j),
          variable("New j", step.j, "accent-j"),
          variable(`key[${step.key_index}]`, step.key_byte),
          variable(`S[${step.i}] before`, step.s_i, "accent-i"),
          variable(`S[${step.j}] before`, step.s_j, "accent-j"),
        ),
        el("p", { className: "swap-line mono", text: step.i === step.j ? `No change: i = j = ${step.i}` : `Swap S[${step.i}] ↔ S[${step.j}]` }),
      );
      return;
    }
    if (step.phase === "prga") {
      calcCard.append(
        el("h3", { text: `PRGA byte ${step.index + 1} / ${summary.plaintext_length}` }),
        el("ol", { className: "equation-list mono" },
          el("li", { text: step.equations.i }),
          el("li", { text: step.equations.j }),
          el("li", { text: `Swap S[${step.i}] ↔ S[${step.j}]: ${step.s_i} ↔ ${step.s_j}` }),
          el("li", { text: step.equations.t }),
          el("li", { className: "output-line", text: step.equations.output }),
        ),
        el(
          "div",
          { className: "variables" },
          variable("i", step.i, "accent-i"),
          variable("j", step.j, "accent-j"),
          variable("t", step.t, "accent-t"),
          variable("Keystream byte", `${step.keystream_byte} (0x${toHex2(step.keystream_byte)})`, "accent-t"),
        ),
      );
      return;
    }
    calcCard.append(
      el("h3", { text: `XOR byte ${step.index + 1} / ${summary.plaintext_length}` }),
      el("p", { className: "formula mono", text: "Ciphertext = Plaintext XOR Keystream" }),
      el(
        "div",
        { className: "variables" },
        variable("Plaintext", `0x${toHex2(step.plaintext_byte)}`),
        variable("Keystream", `0x${toHex2(step.keystream_byte)}`, "accent-t"),
        variable("Ciphertext", `0x${toHex2(step.ciphertext_byte)}`, "accent-i"),
      ),
    );
  }

  function renderXor(step) {
    clear(xorCard);
    const label = step.plaintext_label ? ` '${step.plaintext_label}'` : "";
    const table = el(
      "div",
      { className: "bit-table" },
      bitRow("Plaintext", step.plaintext_byte, `0x${toHex2(step.plaintext_byte)}${label}`),
      bitRow("Keystream", step.keystream_byte, `0x${toHex2(step.keystream_byte)}`),
      el("div", { className: "bit-rule" }),
      bitRow("Ciphertext", step.ciphertext_byte, `0x${toHex2(step.ciphertext_byte)}`),
    );
    const row = table.lastElementChild.querySelector(".bit-row-bits");
    row.parentElement.classList.add("result-row");

    const progress = el("div", { className: "byte-stream mono" });
    summary.ciphertext_bytes.forEach((byte, position) => {
      const processed = position <= step.index;
      progress.append(el("span", { className: `byte${position === step.index ? " latest" : ""}${processed ? "" : " pending"}`, text: processed ? toHex2(byte) : "··" }));
    });

    xorCard.append(el("h3", { text: "Bitwise XOR" }), table, el("h3", { text: "Ciphertext so far" }), progress);
    if (step.index === summary.plaintext_length - 1) {
      xorCard.append(el("p", { className: "done-line", text: `Complete. Ciphertext: ${summary.ciphertext_hex}` }));
    }
  }

  return {
    render(step, index, context) {
      clearGhosts();
      const isXor = step.phase === "xor";
      gridCard.hidden = isXor;
      xorCard.hidden = !isXor;
      renderCalc(step);
      keyBytes.forEach((node, position) => node.classList.toggle("active", step.phase === "ksa" && position === step.key_index));

      if (isXor) {
        renderXor(step);
        renderStream(step.index);
        return;
      }
      updateCells(step.S);
      if (step.phase === "ksa") {
        mark([[step.i, "cell-i", "i"], [step.j, "cell-j", "j"]]);
        if (context.animate) animateSwap(step.i, step.j, step.s_i, step.s_j, context.duration);
        renderStream(-1);
      } else if (step.phase === "prga") {
        mark([[step.i, "cell-i", "i"], [step.j, "cell-j", "j"], [step.t, "cell-t", "t"]]);
        if (context.animate) animateSwap(step.i, step.j, step.s_i, step.s_j, context.duration);
        renderStream(step.index);
      } else {
        mark([]);
        renderStream(-1);
      }
    },
    destroy() {
      clearGhosts();
    },
  };
}
