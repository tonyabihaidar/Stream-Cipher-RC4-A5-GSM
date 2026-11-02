// A5/1 stage: the three LFSRs drawn in SVG, plus panels for clocking, feedback, output
// and XOR. Register positions and values all come from the trace supplied by Python.

import { clear, el, prefersReducedMotion, svg } from "./dom.js";

const CELL = 40;
const CELL_HEIGHT = 42;
const RIGHT = 1060;
const ROW_TOPS = [44, 162, 280];
const VIEW_WIDTH = 1150;
const VIEW_HEIGHT = 362;
const COMBINER_X = 60;
const XOR_LINE_BITS = 38;

const toBinary = (value, length) => value.toString(2).padStart(length, "0");
const toHex = (value, length) => `0x${value.toString(16).toUpperCase().padStart(Math.ceil(length / 4), "0")}`;

function xorNode(cx, cy, className) {
  return svg(
    "g",
    { className },
    svg("circle", { cx, cy, r: 12, className: "xor-circle" }),
    svg("path", { d: `M${cx - 12} ${cy}h24M${cx} ${cy - 12}v24`, className: "xor-plus" }),
  );
}

function buildRegister(spec, rowIndex) {
  const top = ROW_TOPS[rowIndex];
  const left = RIGHT - spec.length * CELL;
  const busY = top - 20;
  const midY = top + CELL_HEIGHT / 2;
  const xorX = RIGHT + 44;
  const xOf = (bit) => RIGHT - (bit + 1) * CELL;
  const centerOf = (bit) => xOf(bit) + CELL / 2;
  const group = svg("g", { className: `reg reg-${rowIndex + 1}` });

  const leftTap = Math.max(...spec.taps);
  const wires = svg("g", { className: "wires" });
  wires.append(
    svg("path", { d: `M${centerOf(leftTap)} ${busY}H${xorX - 12}`, className: "wire feedback-wire" }),
    svg("path", { d: `M${xorX} ${busY + 12}V${midY}H${RIGHT + 6}`, className: "wire feedback-wire" }),
    svg("path", { d: `M${RIGHT + 8} ${midY - 5}L${RIGHT} ${midY}L${RIGHT + 8} ${midY + 5}Z`, className: "arrow feedback-arrow" }),
  );
  for (const tap of spec.taps) {
    wires.append(svg("path", { d: `M${centerOf(tap)} ${top}V${busY}`, className: "wire feedback-wire" }));
    wires.append(svg("circle", { cx: centerOf(tap), cy: busY, r: 3, className: "tap-dot" }));
  }
  const outY = midY;
  wires.append(svg("path", { d: `M${left} ${outY}H${COMBINER_X}${rowIndex === 1 ? "" : `V${ROW_TOPS[1] + CELL_HEIGHT / 2}`}`, className: "wire output-wire" }));
  group.append(wires);
  group.append(xorNode(xorX, busY, "feedback-xor"));
  const feedbackValue = svg("text", { x: xorX + 20, y: busY + 6, className: "feedback-value" });
  group.append(feedbackValue);

  group.append(
    svg("text", { x: left - 10, y: midY - 8, "text-anchor": "end", className: "reg-name" }, document.createTextNode(spec.name)),
  );
  const status = svg("text", { x: left - 10, y: midY + 18, "text-anchor": "end", className: "reg-status" });
  group.append(status);

  const cellsGroup = svg("g", { className: "cells" });
  const bitsGroup = svg("g", { className: "bits" });
  const rects = [];
  const texts = [];
  for (let bit = spec.length - 1; bit >= 0; bit -= 1) {
    const x = xOf(bit);
    const classes = ["reg-cell"];
    if (spec.taps.includes(bit)) classes.push("is-tap");
    if (bit === spec.clock_bit) classes.push("is-clock");
    if (bit === spec.output_bit) classes.push("is-output");
    const rect = svg("rect", { x: x + 1, y: top, width: CELL - 2, height: CELL_HEIGHT, rx: 5, className: classes.join(" ") });
    const text = svg("text", { x: x + CELL / 2, y: top + CELL_HEIGHT / 2 + 7, "text-anchor": "middle", className: "bit-text" });
    const indexLabel = svg("text", { x: x + CELL / 2, y: top + CELL_HEIGHT + 15, "text-anchor": "middle", className: "index-text" }, document.createTextNode(String(bit)));
    rects[bit] = rect;
    texts[bit] = text;
    cellsGroup.append(rect, indexLabel);
    bitsGroup.append(text);
    if (bit === spec.clock_bit) {
      cellsGroup.append(svg("text", { x: x + CELL / 2, y: top + CELL_HEIGHT + 30, "text-anchor": "middle", className: "role-text role-clock" }, document.createTextNode("clock")));
    }
    if (bit === spec.output_bit) {
      cellsGroup.append(svg("text", { x: x + CELL / 2, y: top + CELL_HEIGHT + 30, "text-anchor": "middle", className: "role-text role-output" }, document.createTextNode("output")));
    }
  }
  group.append(cellsGroup, bitsGroup);
  return { group, rects, texts, bitsGroup, feedbackValue, status, spec };
}

function buildDiagram(registers) {
  const root = svg("svg", {
    viewBox: `0 0 ${VIEW_WIDTH} ${VIEW_HEIGHT}`,
    className: "lfsr-diagram",
    role: "img",
    "aria-label": "The three A5/1 shift registers, with bit 0 on the right. New bits enter on the right, and output bits leave on the left.",
  });
  const rows = registers.map((spec, index) => buildRegister(spec, index));
  rows.forEach((row) => root.append(row.group));
  const combinerY = ROW_TOPS[1] + CELL_HEIGHT / 2;
  root.append(xorNode(COMBINER_X, combinerY, "output-xor"));
  root.append(svg("path", { d: `M${COMBINER_X - 12} ${combinerY}H20`, className: "wire output-wire" }));
  root.append(svg("path", { d: `M24 ${combinerY - 5}L16 ${combinerY}L24 ${combinerY + 5}Z`, className: "arrow output-arrow" }));
  const outputValue = svg("text", { x: 18, y: combinerY - 12, "text-anchor": "middle", className: "output-value-text" });
  root.append(outputValue);
  return { root, rows, outputValue };
}

function chip(label, value, className = "") {
  return el("div", { className: `bit-chip ${className}` }, el("span", { className: "bit-chip-label", text: label }), el("span", { className: "bit-chip-value mono", text: String(value) }));
}

export function createA51View(container, summary) {
  const specs = summary.registers;
  const diagram = buildDiagram(specs);

  const traced = summary.segments[summary.selected_segment];
  const diagramCard = el(
    "div",
    { className: "panel diagram-card" },
    el(
      "div",
      { className: "array-head" },
      el("h3", { text: `Registers · COUNT ${traced.count_hex}${summary.segment_count > 1 ? ` (segment ${traced.index + 1} of ${summary.segment_count})` : ""}` }),
      el(
        "div",
        { className: "legend" },
        el("span", { className: "legend-item legend-tap", text: "Feedback tap" }),
        el("span", { className: "legend-item legend-clock", text: "Clocking bit" }),
        el("span", { className: "legend-item legend-output", text: "Output bit" }),
      ),
    ),
    el("div", { className: "diagram-scroll" }, diagram.root),
  );

  const clockCard = el("div", { className: "panel info-card" });
  const feedbackCard = el("div", { className: "panel info-card" });
  const ioCard = el("div", { className: "panel info-card" });
  const stateCard = el("div", { className: "panel state-card" });
  const infoGrid = el("div", { className: "info-grid" }, clockCard, feedbackCard, ioCard);

  const streamCard = el("div", { className: "panel" });
  const xorCard = el("div", { className: "panel xor-card" });
  const root = el("div", { className: "a51-layout" }, diagramCard, infoGrid, stateCard, xorCard, streamCard);
  container.append(root);

  // Keystream strip: two fixed blocks, filled as bits are generated.
  const sequenceCells = { downlink: [], uplink: [] };
  const buildStrip = () => {
    const usedInTraced = traced.length;
    const strip = el("div", { className: "stream-blocks" });
    for (const name of ["downlink", "uplink"]) {
      const selected = name === summary.direction;
      const bits = el("div", { className: "stream-bits mono" });
      for (let index = 0; index < 114; index += 1) {
        const bit = el("span", { className: "stream-bit" });
        if (selected && index < usedInTraced) bit.classList.add("used");
        sequenceCells[name].push(bit);
        bits.append(bit);
      }
      strip.append(
        el(
          "div",
          { className: `stream-block${selected ? " selected" : ""}` },
          el(
            "div",
            { className: "stream-head" },
            el("strong", { text: `${name === "downlink" ? "Downlink: first" : "Uplink: next"} 114 bits` }),
            el("span", { className: selected ? "tag tag-green" : "muted", text: selected ? `Selected · ${usedInTraced} used, ${114 - usedInTraced} unused` : "Not used by this message" }),
          ),
          bits,
        ),
      );
    }
    return strip;
  };
  const generatedLabel = el("p", { className: "muted mono" });
  streamCard.append(el("h3", { text: "Generated keystream" }), generatedLabel, buildStrip());

  function renderRegisters(step, context) {
    const isClear = step.phase === "clear";
    const isIdle = isClear || step.phase === "loaded";
    diagram.rows.forEach((row, index) => {
      const value = step.registers[index];
      const moved = step.moved[index];
      const { spec } = row;
      for (let bit = 0; bit < spec.length; bit += 1) {
        const on = (value >> bit) & 1;
        row.texts[bit].textContent = String(on);
        row.rects[bit].classList.toggle("bit-on", on === 1);
      }
      row.group.classList.toggle("active", moved);
      row.group.classList.toggle("stationary", !moved && !isIdle);
      row.status.textContent = isIdle ? "" : moved ? "CLOCKED" : "STATIONARY";

      const feedback = step.feedback.find((item) => item.register === spec.name);
      row.feedbackValue.textContent = feedback ? String(feedback.result) : "";
      if (context.animate && moved && !prefersReducedMotion() && context.duration >= 120) {
        row.bitsGroup.animate(
          [{ transform: `translateX(${CELL}px)` }, { transform: "translateX(0)" }],
          { duration: context.duration, easing: "ease-out" },
        );
      }
    });
    diagram.outputValue.textContent = step.phase === "keystream" ? String(step.keystream_bit) : "";
  }

  function renderClock(step) {
    clear(clockCard);
    clockCard.append(el("h3", { text: "Clocking" }));
    if (step.phase === "clear" || step.phase === "loaded") {
      clockCard.append(el("p", { className: "muted", text: "No clock in this step." }));
      return;
    }
    const chips = el("div", { className: "chip-row" });
    specs.forEach((spec, index) => {
      chips.append(chip(`${spec.name} clock bit (b${spec.clock_bit})`, step.clock_bits[index], `reg-tone-${index + 1}`));
    });
    clockCard.append(chips);
    if (step.majority === null) {
      clockCard.append(el("p", { className: "calc-line", text: "Forced clock: during loading, all registers advance and the control bits are ignored." }));
      return;
    }
    clockCard.append(el("div", { className: "chip-row" }, chip("Majority", step.majority, "majority")));
    const list = el("ul", { className: "move-list" });
    specs.forEach((spec, index) => {
      list.append(el("li", { className: step.moved[index] ? "moved" : "held", text: `${spec.name}: ${step.moved[index] ? "clocked" : "not clocked"}` }));
    });
    clockCard.append(list);
    clockCard.append(el("p", { className: "hint", text: "Control bits are read before the shift. The diagram above shows the registers after it." }));
  }

  function renderFeedback(step) {
    clear(feedbackCard);
    feedbackCard.append(el("h3", { text: "Feedback" }));
    if (!step.feedback.length) {
      feedbackCard.append(el("p", { className: "muted", text: "No register moved." }));
      return;
    }
    for (const item of step.feedback) {
      const index = specs.findIndex((spec) => spec.name === item.register);
      const names = item.taps.map((tap) => `b${tap.bit}`).join(" ⊕ ");
      feedbackCard.append(
        el(
          "div",
          { className: `feedback-line reg-tone-${index + 1}` },
          el("span", { className: "feedback-name", text: item.register }),
          el("span", { className: "mono", text: `${names} = ${item.expression} = ` }),
          el("strong", { className: "mono", text: String(item.result) }),
        ),
      );
    }
    feedbackCard.append(el("p", { className: "hint", text: "The values above are taken before the shift. The result enters at bit 0." }));
  }

  function renderIo(step) {
    clear(ioCard);
    if (step.phase === "key" || step.phase === "count") {
      ioCard.append(
        el("h3", { text: step.phase === "key" ? `Key bit ${step.phase_step + 1} / 64` : `COUNT bit ${step.phase_step + 1} / 22` }),
        el("div", { className: "chip-row" }, chip("Input bit", step.input_bit, "majority")),
        el("p", { className: "calc-line", text: step.input_source }),
        el("p", { className: "calc-line mono", text: `bit 0 ← bit 0 ⊕ ${step.input_bit} in every register` }),
      );
    } else if (step.phase === "warmup") {
      ioCard.append(
        el("h3", { text: step.counter }),
        el("p", { className: "calc-line", text: "Warm-up mixes the key and COUNT through the registers." }),
        el("p", { className: "calc-line mono", text: "Output: discarded" }),
      );
    } else if (step.phase === "keystream") {
      const chips = el("div", { className: "chip-row" });
      specs.forEach((spec, index) => {
        chips.append(chip(`${spec.name} output (b${spec.output_bit})`, step.output_bits[index], `reg-tone-${index + 1}`));
      });
      ioCard.append(
        el("h3", { text: step.counter }),
        chips,
        el("p", { className: "equation mono", text: step.equation }),
        el("div", { className: "chip-row" }, chip("Keystream bit", step.keystream_bit, "keystream"), chip("Generated", `${step.generated} / 228`)),
      );
    } else {
      ioCard.append(el("h3", { text: step.phase === "clear" ? "Registers cleared" : "Key setup complete" }));
      ioCard.append(el("p", { className: "calc-line mono", text: `Kc = ${summary.key_hex}` }));
      ioCard.append(el("p", { className: "calc-line mono", text: `COUNT = ${traced.count_hex}${traced.fn !== null ? ` (from FN ${traced.fn})` : ""}` }));
      if (summary.fn_details && traced.index === 0) {
        const { t1, t2, t3 } = summary.fn_details;
        ioCard.append(el("p", { className: "calc-line mono", text: `T1 = ${t1}, T2 = ${t2}, T3 = ${t3}` }));
      }
    }
  }

  function renderState(step) {
    clear(stateCard);
    const injecting = step.phase === "key" || step.phase === "count";
    const heads = ["Register", "Before clocking", "After clocking"];
    if (injecting) heads.push(`After bit-0 XOR (${step.input_bit})`);
    const table = el(
      "table",
      { className: "data-table state-table mono" },
      el("thead", {}, el("tr", {}, ...heads.map((name) => el("th", { scope: "col", text: name })))),
    );
    const body = el("tbody");
    specs.forEach((spec, index) => {
      const cellFor = (value) => el("td", {}, el("span", { text: toBinary(value, spec.length) }), el("span", { className: "muted hex-note", text: toHex(value, spec.length) }));
      const row = el(
        "tr",
        { className: `reg-tone-${index + 1}` },
        el("th", { scope: "row", text: spec.name }),
        cellFor(step.registers_before[index]),
        cellFor(step.registers_after_clock[index]),
      );
      if (injecting) row.append(cellFor(step.registers[index]));
      body.append(row);
    });
    table.append(body);
    stateCard.append(el("h3", { text: "Register states" }), el("div", { className: "table-wrap" }, table));
  }

  function renderStream(step) {
    const lastIndex = step.phase === "keystream" ? step.keystream_index : step.phase === "xor" ? 227 : -1;
    const fill = (name, bits, offset) => {
      sequenceCells[name].forEach((cell, index) => {
        const absolute = index + offset;
        const shown = absolute <= lastIndex;
        cell.textContent = shown ? bits[index] : "·";
        cell.classList.toggle("generated", shown);
        cell.classList.toggle("latest", absolute === lastIndex && step.phase === "keystream");
      });
    };
    fill("downlink", summary.downlink, 0);
    fill("uplink", summary.uplink, 114);
    generatedLabel.textContent = `${lastIndex + 1} of 228 bits generated`;
  }

  function renderXor(step) {
    clear(xorCard);
    const segment = summary.segments[step.segment];
    xorCard.append(
      el("h3", { text: `Bitwise XOR · message bit ${step.bit_index + 1} / ${summary.bit_length}` }),
      el(
        "div",
        { className: "segment-summary" },
        chip("Segment", `${segment.index + 1} / ${summary.segment_count}`),
        chip("COUNT", segment.count_hex),
        segment.fn !== null ? chip("FN", segment.fn) : null,
        chip("Generated", `${segment.generated} bits`),
        chip("Used", `${segment.length} bits`),
        chip("Unused", `${segment.unused} bits`),
      ),
    );

    const lines = el("div", { className: "xor-lines mono" });
    for (let start = 0; start < 114; start += XOR_LINE_BITS) {
      const rows = { plain: [], key: [], cipher: [] };
      for (let offset = start; offset < Math.min(start + XOR_LINE_BITS, 114); offset += 1) {
        const used = offset < segment.length;
        const done = used && offset <= step.segment_bit;
        const current = used && offset === step.segment_bit;
        const flag = current ? " current" : "";
        rows.plain.push(el("span", { className: `xbit${used ? "" : " blank"}${flag}`, text: used ? segment.plaintext_bits[offset] : " " }));
        rows.key.push(el("span", { className: `xbit${used ? " key" : " unused"}${flag}`, text: segment.keystream_bits[offset] }));
        rows.cipher.push(el("span", { className: `xbit${done ? " cipher" : " blank"}${flag}`, text: done ? segment.ciphertext_bits[offset] : used ? "·" : " " }));
      }
      lines.append(
        el(
          "div",
          { className: "xor-line" },
          el("span", { className: "xor-label", text: "Plaintext" }), el("span", { className: "xbits" }, ...rows.plain),
          el("span", { className: "xor-label", text: "Keystream" }), el("span", { className: "xbits" }, ...rows.key),
          el("span", { className: "xor-label", text: "Ciphertext" }), el("span", { className: "xbits" }, ...rows.cipher),
        ),
      );
    }
    xorCard.append(
      el("div", { className: "equation-big mono", text: `${step.plaintext_bit} XOR ${step.keystream_bit} = ${step.ciphertext_bit}` }),
      el("div", { className: "xor-scroll" }, lines),
    );
    if (segment.unused) {
      xorCard.append(el("p", { className: "hint", text: `Faded keystream bits are the ${segment.unused} unused bits of this frame. They are generated but never touch the message.` }));
    }
    if (summary.segment_count > 1) {
      const list = el("div", { className: "segment-track" });
      for (const item of summary.segments) {
        const state = item.index < step.segment ? "done" : item.index === step.segment ? "current" : "";
        list.append(el("span", { className: `segment-pill mono ${state}`, text: `${item.count_hex} · ${item.length}b` }));
      }
      xorCard.append(el("h3", { text: "Frames" }), list);
    }
    if (step.bit_index === summary.bit_length - 1) {
      xorCard.append(el("p", { className: "done-line", text: `Complete. Ciphertext: ${summary.ciphertext_hex} (${summary.bit_length} bits)` }));
    }
  }

  return {
    render(step, index, context) {
      const isXor = step.phase === "xor";
      diagramCard.hidden = isXor;
      infoGrid.hidden = isXor;
      stateCard.hidden = isXor;
      xorCard.hidden = !isXor;
      renderStream(step);
      if (isXor) {
        renderXor(step);
        return;
      }
      renderRegisters(step, context);
      renderClock(step);
      renderFeedback(step);
      renderIo(step);
      renderState(step);
    },
    destroy() {},
  };
}
