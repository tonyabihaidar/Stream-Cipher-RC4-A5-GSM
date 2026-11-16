// Guided tour started by the Help button. Each step highlights one part of the page and
// explains it in a small card with Next and Skip.

import { el } from "./dom.js";

const STEPS = [
  {
    target: null,
    title: "Welcome to the Stream Cipher Laboratory",
    text: "This tool encrypts and decrypts messages with RC4 and A5/1, and can show every step the cipher takes. This short tour shows you around.",
  },
  {
    target: "algorithm",
    title: "Pick an algorithm",
    text: "Switch between RC4 and A5/1 here. The fields and explanations on the page follow your choice.",
  },
  {
    target: "message",
    title: "Write a message",
    text: "Type any text, Arabic included, or switch the format to hex bytes or binary bits. You can also load a ready-made example, including the official test vectors.",
  },
  {
    target: "key",
    title: "Choose a secret key",
    text: "Type a key, or press Random to generate one. A5/1 also needs a COUNT value and a direction.",
  },
  {
    target: "encrypt",
    title: "Encrypt",
    text: "Press Encrypt to see the ciphertext, the keystream and the lengths. Send to Decryption copies the result and settings to the Decrypt panel.",
  },
  {
    target: "decrypt",
    title: "Decrypt",
    text: "Decrypt with the same key and settings to get the original message back. A wrong key gives scrambled output, not an error.",
  },
  {
    target: "steps",
    title: "Show the steps",
    text: "Turn this on to watch the cipher work through the Encrypt panel's message step by step. Use Play, Next and Previous, or the arrow keys.",
  },
  {
    target: "learn",
    title: "Learn your algorithms",
    text: "Short explanations of stream ciphers, XOR, RC4 and A5/1, with a side-by-side comparison and their security limits.",
  },
  {
    target: "help",
    title: "You're ready",
    text: "That's the whole tool. Press Help any time to see this tour again.",
  },
];

const GAP = 12;
const SPOTLIGHT_PADDING = 6;

// The first matching element that is actually displayed, since some exist once per algorithm.
function findTarget(name) {
  if (!name) return null;
  return [...document.querySelectorAll(`[data-tour="${name}"]`)].find((node) => node.getClientRects().length > 0) || null;
}

export function initTour(state) {
  const helpButton = document.getElementById("help-tour");
  const titleId = "tour-title";
  const textId = "tour-text";

  const spotlight = el("div", { className: "tour-spotlight" });
  const counter = el("p", { className: "tour-counter mono" });
  const title = el("h2", { id: titleId, className: "tour-title" });
  const text = el("p", { id: textId, className: "tour-text" });
  const skip = el("button", { type: "button", className: "btn", text: "Skip" });
  const next = el("button", { type: "button", className: "btn btn-primary", text: "Next" });
  const card = el(
    "div",
    { className: "tour-card", role: "dialog", "aria-modal": "true", "aria-labelledby": titleId, "aria-describedby": textId },
    counter,
    title,
    text,
    el("div", { className: "tour-actions" }, skip, next),
  );
  const root = el("div", { className: "tour", hidden: true }, spotlight, card);
  document.body.append(root);

  let index = 0;
  let frame = 0;

  function position() {
    const target = findTarget(STEPS[index].target);
    root.classList.toggle("no-target", !target);
    if (!target) {
      spotlight.hidden = true;
      card.style.left = `${Math.max(16, (window.innerWidth - card.offsetWidth) / 2)}px`;
      card.style.top = `${Math.max(16, (window.innerHeight - card.offsetHeight) / 2)}px`;
      return;
    }
    const rect = target.getBoundingClientRect();
    spotlight.hidden = false;
    spotlight.style.left = `${rect.left - SPOTLIGHT_PADDING}px`;
    spotlight.style.top = `${rect.top - SPOTLIGHT_PADDING}px`;
    spotlight.style.width = `${rect.width + SPOTLIGHT_PADDING * 2}px`;
    spotlight.style.height = `${rect.height + SPOTLIGHT_PADDING * 2}px`;

    // Try below, above, right and left of the target, in that order. If none fits, the card
    // goes to the bottom of the screen.
    const width = card.offsetWidth;
    const height = card.offsetHeight;
    const edge = SPOTLIGHT_PADDING + GAP;
    const clampLeft = (value) => Math.min(Math.max(16, value), window.innerWidth - width - 16);
    const clampTop = (value) => Math.min(Math.max(16, value), window.innerHeight - height - 16);
    const fitsVertically = (top) => top >= 16 && top + height <= window.innerHeight - 16;
    const candidates = [
      { left: clampLeft(rect.left), top: rect.bottom + edge, fits: fitsVertically(rect.bottom + edge) },
      { left: clampLeft(rect.left), top: rect.top - edge - height, fits: fitsVertically(rect.top - edge - height) },
      { left: rect.right + edge, top: clampTop(rect.top), fits: rect.right + edge + width <= window.innerWidth - 16 },
      { left: rect.left - edge - width, top: clampTop(rect.top), fits: rect.left - edge - width >= 16 },
    ];
    const choice = candidates.find((item) => item.fits) || { left: clampLeft(rect.left), top: window.innerHeight - height - 16 };
    card.style.left = `${choice.left}px`;
    card.style.top = `${choice.top}px`;
  }

  function schedulePosition() {
    window.cancelAnimationFrame(frame);
    frame = window.requestAnimationFrame(position);
  }

  function show(stepIndex) {
    index = stepIndex;
    const step = STEPS[index];
    // Everything but the navigation lives on the workspace page.
    if (step.target && !["learn", "help", "algorithm"].includes(step.target)) state.setView("workspace");
    counter.textContent = `${index + 1} / ${STEPS.length}`;
    title.textContent = step.title;
    text.textContent = step.text;
    const last = index === STEPS.length - 1;
    next.textContent = last ? "Finish" : "Next";
    skip.hidden = last;
    const target = findTarget(step.target);
    // Near the top of the screen, so the card usually has room underneath. The jump is
    // instant, so the card is placed against where the target really is.
    if (target) target.scrollIntoView({ block: "start", behavior: "auto" });
    position();
    next.focus();
  }

  function open() {
    root.hidden = false;
    document.body.classList.add("tour-open");
    window.addEventListener("resize", schedulePosition);
    window.addEventListener("scroll", schedulePosition, { passive: true });
    show(0);
  }

  function close() {
    root.hidden = true;
    document.body.classList.remove("tour-open");
    window.removeEventListener("resize", schedulePosition);
    window.removeEventListener("scroll", schedulePosition);
    helpButton.focus();
  }

  next.addEventListener("click", () => {
    if (index < STEPS.length - 1) show(index + 1);
    else close();
  });
  skip.addEventListener("click", close);

  root.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      event.preventDefault();
      close();
      return;
    }
    // Keep keyboard focus inside the card while the tour is open.
    if (event.key === "Tab") {
      const buttons = [skip, next].filter((button) => !button.hidden);
      const current = buttons.indexOf(document.activeElement);
      event.preventDefault();
      const offset = event.shiftKey ? -1 : 1;
      buttons[(current + offset + buttons.length) % buttons.length].focus();
    }
  });

  helpButton.addEventListener("click", open);
}
