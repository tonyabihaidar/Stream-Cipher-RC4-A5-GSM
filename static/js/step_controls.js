// Transport controls shared by both visualizations. This class only tracks a position in
// the trace: rendering is delegated, and every position maps to a complete snapshot from
// the server, so moving backwards never has to undo anything.

import { clear, el } from "./dom.js";

const BASE_DELAY_MS = 1000;

export class StepControls {
  constructor(renderStep) {
    this.renderStep = renderStep;
    this.total = 0;
    this.index = 0;
    this.phases = [];
    this.playing = false;
    this.timer = null;
    this.speed = 1;
    this.navigation = 0;

    this.play = document.getElementById("ctl-play");
    this.progress = document.getElementById("ctl-progress");
    this.counter = document.getElementById("ctl-counter");
    this.jump = document.getElementById("ctl-jump");
    this.chips = document.getElementById("phase-chips");
    this.speedSelect = document.getElementById("ctl-speed");
    this.strideGroup = document.getElementById("ctl-stride-group");
    this.strideSelect = document.getElementById("ctl-stride");
    this.prev = document.getElementById("ctl-prev");
    this.next = document.getElementById("ctl-next");

    document.getElementById("ctl-start").addEventListener("click", () => this.start());
    document.getElementById("ctl-reset").addEventListener("click", () => this.reset());
    document.getElementById("ctl-jump-go").addEventListener("click", () => this.jumpToInput());
    this.jump.addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        event.preventDefault();
        this.jumpToInput();
      }
    });
    this.prev.addEventListener("click", () => this.step(-1));
    this.next.addEventListener("click", () => this.step(1));
    this.play.addEventListener("click", () => this.togglePlay());
    this.speedSelect.addEventListener("change", () => {
      this.speed = Number(this.speedSelect.value);
    });
    this.progress.addEventListener("input", () => {
      this.pause();
      this.goTo(Number(this.progress.value));
    });
    document.addEventListener("keydown", (event) => this.onKey(event));
  }

  get delay() {
    return BASE_DELAY_MS / this.speed;
  }

  configure(total, phases, index = 0) {
    this.pause();
    this.total = total;
    this.phases = phases;
    this.progress.max = String(Math.max(total - 1, 0));
    this.jump.max = String(total);
    clear(this.chips);
    for (const phase of phases) {
      const chip = el("button", {
        type: "button",
        className: "chip",
        text: phase.title,
        title: phase.description,
        onclick: () => {
          this.pause();
          this.goTo(phase.start);
        },
      });
      chip.dataset.phase = phase.id;
      this.chips.append(chip);
    }
    return this.goTo(Math.min(index, total - 1));
  }

  currentPhase() {
    return this.phaseAt(this.index);
  }

  phaseAt(index) {
    return this.phases.find((phase) => index >= phase.start && index < phase.start + phase.count);
  }

  async goTo(index, options = {}) {
    if (this.total === 0) return;
    const target = Math.max(0, Math.min(index, this.total - 1));
    this.navigation += 1;
    const token = this.navigation;
    const previous = this.index;
    this.index = target;
    this.syncControls();
    await this.renderStep(target, {
      animate: Boolean(options.animate) && target === previous + 1,
      duration: Math.min(this.delay * 0.7, 520),
      isCurrent: () => token === this.navigation,
    });
  }

  // In the A5/1 XOR phase, the user can choose to move a whole byte at a time.
  strideAt(index) {
    const phase = this.phaseAt(index);
    if (phase && phase.id === "xor" && !this.strideGroup.hidden) return Number(this.strideSelect.value);
    return 1;
  }

  step(direction) {
    this.pause();
    return this.move(direction);
  }

  move(direction) {
    const stride = this.strideAt(this.index);
    if (stride === 1) return this.goTo(this.index + direction, { animate: direction > 0 });
    const phase = this.currentPhase();
    const offset = this.index - phase.start;
    const target = direction > 0 ? offset + stride - (offset % stride) : offset - (offset % stride || stride);
    return this.goTo(target < 0 ? phase.start - 1 : phase.start + target);
  }

  start() {
    this.pause();
    this.goTo(0).then(() => this.resume());
  }

  reset() {
    this.pause();
    this.goTo(0);
  }

  togglePlay() {
    if (this.playing) this.pause();
    else this.resume();
  }

  resume() {
    if (this.total === 0) return;
    if (this.index >= this.total - 1) this.goTo(0);
    this.playing = true;
    this.syncPlayButton();
    this.schedule();
  }

  schedule() {
    window.clearTimeout(this.timer);
    this.timer = window.setTimeout(async () => {
      if (!this.playing) return;
      if (this.index >= this.total - 1) {
        this.pause();
        return;
      }
      await this.move(1);
      if (this.playing) this.schedule();
    }, this.delay);
  }

  pause() {
    window.clearTimeout(this.timer);
    if (!this.playing) return;
    this.playing = false;
    this.syncPlayButton();
  }

  jumpToInput() {
    const value = Number(this.jump.value);
    if (!Number.isInteger(value) || value < 1 || value > this.total) {
      this.jump.setAttribute("aria-invalid", "true");
      return;
    }
    this.jump.removeAttribute("aria-invalid");
    this.pause();
    this.goTo(value - 1);
  }

  syncPlayButton() {
    this.play.textContent = this.playing ? "⏸ Pause" : "▶ Play";
    this.play.setAttribute("aria-pressed", String(this.playing));
    // Announcing every step while playing would overwhelm a screen reader.
    document.getElementById("stage-explanation").setAttribute("aria-live", this.playing ? "off" : "polite");
  }

  syncControls() {
    this.progress.value = String(this.index);
    this.progress.style.setProperty("--progress", `${this.total > 1 ? (this.index / (this.total - 1)) * 100 : 0}%`);
    this.counter.textContent = `Step ${this.index + 1} / ${this.total}`;
    this.prev.disabled = this.index === 0;
    this.next.disabled = this.index >= this.total - 1;
    const phase = this.currentPhase();
    this.chips.querySelectorAll(".chip").forEach((chip) => {
      const active = phase && chip.dataset.phase === phase.id;
      chip.classList.toggle("active", Boolean(active));
      chip.setAttribute("aria-pressed", String(Boolean(active)));
    });
  }

  onKey(event) {
    if (this.total === 0 || document.body.dataset.view !== "visualize") return;
    const tag = event.target.tagName;
    if (["INPUT", "TEXTAREA", "SELECT"].includes(tag) || event.altKey || event.ctrlKey || event.metaKey) return;
    if (event.key === "ArrowRight") {
      event.preventDefault();
      this.step(1);
    } else if (event.key === "ArrowLeft") {
      event.preventDefault();
      this.step(-1);
    } else if (event.key === " " && tag !== "BUTTON" && tag !== "SUMMARY") {
      event.preventDefault();
      this.togglePlay();
    }
  }
}
