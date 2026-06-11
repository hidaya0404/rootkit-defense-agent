const canvas = document.getElementById("particles");
const ctx = canvas.getContext("2d");

let w, h;
let particles = [];

function resizeCanvas() {
  w = canvas.width = window.innerWidth;
  h = canvas.height = window.innerHeight;
}

function createParticles() {
  particles = [];
  const count = Math.floor((window.innerWidth * window.innerHeight) / 14000);

  for (let i = 0; i < count; i++) {
    particles.push({
      x: Math.random() * w,
      y: Math.random() * h,
      r: Math.random() * 1.8 + 0.5,
      vx: (Math.random() - 0.5) * 0.35,
      vy: (Math.random() - 0.5) * 0.35,
      alpha: Math.random() * 0.55 + 0.18
    });
  }
}

function drawParticles() {
  ctx.clearRect(0, 0, w, h);

  particles.forEach((p) => {
    p.x += p.vx;
    p.y += p.vy;

    if (p.x < 0 || p.x > w) p.vx *= -1;
    if (p.y < 0 || p.y > h) p.vy *= -1;

    ctx.beginPath();
    ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
    ctx.fillStyle = `rgba(255, 35, 35, ${p.alpha})`;
    ctx.fill();
  });

  for (let i = 0; i < particles.length; i++) {
    for (let j = i + 1; j < particles.length; j++) {
      const a = particles[i];
      const b = particles[j];
      const dx = a.x - b.x;
      const dy = a.y - b.y;
      const dist = Math.sqrt(dx * dx + dy * dy);

      if (dist < 120) {
        ctx.beginPath();
        ctx.moveTo(a.x, a.y);
        ctx.lineTo(b.x, b.y);
        ctx.strokeStyle = `rgba(255, 20, 20, ${0.12 * (1 - dist / 120)})`;
        ctx.lineWidth = 1;
        ctx.stroke();
      }
    }
  }

  requestAnimationFrame(drawParticles);
}

resizeCanvas();
createParticles();
drawParticles();

window.addEventListener("resize", () => {
  resizeCanvas();
  createParticles();
});

const progressFill = document.getElementById("progressFill");
const progressGlow = document.getElementById("progressGlow");
const progressPercent = document.getElementById("progressPercent");
const terminalText = document.getElementById("terminalText");
const enterBtn = document.getElementById("enterBtn");
const hint = document.getElementById("hint");

const modules = [
  document.getElementById("m1"),
  document.getElementById("m2"),
  document.getElementById("m3"),
  document.getElementById("m4")
];

const terminalMessages = [
  "initializing defensive kernel monitor",
  "loading agent telemetry channels",
  "verifying quarantine evidence chain",
  "connecting sandbox execution pipeline",
  "extracting IOC and risk indicators",
  "preparing incident response console",
  "system ready"
];

let progress = 0;
let messageIndex = 0;
let canEnter = false;

function setTerminalMessage(text) {
  terminalText.textContent = text;
}

function updateModules(value) {
  const levels = [20, 45, 70, 95];

  levels.forEach((level, index) => {
    if (value >= level && !modules[index].classList.contains("ok")) {
      modules[index].textContent = "[ OK ]";
      modules[index].classList.add("ok");
    }
  });
}

function updateTerminal(value) {
  let newIndex = 0;

  if (value >= 15) newIndex = 1;
  if (value >= 32) newIndex = 2;
  if (value >= 50) newIndex = 3;
  if (value >= 68) newIndex = 4;
  if (value >= 86) newIndex = 5;
  if (value >= 100) newIndex = 6;

  if (newIndex !== messageIndex) {
    messageIndex = newIndex;
    setTerminalMessage(terminalMessages[messageIndex]);
  }
}

function updateProgress(value) {
  progressFill.style.width = value + "%";
  progressGlow.style.transform = `translateX(${value * 6.9}px)`;
  progressPercent.textContent = value + "%";
}

const loader = setInterval(() => {
  progress += Math.floor(Math.random() * 6) + 3;

  if (progress > 100) progress = 100;

  updateProgress(progress);
  updateModules(progress);
  updateTerminal(progress);

  if (progress >= 100) {
    clearInterval(loader);
    canEnter = true;
    enterBtn.style.display = "inline-block";
    hint.textContent = "System ready — press Enter or launch console";
  }
}, 260);

function goDashboard() {
  if (!canEnter) return;

  document.body.classList.add("exit");

  setTimeout(() => {
    window.location.href = "/dashboard";
  }, 520);
}

enterBtn.addEventListener("click", goDashboard);

document.addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    goDashboard();
  }
});
