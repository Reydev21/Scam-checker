/* ═══════════════════════════════════════════════════
   ScamCheck AI — app.js
   Handles: tabs, drag/drop, file upload, camera capture (WebRTC), form submit, result render
   ═══════════════════════════════════════════════════ */

// ── DOM refs ──────────────────────────────────────────
const form          = document.getElementById("checkerForm");
const modeInput     = document.getElementById("mode");
const articleFields = document.getElementById("articleFields");
const modeTitle     = document.getElementById("modeTitle");
const textEl        = document.getElementById("text");
const dropzone      = document.getElementById("dropzone");
const imageInput    = document.getElementById("image");
const previewBox    = document.getElementById("previewBox");
const previewImg    = document.getElementById("preview");
const fileNameEl    = document.getElementById("fileName");
const removeImageBtn= document.getElementById("removeImage");
const statusEl      = document.getElementById("status");
const statusText    = document.getElementById("statusText");
const statusIconRef = document.getElementById("statusIconRef");
const resultSection = document.getElementById("result");
const scanBtn       = document.getElementById("scanBtn");
const browseBtn     = document.getElementById("browseBtn");
const cameraBtn     = document.getElementById("cameraBtn");
const articleInput  = document.getElementById("source_url");

// Camera modal refs
const cameraModal   = document.getElementById("cameraModal");
const cameraFeed    = document.getElementById("cameraFeed");
const snapCanvas    = document.getElementById("snapCanvas");
const snapBtn       = document.getElementById("snapBtn");
const switchBtn     = document.getElementById("switchCamera");
const closeCamera   = document.getElementById("closeCamera");
const cancelCamera  = document.getElementById("cancelCamera");
const cameraError   = document.getElementById("cameraError");
const cameraErrorMsg= document.getElementById("cameraErrorMsg");

// ── Camera state ──────────────────────────────────────
let activeStream    = null;
let facingMode      = "environment"; // "environment" = back cam, "user" = front cam

// ═══════════════════════════════════════════════════
// TABS
// ═══════════════════════════════════════════════════
document.querySelectorAll(".tab").forEach(tab => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(x => x.classList.remove("active"));
    tab.classList.add("active");

    const mode    = tab.dataset.mode;
    sessionStorage.setItem("scamcheck-mode", mode);
    const article = mode === "article";
    const receipt = mode === "receipt";
    modeInput.value = mode;
    articleFields.classList.toggle("hidden", !article);
    document.getElementById("receiptTip").classList.toggle("hidden", !receipt);
    modeTitle.textContent     = article ? "Check an article's credibility signals" 
                              : receipt ? "Scan a receipt or transaction screenshot" 
                              : "Scan a suspicious message";
    textEl.placeholder        = article
      ? "Upload an article screenshot or paste its link above..."
      : receipt
      ? "Upload a receipt image, or paste receipt text here..."
      : "Type a message or attach a screenshot...";
    textEl.classList.toggle("hidden", article);
    resultSection.classList.add("hidden");
    showStatus("", "");
  });
});

// Keep the selected checker when the browser restores or reloads the page.
const savedMode = sessionStorage.getItem("scamcheck-mode");
if (savedMode && ["message", "article", "receipt"].includes(savedMode)) {
  const savedTab = document.querySelector(`.tab[data-mode="${savedMode}"]`);
  if (savedTab) savedTab.click();
}

// ═══════════════════════════════════════════════════
// DRAG & DROP
// ═══════════════════════════════════════════════════
["dragenter", "dragover"].forEach(ev =>
  dropzone.addEventListener(ev, e => { e.preventDefault(); dropzone.classList.add("drag"); })
);
["dragleave", "drop"].forEach(ev =>
  dropzone.addEventListener(ev, e => { e.preventDefault(); dropzone.classList.remove("drag"); })
);
dropzone.addEventListener("drop", e => {
  const file = e.dataTransfer.files[0];
  if (file) setImage(file);
});

// ═══════════════════════════════════════════════════
// PLUS MENU BUTTON
// ═══════════════════════════════════════════════════
const plusMenuBtn = document.getElementById("plusMenuBtn");
const uploadMenu  = document.getElementById("uploadMenu");

plusMenuBtn.addEventListener("click", e => {
  e.stopPropagation();
  uploadMenu.classList.toggle("hidden");
});

// Close menu when clicking outside
document.addEventListener("click", e => {
  if (!plusMenuBtn.contains(e.target) && !uploadMenu.contains(e.target)) {
    uploadMenu.classList.add("hidden");
  }
});

// ═══════════════════════════════════════════════════
// BROWSE FILE BUTTON
// ═══════════════════════════════════════════════════
browseBtn.addEventListener("click", e => {
  e.stopPropagation();
  uploadMenu.classList.add("hidden");
  imageInput.click();
});

imageInput.addEventListener("change", () => {
  if (imageInput.files[0]) setImage(imageInput.files[0]);
});

// ═══════════════════════════════════════════════════
// SET IMAGE (used by both upload and camera snap)
// ═══════════════════════════════════════════════════
function setImage(file) {
  if (!file.type.startsWith("image/")) {
    showStatus("Please choose a PNG, JPG, or WEBP image.", "warn");
    return;
  }
  if (file.size > 12 * 1024 * 1024) {
    showStatus("Image is larger than 12 MB.", "warn");
    return;
  }

  // Inject file into the hidden <input type="file">
  const dt = new DataTransfer();
  dt.items.add(file);
  imageInput.files = dt.files;

  // Show preview
  previewImg.src = URL.createObjectURL(file);
  fileNameEl.textContent = file.name;
  previewBox.classList.remove("hidden");
  showStatus("Image ready — click Analyze now.", "ok");
}

// Remove image
removeImageBtn.addEventListener("click", () => {
  imageInput.value = "";
  previewBox.classList.add("hidden");
  previewImg.removeAttribute("src");
  showStatus("", "");
});

// ═══════════════════════════════════════════════════
// CAMERA — OPEN
// ═══════════════════════════════════════════════════
cameraBtn.addEventListener("click", openCamera);

async function openCamera() {
  uploadMenu.classList.add("hidden");
  cameraModal.classList.remove("hidden");
  cameraError.classList.add("hidden");
  await startStream();
}

async function startStream() {
  // Stop any existing stream first
  stopStream();

  // Check browser support
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    showCameraError("Your browser does not support camera access. Please use a modern browser or upload an image instead.");
    return;
  }

  try {
    const constraints = {
      video: {
        facingMode: facingMode,
        width: { ideal: 1280 },
        height: { ideal: 720 }
      },
      audio: false
    };

    activeStream = await navigator.mediaDevices.getUserMedia(constraints);
    cameraFeed.srcObject = activeStream;
    cameraFeed.play();
    cameraError.classList.add("hidden");
  } catch (err) {
    let msg = "Camera access was denied or is unavailable.";
    if (err.name === "NotAllowedError" || err.name === "PermissionDeniedError") {
      msg = "Camera permission was denied. Please allow camera access in your browser settings and try again.";
    } else if (err.name === "NotFoundError" || err.name === "DevicesNotFoundError") {
      msg = "No camera device was found. Please connect a camera or use file upload instead.";
    } else if (err.name === "NotReadableError") {
      msg = "Camera is in use by another application. Please close it and try again.";
    }
    showCameraError(msg);
  }
}

// ═══════════════════════════════════════════════════
// CAMERA — SWITCH (front / back)
// ═══════════════════════════════════════════════════
switchBtn.addEventListener("click", () => {
  facingMode = facingMode === "environment" ? "user" : "environment";
  startStream();
});

// ═══════════════════════════════════════════════════
// CAMERA — SNAP PHOTO
// ═══════════════════════════════════════════════════
snapBtn.addEventListener("click", () => {
  if (!activeStream) return;

  const video  = cameraFeed;
  const canvas = snapCanvas;
  const w = video.videoWidth  || 1280;
  const h = video.videoHeight || 720;

  canvas.width  = w;
  canvas.height = h;

  const ctx = canvas.getContext("2d");
  // Mirror front cam for natural feel, flip back
  if (facingMode === "user") {
    ctx.translate(w, 0);
    ctx.scale(-1, 1);
  }
  ctx.drawImage(video, 0, 0, w, h);

  // Flash animation
  flashEffect();

  // Convert canvas to File
  canvas.toBlob(blob => {
    if (!blob) return;
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    const file = new File([blob], `camera-snap-${timestamp}.jpg`, { type: "image/jpeg" });
    closeModal();
    setImage(file);
  }, "image/jpeg", 0.95);
});

// ═══════════════════════════════════════════════════
// CAMERA — CLOSE / CLEANUP
// ═══════════════════════════════════════════════════
closeCamera.addEventListener("click", closeModal);
cancelCamera.addEventListener("click", closeModal);

// Close on backdrop click
cameraModal.addEventListener("click", e => {
  if (e.target === cameraModal) closeModal();
});

// Close on Escape key
document.addEventListener("keydown", e => {
  if (e.key === "Escape" && !cameraModal.classList.contains("hidden")) {
    closeModal();
  }
});

function closeModal() {
  stopStream();
  cameraModal.classList.add("hidden");
}

function stopStream() {
  if (activeStream) {
    activeStream.getTracks().forEach(track => track.stop());
    activeStream = null;
    cameraFeed.srcObject = null;
  }
}

// ═══════════════════════════════════════════════════
// CAMERA HELPERS
// ═══════════════════════════════════════════════════
function showCameraError(msg) {
  cameraErrorMsg.textContent = msg;
  cameraError.classList.remove("hidden");
}

function flashEffect() {
  const flash = document.createElement("div");
  flash.style.cssText = `
    position: absolute; inset: 0;
    background: #fff;
    opacity: 0.75;
    pointer-events: none;
    z-index: 10;
    animation: fadeOut 0.3s ease forwards;
  `;
  const vp = document.querySelector(".camera-viewport");
  if (!document.getElementById("flashKeyframes")) {
    const style = document.createElement("style");
    style.id = "flashKeyframes";
    style.textContent = "@keyframes fadeOut { from { opacity: .75 } to { opacity: 0 } }";
    document.head.appendChild(style);
  }
  vp.appendChild(flash);
  flash.addEventListener("animationend", () => flash.remove());
}

// ═══════════════════════════════════════════════════
// FORM SUBMIT
// ═══════════════════════════════════════════════════
form.addEventListener("submit", async e => {
  e.preventDefault();

  const mode = modeInput.value;
  const isArticle = mode === "article";
  if (isArticle && !articleInput.value.trim() && !imageInput.files[0]) {
    showStatus("Paste an article link or upload a picture first.", "warn");
    return;
  }
  if (!isArticle && !textEl.value.trim() && !imageInput.files[0]) {
    showStatus("Enter text or upload / snap an image first.", "warn");
    return;
  }

  const data = new FormData(form);

  scanBtn.disabled = true;
  scanBtn.classList.add("is-loading");
  scanBtn.setAttribute("aria-label", "Analyzing");
  scanBtn.title = "Analyzing";
  showStatus(
    mode === "article"
      ? "Checking article credibility signals…"
      : "Scanning text, URLs, and image content…",
    "info"
  );

  try {
    const res  = await fetch("/api/check", { method: "POST", body: data });
    const json = await res.json();
    if (!res.ok) throw new Error(json.error || "Analysis failed.");
    renderResult(json);
  } catch (err) {
    showStatus(err.message, "warn");
  } finally {
    scanBtn.disabled = false;
    scanBtn.classList.remove("is-loading");
    scanBtn.setAttribute("aria-label", "Analyze");
    scanBtn.title = "Analyze";
    scanBtn.innerHTML = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="22" y1="2" x2="11" y2="13"></line><polygon points="22 2 15 22 11 13 2 9 22 2"></polygon></svg>';
  }
});

// ═══════════════════════════════════════════════════
// RENDER RESULT
// ═══════════════════════════════════════════════════
function renderResult(data) {
  resultSection.classList.remove("hidden");

  const score = data.risk_score || 0;
  const level = data.risk_level || "—";

  // Risk level & colors
  let color, bgColor;
  if (score >= 70) {
    color   = "#ef4444";
    bgColor = "rgba(239,68,68,0.12)";
  } else if (score >= 35) {
    color   = "#f59e0b";
    bgColor = "rgba(245,158,11,0.12)";
  } else {
    color   = "#10b981";
    bgColor = "rgba(16,185,129,0.12)";
  }

  document.getElementById("riskLevel").textContent = level;
  document.getElementById("riskLevel").style.color = color;
  document.getElementById("credibility").textContent = data.credibility || "";
  document.getElementById("riskScore").textContent = score;
  document.getElementById("riskScore").style.color = color;

  // Meter
  const meter = document.getElementById("meterFill");
  meter.style.width      = score + "%";
  meter.style.background = color;

  // Result card styling
  resultSection.style.borderColor = color + "44";

  // Score box background
  const scoreBox = document.querySelector(".score-box");
  if (scoreBox) scoreBox.style.background = bgColor;

  // Receipt Verdict
  const receiptVerdict = document.getElementById("receiptVerdict");
  if (data.analysis_type === "receipt") {
    document.getElementById("verdictPlatform").textContent = data.platform || "Unknown";
    document.getElementById("verdictText").textContent = data.verdict || "—";
    receiptVerdict.classList.remove("hidden");
  } else {
    receiptVerdict.classList.add("hidden");
  }

  // Receipt image forensics
  const forensicsPanel = document.getElementById("forensicsPanel");
  const forensics = data.image_forensics;
  if (forensicsPanel) {
    if (forensics && forensics.available) {
      const forensicsVerdict = document.getElementById("forensicsVerdict");
      forensicsVerdict.textContent = forensics.verdict || "—";
      forensicsVerdict.style.color = forensics.tampering_score >= 55 ? "#ef4444"
        : forensics.tampering_score >= 25 ? "#f59e0b" : "#10b981";
      document.getElementById("forensicsScore").textContent = (forensics.tampering_score || 0) + " / 100";
      document.getElementById("forensicsCanvas").textContent =
        `${forensics.dimensions || "?"} ${forensics.format ? "(" + forensics.format + ")" : ""}`.trim();
      forensicsPanel.classList.remove("hidden");
    } else {
      forensicsPanel.classList.add("hidden");
    }
  }

  // Article source verification
  const sourcePanel = document.getElementById("sourcePanel");
  const source = data.source_verification;
  if (sourcePanel) {
    if (source) {
      document.getElementById("sourcePublisher").textContent =
        source.real_publisher || "Not stated by the page";
      const ownership = document.getElementById("sourceOwnership");
      if (source.impersonating_brand) {
        ownership.textContent = `FAKE - impersonates ${source.impersonating_brand} (real domain: ${source.official_domain})`;
        ownership.style.color = "#ef4444";
      } else if (source.is_official_domain) {
        ownership.textContent = `OFFICIAL - ${source.official_domain}`;
        ownership.style.color = "#10b981";
      } else {
        ownership.textContent = "Unverified third-party domain";
        ownership.style.color = "#f59e0b";
      }
      document.getElementById("sourceDomain").textContent = source.registrable_domain || "—";
      document.getElementById("sourceAge").textContent = source.domain_age_days == null
        ? "Registration record not public"
        : `${source.domain_age_days} days (registered ${source.registered_on})`;
      sourcePanel.classList.remove("hidden");
    } else {
      sourcePanel.classList.add("hidden");
    }
  }

  // Lists
  fillList("flags",    data.red_flags,         "No major red flags detected.");
  fillList("positive", data.positive_signals || [], "No strong positive signals detected.");

  document.getElementById("action").textContent = data.action || "";
  document.getElementById("json").textContent   = JSON.stringify(data, null, 2);

  showStatus("Analysis complete.", "ok");
  resultSection.scrollIntoView({ behavior: "smooth", block: "start" });
}

function fillList(id, items, emptyMsg) {
  const el = document.getElementById(id);
  el.innerHTML = "";
  const list = items && items.length ? items : [emptyMsg];
  list.forEach(item => {
    const li = document.createElement("li");
    li.textContent = item;
    el.appendChild(li);
  });
}

// ═══════════════════════════════════════════════════
// STATUS HELPER
// ═══════════════════════════════════════════════════
const STATUS_ICONS = { warn: "i-alert", ok: "i-check-circle", info: "i-info", idle: "i-info" };

function showStatus(msg, type) {
  statusText.textContent = msg;
  statusEl.classList.toggle("quiet", !msg);
  statusIconRef.setAttribute("href", "#" + (STATUS_ICONS[type] || "i-info"));
  statusEl.style.color = type === "warn"  ? "#ef4444"
                        : type === "ok"   ? "#10b981"
                        : type === "info" ? "#2563eb"
                        : "#64748b";
}
