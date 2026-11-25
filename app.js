let allTrials = [];
let filteredTrials = [];
let currentIndex = 0;
let trialStartTime = Date.now();
let beeswarmOpenedCount = 0;
const sessionLog = [];

const OUTCOME_DESCRIPTIONS = {
  TP: "True Positive (TP): Actual insider threat day accurately flagged above the MAD anomaly threshold.",
  FP: "False Positive (FP): Benign workday flagged above the MAD threshold due to unusual but non-malicious activity variance.",
  FN: "False Negative (FN): Actual insider threat day whose reconstruction error fell below the MAD threshold.",
  TN: "True Negative (TN): Normal benign workday accurately below the MAD anomaly threshold."
};

// Extract basename cleanly even if testing_manifest.json contains Windows backslashes
function toRelativePlotPath(rawPath, folderName) {
  if (!rawPath) return "";
  const parts = rawPath.split(/[\\/]/);
  const fileName = parts[parts.length - 1];
  return `./data/testing/${folderName}/${fileName}`;
}

async function loadManifest() {
  try {
    const res = await fetch("./data/testing_manifest.json");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const payload = await res.json();
    allTrials = (payload.trials || []).map((t) => ({
      ...t,
      web_design_A: toRelativePlotPath(t.design_A_path, "design_A_zscore"),
      web_design_B: toRelativePlotPath(t.design_B_path, "design_B_shap"),
      web_beeswarm: `./data/beeswarms/beeswarm_${t.scenario}_${t.cert_id}.png`
    }));
    filteredTrials = [...allTrials];
  } catch (err) {
    alert(
      "Could not load ./data/testing_manifest.json. Ensure testing_manifest.json, beeswarms/, and testing/ folders are placed inside /data/."
    );
    console.error(err);
  }
}

function updateLayoutMode() {
  const mode = document.getElementById("designSelect").value;
  const grid = document.getElementById("visualGrid");
  const panelA = document.getElementById("panelA");
  const panelB = document.getElementById("panelB");
  const beeswarmBar = document.getElementById("beeswarmToolbar");
  const beeswarmPanel = document.getElementById("beeswarmPanel");

  if (mode === "side_by_side") {
    grid.className = "visual-grid two-col";
    panelA.classList.remove("hidden");
    panelB.classList.remove("hidden");
    beeswarmBar.classList.remove("hidden");
  } else if (mode === "design_A") {
    // Keep Design A strictly statistical Z-score without leaking SHAP plots
    grid.className = "visual-grid one-col";
    panelA.classList.remove("hidden");
    panelB.classList.add("hidden");
    beeswarmBar.classList.add("hidden");
    beeswarmPanel.classList.add("hidden");
    document.getElementById("toggleBeeswarmBtn").textContent = "Show User Global Beeswarm";
  } else {
    grid.className = "visual-grid one-col";
    panelA.classList.add("hidden");
    panelB.classList.remove("hidden");
    beeswarmBar.classList.remove("hidden");
  }
}

function renderTrial() {
  if (!filteredTrials.length) return;
  const trial = filteredTrials[currentIndex];
  trialStartTime = Date.now();
  beeswarmOpenedCount = 0;

  document.getElementById("progressText").textContent = `${currentIndex + 1} / ${filteredTrials.length}`;
  document.getElementById("trialIdText").textContent = trial.trial_id;
  document.getElementById("userText").textContent = `${trial.scenario} (${trial.cert_id})`;
  document.getElementById("dateText").textContent = `${trial.date} (${trial.day_of_week})`;
  document.getElementById("scoreText").textContent = Number(trial.anomaly_score).toFixed(5);
  document.getElementById("threshText").textContent = Number(trial.threshold).toFixed(5);

  document.getElementById("imgA").src = trial.web_design_A;
  document.getElementById("imgB").src = trial.web_design_B;
  document.getElementById("imgBeeswarm").src = trial.web_beeswarm;
  document.getElementById("beeswarmTitle").textContent =
    `Global SHAP Beeswarm — Scenario ${trial.scenario} (${trial.cert_id}) Across All Test Days`;

  // Reset form inputs
  document.querySelectorAll('input[name="decision"]').forEach((r) => (r.checked = false));
  document.getElementById("confidenceRange").value = 50;
  document.getElementById("confidenceVal").textContent = "50%";
  document.getElementById("primaryCue").value = "";

  const fb = document.getElementById("feedbackBox");
  fb.className = "feedback-box hidden";
  fb.innerHTML = "";

  updateAccuracyBadge();
}

function updateAccuracyBadge() {
  const scored = sessionLog.filter((r) => r.user_decision !== "PREFER_NOT_TO_ANSWER");
  if (!scored.length) {
    document.getElementById("accuracyText").textContent = "N/A";
    return;
  }
  const hits = scored.filter((r) => r.is_correct).length;
  const pct = Math.round((hits / scored.length) * 100);
  document.getElementById("accuracyText").textContent = `${pct}% (${hits}/${scored.length})`;
}

function submitDecision() {
  const trial = filteredTrials[currentIndex];
  const selectedRadio = document.querySelector('input[name="decision"]:checked');
  if (!selectedRadio) {
    alert("Please select a triage classification (or 'Prefer not to answer') before submitting.");
    return;
  }

  const userDecision = selectedRadio.value;
  const confidence = Number(document.getElementById("confidenceRange").value);
  const primaryCue = document.getElementById("primaryCue").value || "unspecified";
  const responseTimeSec = Number(((Date.now() - trialStartTime) / 1000).toFixed(2));

  // Ground truth: TP and FN are actual insider threat days; FP and TN are benign days
  const actualLabel = trial.alert_type === "TP" || trial.alert_type === "FN" ? "THREAT" : "BENIGN";
  const isCorrect = userDecision === actualLabel;

  const existingIdx = sessionLog.findIndex((item) => item.trial_id === trial.trial_id);
  const record = {
    participant_id: document.getElementById("participantId").value.trim() || "ANON",
    timestamp_iso: new Date().toISOString(),
    view_mode: document.getElementById("designSelect").value,
    beeswarm_inspected_count: beeswarmOpenedCount,
    trial_id: trial.trial_id,
    scenario: trial.scenario,
    cert_id: trial.cert_id,
    date: trial.date,
    model_outcome_type: trial.alert_type,
    actual_ground_truth: actualLabel,
    user_decision: userDecision,
    is_correct: userDecision === "PREFER_NOT_TO_ANSWER" ? "" : isCorrect,
    confidence_pct: confidence,
    primary_cue: primaryCue,
    response_time_sec: responseTimeSec,
    anomaly_score: trial.anomaly_score,
    mad_threshold: trial.threshold
  };

  if (existingIdx >= 0) {
    sessionLog[existingIdx] = record;
  } else {
    sessionLog.push(record);
  }

  const fb = document.getElementById("feedbackBox");
  fb.classList.remove("hidden", "correct", "incorrect", "neutral");

  if (userDecision === "PREFER_NOT_TO_ANSWER") {
    fb.classList.add("neutral");
    fb.innerHTML = `
      <strong>Response Recorded (Skipped)</strong><br/>
      <strong>Ground Truth:</strong> ${actualLabel} &mdash; ${OUTCOME_DESCRIPTIONS[trial.alert_type] || trial.alert_type}
    `;
  } else if (isCorrect) {
    fb.classList.add("correct");
    fb.innerHTML = `
      <strong>Correct Triage Assessment (${actualLabel})</strong><br/>
      <strong>Detector Outcome Context:</strong> ${OUTCOME_DESCRIPTIONS[trial.alert_type] || trial.alert_type}<br/>
      <strong>Selection Reason:</strong> ${trial.selection_reason} | <strong>Response Time:</strong> ${responseTimeSec}s
    `;
  } else {
    fb.classList.add("incorrect");
    fb.innerHTML = `
      <strong>Calibration Mismatch &mdash; Ground Truth is ${actualLabel}</strong><br/>
      <strong>Detector Outcome Context:</strong> ${OUTCOME_DESCRIPTIONS[trial.alert_type] || trial.alert_type}<br/>
      <strong>Tip:</strong> Cross-check today's feature values against the Global SHAP Beeswarm and baseline counts to distinguish routine role variance from true insider activity.
    `;
  }

  updateAccuracyBadge();
}

function exportSessionCsv() {
  if (!sessionLog.length) {
    alert("No completed trials to export yet.");
    return;
  }
  const headers = Object.keys(sessionLog[0]);
  const rows = [
    headers.join(","),
    ...sessionLog.map((row) =>
      headers.map((h) => `"${String(row[h] ?? "").replace(/"/g, '""')}"`).join(",")
    )
  ];
  const blob = new Blob([rows.join("\n")], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  const pid = document.getElementById("participantId").value.trim() || "session";
  a.download = `soc_xai_training_${pid}_${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

function openZoom(imgElementId) {
  const src = document.getElementById(imgElementId).src;
  if (!src) return;
  document.getElementById("lightboxImg").src = src;
  document.getElementById("lightbox").classList.remove("hidden");
}

function closeZoom() {
  document.getElementById("lightbox").classList.add("hidden");
}

document.addEventListener("DOMContentLoaded", async () => {
  await loadManifest();

  document.getElementById("startBtn").addEventListener("click", () => {
    if (!allTrials.length) return;
    document.getElementById("introCard").classList.add("hidden");
    document.getElementById("workspace").classList.remove("hidden");
    updateLayoutMode();
    renderTrial();
  });

  document.getElementById("designSelect").addEventListener("change", updateLayoutMode);

  document.getElementById("scenarioFilter").addEventListener("change", (e) => {
    const val = e.target.value;
    filteredTrials = val === "ALL" ? [...allTrials] : allTrials.filter((t) => t.scenario === val);
    currentIndex = 0;
    renderTrial();
  });

  document.getElementById("toggleBeeswarmBtn").addEventListener("click", (e) => {
    const panel = document.getElementById("beeswarmPanel");
    const isHidden = panel.classList.toggle("hidden");
    if (!isHidden) beeswarmOpenedCount++;
    e.target.textContent = isHidden ? "Show User Global Beeswarm" : "Hide User Global Beeswarm";
  });

  document.getElementById("confidenceRange").addEventListener("input", (e) => {
    document.getElementById("confidenceVal").textContent = `${e.target.value}%`;
  });

  document.getElementById("submitDecisionBtn").addEventListener("click", submitDecision);

  document.getElementById("prevBtn").addEventListener("click", () => {
    if (currentIndex > 0) {
      currentIndex--;
      renderTrial();
    }
  });

  document.getElementById("nextBtn").addEventListener("click", () => {
    if (currentIndex < filteredTrials.length - 1) {
      currentIndex++;
      renderTrial();
    } else {
      alert("You have reached the end of the selected training cases. Click 'Export Session Log (CSV)' to save your results.");
    }
  });

  document.getElementById("exportCsvBtn").addEventListener("click", exportSessionCsv);
  document.getElementById("imgA").addEventListener("click", () => openZoom("imgA"));
  document.getElementById("imgB").addEventListener("click", () => openZoom("imgB"));
  document.getElementById("imgBeeswarm").addEventListener("click", () => openZoom("imgBeeswarm"));
});
