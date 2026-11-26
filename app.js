let allTrials = [];
let filteredTrials = [];
let currentIndex = 0;
let trialStartTime = Date.now();
let beeswarmOpenedCount = 0;
let playbookTabClicks = 0;
const sessionLog = [];

const OUTCOME_DESCRIPTIONS = {
  TP: "True Positive (TP): Actual insider threat day accurately flagged above the MAD anomaly threshold.",
  FP: "False Positive (FP): Benign anomaly / normal workday flagged above the MAD threshold due to non-malicious activity variance.",
  FN: "False Negative (FN): Actual insider threat day whose reconstruction error fell below the MAD threshold.",
  TN: "True Negative (TN): Normal benign workday accurately below the MAD anomaly threshold."
};

const SCENARIO_PLAYBOOK = {
  S1: {
    title: "Scenario 1: WikiLeaks Exfiltration",
    tagClass: "threat",
    tagLabel: "Insider Threat — S1",
    description:
      "A user who did not previously use removable drives or work after hours suddenly begins logging in after hours, using a removable thumb drive, and uploading sensitive data to <code>wikileaks.org</code>, leaving the organization shortly thereafter.",
    primary: [
      "<strong>WikiLeaks Access Count</strong> (<code>val &ge; 1</code>, zero baseline)",
      "<strong>Thumb Drive / Removable Media Usage</strong>"
    ],
    secondary: [
      "After-hours activity (Evening / Night / Weekend)",
      "<strong>Sudden Departure Flag</strong>"
    ]
  },
  S2: {
    title: "Scenario 2: Pre-Departure IP Theft",
    tagClass: "threat",
    tagLabel: "Insider Threat — S2",
    description:
      "A user begins surfing external job websites and soliciting employment from a competitor. Before leaving the company, they use a thumb drive at markedly higher rates than their baseline to steal proprietary data.",
    primary: [
      "<strong>Thumb Drive Usage Count</strong> (sharp spike above baseline)",
      "<strong>Job Site Access / Competitor Email Count</strong>"
    ],
    secondary: [
      "<strong>Sudden Departure Flag</strong>",
      "Elevated <code>File</code> / <code>Http</code> activity transitions"
    ]
  },
  S3: {
    title: "Scenario 3: Keylogger & Sabotage",
    tagClass: "threat",
    tagLabel: "Insider Threat — S3",
    description:
      "A disgruntled system administrator downloads a keylogger and uses a thumb drive to transfer it to their supervisor's machine. The next day, they use the collected credentials to log in as the supervisor and send out an alarming mass email causing organization-wide panic before leaving immediately.",
    primary: [
      "<strong>Keylogger Download Count</strong>",
      "<strong>Mass Email Count</strong> (&ge; 5 recipients)"
    ],
    secondary: [
      "<strong>Thumb Drive Usage Count</strong> (transferring keylogger)",
      "<strong>Unauthorized / Suspicious PC Login</strong>",
      "<strong>Sudden Departure Flag</strong>"
    ]
  },
  S4: {
    title: "Scenario 4: Lateral Snooping & Home Email",
    tagClass: "threat",
    tagLabel: "Insider Threat — S4",
    description:
      "A user repeatedly logs into another user's workstation, searches for interesting or confidential files, and emails them to their personal home email address (Gmail, Yahoo, Hotmail), with frequency escalating over time.",
    primary: [
      "<strong>Unauthorized / Non-Primary PC Login</strong>",
      "<strong>Home Email Count</strong>"
    ],
    secondary: [
      "<strong>File Search / Decoy File Access Count</strong>",
      "<code>Http &rarr; File</code> or <code>File &rarr; Http</code> transitions"
    ]
  },
  MIXED: {
    title: "Mixed Mode: Multi-Vector Attack",
    tagClass: "mixed",
    tagLabel: "Compound Threat — Mixed",
    description:
      "A compound threat profile in which a user exhibits behavioral indicators spanning <strong>two or more</strong> distinct insider scenarios within the same observation window (e.g., unauthorized PC snooping + home email exfiltration combined with WikiLeaks uploads or job-search USB theft).",
    primary: [
      "Two or more primary threat indicators active simultaneously (e.g., <strong>WikiLeaks + Home Email</strong> or <strong>Unauthorized Login + Thumb Drive</strong>)"
    ],
    secondary: [
      "Multi-channel spikes across <code>email</code>, <code>http</code>, <code>file</code>, and after-hours timing"
    ]
  },
  BENIGN: {
    title: "Benign Anomaly: Non-Malicious Outlier",
    tagClass: "benign",
    tagLabel: "Non-Malicious — Benign",
    description:
      "A legitimate employee whose daily reconstruction score crosses the MAD threshold due to an unusual but benign workload surge (deadline crunch, heavy email volume, atypical meeting gaps, or routine authorized USB use) with <strong>no</strong> malicious exfiltration or unauthorized access.",
    primary: [
      "<strong>Routine Workload / Timing Spike</strong> (<code>Morning</code>/<code>Afternoon</code> count, inter-activity time, or <code>Logon &rarr; Email</code>)"
    ],
    secondary: [
      "Occasional authorized <code>Thumb Drive</code> or <code>Weekend</code> work without WikiLeaks, keyloggers, decoy files, or unauthorized logins"
    ]
  }
};

function renderPlaybookTab(tabKey) {
  const item = SCENARIO_PLAYBOOK[tabKey] || SCENARIO_PLAYBOOK.S1;
  document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.tab === tabKey);
  });

  const box = document.getElementById("tabDetailBox");
  box.innerHTML = `
    <div class="tab-col">
      <h4>${item.title} <span class="tag ${item.tagClass}" style="margin-left:6px;">${item.tagLabel}</span></h4>
      <p>${item.description}</p>
    </div>
    <div class="tab-col">
      <h4>Primary Indicators (Strongest Drivers)</h4>
      <ul>${item.primary.map((p) => `<li>${p}</li>`).join("")}</ul>
    </div>
    <div class="tab-col">
      <h4>Secondary / Co-Occurring Indicators</h4>
      <ul>${item.secondary.map((s) => `<li>${s}</li>`).join("")}</ul>
    </div>
  `;
}

function populateFullMatrixTable() {
  const tbody = document.getElementById("fullMatrixBody");
  tbody.innerHTML = Object.values(SCENARIO_PLAYBOOK)
    .map(
      (item) => `
      <tr>
        <td><strong>${item.title}</strong><br/><span class="tag ${item.tagClass}">${item.tagLabel}</span></td>
        <td>${item.description}</td>
        <td><ul>${item.primary.map((p) => `<li>${p}</li>`).join("")}</ul></td>
        <td><ul>${item.secondary.map((s) => `<li>${s}</li>`).join("")}</ul></td>
      </tr>
    `
    )
    .join("");
}

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
    populateDateJumpDropdown();
  } catch (err) {
    alert(
      "Could not load ./data/testing_manifest.json. Ensure testing_manifest.json, beeswarms/, and testing/ folders are placed inside /data/."
    );
    console.error(err);
  }
}

function populateDateJumpDropdown() {
  const sel = document.getElementById("dateJumpSelect");
  if (!filteredTrials.length) {
    sel.innerHTML = `<option value="">No matching days</option>`;
    return;
  }
  sel.innerHTML = filteredTrials
    .map(
      (t, idx) =>
        `<option value="${idx}">${t.date} [${t.scenario} | ${t.alert_type} | ${Number(t.anomaly_score).toFixed(4)}]</option>`
    )
    .join("");
}

function applyFilters() {
  const scenVal = document.getElementById("scenarioFilter").value;
  const outVal = document.getElementById("outcomeFilter").value;

  filteredTrials = allTrials.filter((t) => {
    const matchScen = scenVal === "ALL" || t.scenario === scenVal;
    let matchOut = true;
    if (outVal === "FLAGGED") matchOut = t.alert_type === "TP" || t.alert_type === "FP";
    else if (outVal === "THREATS") matchOut = t.alert_type === "TP" || t.alert_type === "FN";
    else if (outVal !== "ALL") matchOut = t.alert_type === outVal;
    return matchScen && matchOut;
  });

  currentIndex = 0;
  populateDateJumpDropdown();

  if (!filteredTrials.length) {
    alert(`No days matched User/Scenario='${scenVal}' and Day Filter='${outVal}'.`);
    return;
  }
  renderTrial();
}

function renderUserTimeline(activeTrial) {
  const container = document.getElementById("timelineContainer");
  const userDays = allTrials
    .filter((t) => t.cert_id === activeTrial.cert_id)
    .sort((a, b) => a.date.localeCompare(b.date));

  if (!userDays.length) return;
  document.getElementById("timelineTitle").textContent =
    `Full Timeline: ${activeTrial.scenario} (${activeTrial.cert_id}) — ${userDays.length} Total Test Days (Click Any Dot to Inspect Day)`;

  const width = Math.max(920, userDays.length * 4.2);
  const height = 135;
  const pad = 22;
  const thresh = Number(activeTrial.threshold);
  const maxScore = Math.max(thresh * 1.35, ...userDays.map((d) => Number(d.anomaly_score)));

  const xScale = (i) => pad + (i / Math.max(userDays.length - 1, 1)) * (width - 2 * pad);
  const yScale = (s) => height - pad - (s / (maxScore || 1)) * (height - 2 * pad);

  const linePoints = userDays
    .map((d, i) => `${xScale(i).toFixed(1)},${yScale(Number(d.anomaly_score)).toFixed(1)}`)
    .join(" ");
  const threshY = yScale(thresh).toFixed(1);

  const circles = userDays
    .map((d, i) => {
      const cx = xScale(i).toFixed(1);
      const cy = yScale(Number(d.anomaly_score)).toFixed(1);
      const isSelected = d.trial_id === activeTrial.trial_id;
      let fill = "#3b82f6";
      if (d.alert_type === "TP" || d.alert_type === "FN") fill = "#ef4444";
      else if (d.alert_type === "FP") fill = "#f59e0b";

      const r = isSelected ? 6 : d.alert_type === "TN" ? 2.6 : 4.5;
      const stroke = isSelected ? 'stroke="#ffffff" stroke-width="2"' : "";
      return `<circle cx="${cx}" cy="${cy}" r="${r}" fill="${fill}" ${stroke} style="cursor:pointer"
                onclick="jumpToTrialId('${d.trial_id}')">
                <title>${d.date} (${d.day_of_week}) | ${d.alert_type} | Score: ${Number(d.anomaly_score).toFixed(5)}</title>
              </circle>`;
    })
    .join("");

  container.innerHTML = `
    <svg width="${width}" height="${height}" style="background:#0f172a; border-radius:6px; display:block;">
      <line x1="${pad}" y1="${threshY}" x2="${width - pad}" y2="${threshY}" stroke="#10b981" stroke-dasharray="5,4" stroke-width="1.5" />
      <polyline fill="none" stroke="#64748b" stroke-width="1.2" points="${linePoints}" />
      ${circles}
    </svg>
  `;
}

function jumpToTrialId(trialId) {
  let idx = filteredTrials.findIndex((t) => t.trial_id === trialId);
  if (idx === -1) {
    document.getElementById("outcomeFilter").value = "ALL";
    applyFilters();
    idx = filteredTrials.findIndex((t) => t.trial_id === trialId);
  }
  if (idx >= 0) {
    currentIndex = idx;
    renderTrial();
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
  playbookTabClicks = 0;

  document.getElementById("dateJumpSelect").value = String(currentIndex);
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

  renderUserTimeline(trial);

  // Reset form inputs
  document.querySelectorAll('input[name="decision"]').forEach((r) => (r.checked = false));
  document.getElementById("scenarioHypothesis").value = "";
  document.getElementById("primaryCue").value = "";
  document.querySelectorAll('input[name="secondaryCue"]').forEach((cb) => (cb.checked = false));
  document.getElementById("confidenceRange").value = 50;
  document.getElementById("confidenceVal").textContent = "50%";

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
    alert("Please select a triage classification decision (or 'Prefer not to answer') before submitting.");
    return;
  }

  const userDecision = selectedRadio.value;
  const scenarioHypothesis = document.getElementById("scenarioHypothesis").value || "unspecified";
  const primaryCue = document.getElementById("primaryCue").value || "unspecified";
  const secondaryCuesList = Array.from(document.querySelectorAll('input[name="secondaryCue"]:checked')).map(
    (cb) => cb.value
  );
  const secondaryCuesStr = secondaryCuesList.length ? secondaryCuesList.join(";") : "none";
  const confidence = Number(document.getElementById("confidenceRange").value);
  const responseTimeSec = Number(((Date.now() - trialStartTime) / 1000).toFixed(2));

  const actualLabel = trial.alert_type === "TP" || trial.alert_type === "FN" ? "THREAT" : "BENIGN";
  const isCorrect = userDecision === actualLabel;

  const existingIdx = sessionLog.findIndex((item) => item.trial_id === trial.trial_id);
  const record = {
    participant_id: document.getElementById("participantId").value.trim() || "ANON",
    timestamp_iso: new Date().toISOString(),
    view_mode: document.getElementById("designSelect").value,
    beeswarm_inspected_count: beeswarmOpenedCount,
    playbook_tab_clicks: playbookTabClicks,
    trial_id: trial.trial_id,
    true_scenario: trial.scenario,
    cert_id: trial.cert_id,
    date: trial.date,
    model_outcome_type: trial.alert_type,
    actual_ground_truth: actualLabel,
    user_decision: userDecision,
    scenario_hypothesis: scenarioHypothesis,
    is_correct: userDecision === "PREFER_NOT_TO_ANSWER" ? "" : isCorrect,
    confidence_pct: confidence,
    primary_cue: primaryCue,
    secondary_cues: secondaryCuesStr,
    secondary_cue_count: secondaryCuesList.length,
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

  const scenInfo = SCENARIO_PLAYBOOK[trial.scenario];
  const scenGuide = scenInfo ? `${scenInfo.title}: ${scenInfo.description}` : "";

  if (userDecision === "PREFER_NOT_TO_ANSWER") {
    fb.classList.add("neutral");
    fb.innerHTML = `
      <strong>Response Recorded (Skipped)</strong><br/>
      <strong>Ground Truth:</strong> ${actualLabel} (${trial.scenario}) &mdash; ${OUTCOME_DESCRIPTIONS[trial.alert_type] || trial.alert_type}<br/>
      <strong>Scenario Signature:</strong> ${scenGuide}
    `;
  } else if (isCorrect) {
    fb.classList.add("correct");
    fb.innerHTML = `
      <strong>Correct Triage Assessment (${actualLabel})</strong><br/>
      <strong>Detector Outcome Context:</strong> ${OUTCOME_DESCRIPTIONS[trial.alert_type] || trial.alert_type}<br/>
      <strong>Scenario Signature:</strong> ${scenGuide}<br/>
      <strong>Logged Indicators:</strong> Primary = <code>${primaryCue}</code> | Secondary = <code>${secondaryCuesStr}</code> | Response Time = ${responseTimeSec}s
    `;
  } else {
    fb.classList.add("incorrect");
    fb.innerHTML = `
      <strong>Calibration Mismatch &mdash; Ground Truth is ${actualLabel} (${trial.scenario})</strong><br/>
      <strong>Detector Outcome Context:</strong> ${OUTCOME_DESCRIPTIONS[trial.alert_type] || trial.alert_type}<br/>
      <strong>Scenario Signature:</strong> ${scenGuide}<br/>
      <strong>Tip:</strong> Switch between the scenario tabs below to compare primary malicious indicators against secondary workload/timing cues.
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
  renderPlaybookTab("S1");
  populateFullMatrixTable();

  document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      playbookTabClicks++;
      renderPlaybookTab(btn.dataset.tab);
    });
  });

  document.getElementById("toggleFullMatrixBtn").addEventListener("click", (e) => {
    const matrixBox = document.getElementById("fullMatrixBox");
    const isHidden = matrixBox.classList.toggle("hidden");
    e.target.textContent = isHidden ? "View All 6 Side-by-Side" : "Hide Full Table";
  });

  document.getElementById("startBtn").addEventListener("click", () => {
    if (!allTrials.length) return;
    document.getElementById("introCard").classList.add("hidden");
    document.getElementById("workspace").classList.remove("hidden");
    updateLayoutMode();
    renderTrial();
  });

  document.getElementById("designSelect").addEventListener("change", updateLayoutMode);
  document.getElementById("scenarioFilter").addEventListener("change", applyFilters);
  document.getElementById("outcomeFilter").addEventListener("change", applyFilters);

  document.getElementById("dateJumpSelect").addEventListener("change", (e) => {
    const idx = Number(e.target.value);
    if (!Number.isNaN(idx) && idx >= 0 && idx < filteredTrials.length) {
      currentIndex = idx;
      renderTrial();
    }
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
      alert("You have reached the end of the selected cases. Click 'Export CSV' to save your session log.");
    }
  });

  document.getElementById("exportCsvBtn").addEventListener("click", exportSessionCsv);
  document.getElementById("imgA").addEventListener("click", () => openZoom("imgA"));
  document.getElementById("imgB").addEventListener("click", () => openZoom("imgB"));
  document.getElementById("imgBeeswarm").addEventListener("click", () => openZoom("imgBeeswarm"));
});
