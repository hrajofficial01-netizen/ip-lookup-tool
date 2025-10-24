function isValidIP(ip) {
  try {
    return ipaddr.isValid(ip);
  } catch {
    return false;
  }
}

function isValidHash(str) {
  const s = str.toLowerCase();
  return /^[a-f0-9]{32}$/.test(s) || // MD5
         /^[a-f0-9]{40}$/.test(s) || // SHA1
         /^[a-f0-9]{64}$/.test(s);   // SHA256
}


function isPrivateIP(ip) {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some(isNaN)) return false;
  const [a, b] = parts;
  return (
    a === 10 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    a === 127 ||
    (a === 169 && b === 254) ||
    (a === 100 && b >= 64 && b <= 127)
  );
}

function isValidURL(str) {
  try {
    const url = new URL(str.startsWith("http") ? str : `http://${str}`);
    const hostname = url.hostname;
    if (/^\d{1,3}(\.\d{1,3}){1,2}$/.test(hostname)) return false;
    if (!hostname.includes(".") || !/[a-zA-Z]{2,}$/.test(hostname.split(".").pop())) return false;
    return true;
  } catch {
    return false;
  }
}

async function fetchIPData() {
  const inputField = document.getElementById("ipInput");
  const lookupButton = document.getElementById("lookupButton");
  const summaryDiv = document.getElementById("summary");
  const tableBody = document.getElementById("tableBody");
  const summarySection = document.getElementById("summarySection");
  const tableSection = document.getElementById("tableSection");
  const errorMsg = document.getElementById("errorMsg");
  const messageDiv = document.getElementById("message");
  const messageBlock = document.getElementById("messageBlock");
  const downloadBtn = document.getElementById("downloadExcelBtn");

  errorMsg.classList.add("hidden");
  summarySection.classList.add("hidden");
  tableSection.classList.add("hidden");
  summaryDiv.textContent = "";
  tableBody.innerHTML = "";
  downloadBtn.style.display = "none";
  messageDiv.innerHTML = "";
  messageBlock.classList.remove("show", "hidden");

  let rawEntries = inputField.value
    .split(/[\s,\n]+/)
    .map(e => e.trim())
    .filter(e => e.length > 0);

  const seen = new Set();
  const validIPs = [];
  const validURLs = [];
  const validHashes = [];
  const skippedInvalid = [];
  const duplicates = [];

  function isValidHash(str) {
    const s = str.toLowerCase();
    return /^[a-f0-9]{32}$/.test(s) || /^[a-f0-9]{40}$/.test(s) || /^[a-f0-9]{64}$/.test(s);
  }

  for (const entry of rawEntries) {
    if (seen.has(entry)) {
      duplicates.push(entry);
      continue;
    }
    seen.add(entry);
    if (isValidIP(entry)) {
      if (!isPrivateIP(entry)) validIPs.push(entry);
    } else if (isValidURL(entry)) {
      validURLs.push(entry);
    } else if (isValidHash(entry)) {
      validHashes.push(entry);
    } else {
      skippedInvalid.push(entry);
    }
  }

  let validEntries = [...validIPs, ...validURLs, ...validHashes];
  const messages = [];

  if (validEntries.length === 0) {
    errorMsg.textContent = "⚠️ No valid public IPs, URLs or Hashes found.";
    errorMsg.classList.remove("hidden");
    return;
  }
  if (skippedInvalid.length > 0) {
    messages.push(`⚠️ <span class="text-red-400 font-bold glow-red">${skippedInvalid.length} Invalid entr${skippedInvalid.length !== 1 ? 'ies' : 'y'} skipped</span> : ${skippedInvalid.join(", ")}`);
  }
  if (duplicates.length > 0) {
    messages.push(`⚠️ <span class="text-red-400 font-bold glow-red">${duplicates.length} Duplicate${duplicates.length !== 1 ? 's' : ''} removed</span>: ${duplicates.join(", ")}`);
  }

  const privateIPs = rawEntries.filter(ip => isValidIP(ip) && isPrivateIP(ip));
  if (privateIPs.length > 0) {
    messages.push(`⚠️ <span class="text-red-400 font-bold glow-red">${privateIPs.length} Private/reserved IP${privateIPs.length !== 1 ? 's' : ''} filtered </span>: ${privateIPs.join(", ")}`);
  }
  if (validEntries.length > 100) {
    messages.push(`⚠️ You entered <span class="text-green-400 font-bold">${validEntries.length}</span> valid entries. Only the first 100 will be processed.`);
    messages.push(`⚠️ <span class="text-purple-400 font-bold">${validEntries.length - 100} entries skipped</span>: ${validEntries.slice(100).join(", ")}`);
    validEntries = validEntries.slice(0, 100);
  }

  lookupButton.disabled = true;
  lookupButton.textContent = "Fetching...";

  try {
    const response = await fetch("/get_ip_info", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ips: validEntries,
      }),
    });
    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(error.error || "Server error occurred.");
    }
    const data = await response.json();

    const processedCount = data.raw_table?.length || 0;
    summaryDiv.innerHTML = data.summary;

    if (Array.isArray(data.exhausted_messages) && data.exhausted_messages.length > 0) {
      data.exhausted_messages.forEach(msg => {
        messages.push(`<div class="font-medium mb-3 text-red-600">${msg}</div>`);
      });
    }
    if (Array.isArray(data.no_data_ips) && data.no_data_ips.length > 0) {
      const displayList = data.no_data_ips.slice(0, 5).join(", ");
      const more = data.no_data_ips.length > 5 ? ` and ${data.no_data_ips.length - 5} more...` : "";
      messages.push(`⚠️ ${data.no_data_ips.length} entr${data.no_data_ips.length !== 1 ? 'ies' : 'y'} returned no fields: ${displayList}${more}`);
    }

    const entryMsg = `✅ Data found for <span class="text-green-400 font-bold">${processedCount} entr${processedCount !== 1 ? 'ies' : 'y'} </span> in <span class="text-blue-400 font-bold">${data.elapsed} second${data.elapsed !== 1 ? 's' : ''}</span>.`;
    const serviceList = Array.isArray(data.services_used) ? data.services_used : [];
    const serviceMsg = `🔧 Service${serviceList.length !== 1 ? 's' : ''} used: <span class="text-purple-400 font-bold">${serviceList.join(", ") || "None"}</span>`;

    messages.unshift(serviceMsg);
    messages.unshift(entryMsg);

    const tableHead = document.getElementById("tableHead");
    tableHead.innerHTML = "";
    const headerRow = document.createElement("tr");

    let headerTitles = [
    "IP/URL/HASH", "ISP", "Country", "Detections",
    "APIVoid Risk Score", "APIVoid Blacklist Detections",
    "AbuseIPDB Confidence Score(%)", "AbuseIPDB Report Count",
    "Threat Actor", "Country Of Origin", "Target Sector",
    "Threat Category", "Campaign Name", "Malware Families"
  ];


    for (const title of headerTitles) {
      const th = document.createElement("th");
      th.innerText = title;
      th.className = "border px-3 py-2 text-center";
      headerRow.appendChild(th);
    }
    tableHead.appendChild(headerRow);

    tableBody.innerHTML = "";
    for (const row of data.raw_table || []) {
      const [
        inputValue,
        isp,
        country,
        detections,
        apivoidRiskScore,
        apivoidBlacklistDetections,
        abuseipdbConfidenceRaw,
        abuseipdbReportCountRaw,
        threatActorRaw,
        countryOriginRaw,
        targetSectorRaw,
        threatCategoryRaw,
        campaignNameRaw,
        malwareFamiliesRaw,
      ] = row;


      function formatField(field) {
        if (!field) return "-";
        if (Array.isArray(field)) return field.join(", ");
        return field.toString();
      }

      const threatActor = formatField(threatActorRaw);
      const campaignName = formatField(campaignNameRaw);
      const malwareFamilies = formatField(malwareFamiliesRaw);
      const countryOrigin = formatField(countryOriginRaw);
      const targetSector = formatField(targetSectorRaw);
      const threatCategory = formatField(threatCategoryRaw);
      const abuseipdbConfidence = formatField(abuseipdbConfidenceRaw);
      const abuseipdbReportCount = formatField(abuseipdbReportCountRaw);

      let cells = [
        inputValue, isp, country, detections,
        apivoidRiskScore || "-", apivoidBlacklistDetections || "-",
        formatField(abuseipdbConfidenceRaw), formatField(abuseipdbReportCountRaw),
        formatField(threatActorRaw), formatField(countryOriginRaw),
        formatField(targetSectorRaw), formatField(threatCategoryRaw),
        formatField(campaignNameRaw), formatField(malwareFamiliesRaw)
      ];


      const tr = document.createElement("tr");
      for (const cell of cells) {
        const td = document.createElement("td");
        td.innerText = cell;
        td.className = "border px-3 py-1 text-center";
        tr.appendChild(td);
      }
      tableBody.appendChild(tr);
    }

    summarySection.classList.remove("hidden");
    tableSection.classList.remove("hidden");
    messageBlock.style.display = "block";

    messageDiv.innerHTML = messages.map(m => `<div class="font-medium mb-3">${m}</div>`).join("");

    requestAnimationFrame(() => {
      summarySection.classList.add("show");
      tableSection.classList.add("show");
      messageBlock.classList.add("show");
    });

    downloadBtn.style.display = "inline-block";
    document.getElementById("resetContainer").classList.remove("hidden");

    window._latestSummary = data.summary;
    window._latestTable = data.raw_table;
    window._columnLabel = data.column_label || "IP";

  } catch (err) {
    console.error("Error:", err);
    alert("❌ Error retrieving data:\n" + err.message);
  } finally {
    lookupButton.disabled = false;
    lookupButton.textContent = "Get Info";
  }
}


// Remaining unrelated functions (copyToClipboard, downloadExcel, resetTool, etc.) remain unchanged.


// Copy summary to clipboard
function copyToClipboard(elementId, btnId) {
  const text = document.getElementById(elementId).innerHTML;
  navigator.clipboard.writeText(text).then(() => {
    const btn = document.getElementById(btnId);
    const original = btn.innerHTML;
    btn.innerHTML = '<i class="ph ph-check"></i> Copied!';
    setTimeout(() => (btn.innerHTML = original), 1500);
  });
}

// Copy table to clipboard
function copyTableToClipboard(btnId) {
  const headers = [...document.querySelectorAll("#tableSection thead th")]
    .map(th => th.innerText.trim()).join("\t");

  const rows = [...document.querySelectorAll("#tableBody tr")].map(row => {
    const cells = [...row.children].map((cell, i) => {
      let text = cell.innerText.trim();
      if (i === 3) text = `"${text}"`;
      return text;
    });
    return cells.join("\t");
  });

  const text = [headers, ...rows].join("\n");

  navigator.clipboard.writeText(text).then(() => {
    const btn = document.getElementById(btnId);
    const original = btn.innerHTML;
    btn.innerHTML = '<i class="ph ph-check"></i> Copied!';
    setTimeout(() => (btn.innerHTML = original), 1500);
  });
}

// Download Excel file
function downloadExcel() {
//const clientName = document.getElementById("clientName").value.trim();

  fetch("/download_excel", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      table_data: window._latestTable || [],
      summary: window._latestSummary || "",
      column_label: window._columnLabel || "IP",
      //client_name: clientName || "N/A"
    })
  })
  .then(resp => resp.blob())
  .then(blob => {
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "IP_Info.xlsx";
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);

    const btn = document.getElementById("downloadExcelBtn");
    btn.textContent = "Downloaded";
    btn.classList.add("downloaded");
    btn.disabled = true;

    setTimeout(() => {
      btn.innerHTML = '<i class="ph ph-download-simple"></i> Export to Excel';
      btn.classList.remove("downloaded");
      btn.disabled = false;
    }, 5000);
  })
  .catch(error => {
    console.error("Download failed:", error);
    alert("Download failed. Please try again.");
  });
}

// Reset tool
function resetTool() {
  document.getElementById("ipInput").value = "";
  document.getElementById("message").innerHTML = "";
  const messageBlock = document.getElementById("messageBlock");
  if (messageBlock) {
    messageBlock.classList.remove("show");
    messageBlock.classList.add("hidden");
    messageBlock.style.display = "none";
  }
  document.getElementById("errorMsg").classList.add("hidden");
  document.getElementById("summarySection").classList.add("hidden");
  document.getElementById("tableSection").classList.add("hidden");
  document.getElementById("summary").innerHTML = "";
  document.getElementById("tableBody").innerHTML = "";
  document.getElementById("downloadExcelBtn").style.display = "none";
  document.getElementById("resetContainer").classList.add("hidden");
}

// Theme toggle
const toggleThemeBtn = document.getElementById("toggleTheme");

window.addEventListener("DOMContentLoaded", () => {
  const savedTheme = localStorage.getItem("theme");
  if (savedTheme === "light") {
    document.body.classList.add("light-mode");
    toggleThemeBtn.innerHTML = '<i class="ph ph-moon"></i>';
  } else {
    document.body.classList.remove("light-mode");
    toggleThemeBtn.innerHTML = '<i class="ph ph-sun"></i>';
  }
});

toggleThemeBtn.addEventListener("click", () => {
  document.body.classList.toggle("light-mode");
  const isLight = document.body.classList.contains("light-mode");
  toggleThemeBtn.innerHTML = isLight
    ? '<i class="ph ph-moon"></i>'
    : '<i class="ph ph-sun"></i>';
  localStorage.setItem("theme", isLight ? "light" : "dark");
});
