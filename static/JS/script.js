

// Stricter IPv4 and basic IPv6 format validation

function isValidIP(ip) {
  const ipv4 = /^(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3}$/;
  const ipv6 = /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|::1)$/;
  return ipv4.test(ip) || ipv6.test(ip);
}

// Check if IP is private/reserved (basic IPv4 only)
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

// Improved URL validation to avoid malformed IPs or short strings
function isValidURL(str) {
  try {
    const url = new URL(str.startsWith("http") ? str : `http://${str}`);
    const hostname = url.hostname;

    // Reject malformed or incomplete IP-like hostnames (e.g. "12.23.4")
    if (/^\d{1,3}(\.\d{1,3}){1,2}$/.test(hostname)) return false;

    // Require at least one dot and valid TLD-like pattern
    if (!hostname.includes(".") || !/[a-zA-Z]{2,}$/.test(hostname.split(".").pop())) return false;

    return true;
  } catch {
    return false;
  }
}



// Main fetch function
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
  const clientName ="test"
  //const clientName = document.getElementById("clientName").value.trim();

  // 1️⃣ Must be here — before any splitting or fetch:
  if (!clientName) {
   // errorMsg.textContent = "⚠️ Client name is required to perform the lookup.";
    clientName ="test"
    return;
  }

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
  const skippedInvalid = [];
  const duplicates = [];

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
    } else {
      skippedInvalid.push(entry);
    }
  }

  let validEntries = [...validIPs, ...validURLs];
  const messages = [];


  if (validEntries.length === 0) {
    errorMsg.textContent = "⚠️ No valid public IPs or URLs found.";
    errorMsg.classList.remove("hidden");
    return;
  }
  if (skippedInvalid.length > 0) {
    messages.push(`⚠️ <span class="text-red-400 font-bold glow-red">${skippedInvalid.length} Invalid entr${skippedInvalid.length!== 1 ? 'ies' : 'y'} skipped</span> : ${skippedInvalid.join(", ")}`);
  }

  if (duplicates.length > 0) {
    messages.push(`⚠️ <span class="text-red-400 font-bold glow-red">${duplicates.length} Duplicate${duplicates.length!== 1 ? 's' : ''} removed</span>: ${duplicates.join(", ")}`);
  }

  const privateIPs = rawEntries.filter(ip => isValidIP(ip) && isPrivateIP(ip));
  if (privateIPs.length > 0) {
    messages.push(`⚠️ <span class="text-red-400 font-bold glow-red">${privateIPs.length} Private/reserved IP${privateIPs.length!== 1 ? 's' : ''} filtered </span>: ${privateIPs.join(", ")}`);
  }

  if (validEntries.length > 100) {
    messages.push(`⚠️ You entered <span class="text-green-400 font-bold">${validEntries.length}</span> valid entries</span>. Only the first 100 will be processed.`);
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
        client_name: clientName || "N/A"
      })
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(error.error || "Server error occurred.");
    }

    const data = await response.json();
    const processedCount = data.raw_table?.length || 0;

    // Grab the raw summary

// Now write the (possibly modified) summaryText to the page
summaryDiv.innerHTML = data.summary;

    if (Array.isArray(data.no_data_ips) && data.no_data_ips.length > 0) {
      const displayList = data.no_data_ips.slice(0, 5).join(", ");
      const more = data.no_data_ips.length > 5 ? ` and ${data.no_data_ips.length - 5} more...` : "";
      messages.push(`⚠️ ${data.no_data_ips.length} entr${data.no_data_ips.length !== 1 ? 'ies' : 'y'} returned no fields: ${displayList}${more}`);
    }
    // ─ after  `const data = await response.json();`
  const count   = data.raw_table?.length || 0;
  const elapsed = data.elapsed;   // now coming from backend
  // Prepare both messages first

  const entryMsg = `✅ Data found for <span class="text-green-400 font-bold">${processedCount} entr${processedCount !== 1 ? 'ies' : 'y'} </span> in <span class="text-blue-400 font-bold">${data.elapsed} second${data.elapsed !== 1 ? 's' : ''}</span>.`;
  const serviceList = Array.isArray(data.services_used) ? data.services_used : [];
  const serviceMsg = `🔧 Service${serviceList.length !== 1 ? 's' : ''} used: <span class="text-purple-400 font-bold">${serviceList.join(", ") || "None"}</span>`;

  // Unshift them in reverse order so they appear in the correct visual order
  messages.unshift(serviceMsg);
  messages.unshift(entryMsg);
    // … after you've done:
// const data = await response.json();

   const tableHead = document.getElementById("tableHead");
    tableHead.innerHTML = "";
    const headerRow = document.createElement("tr");

    let headerTitles = [];
    let useResolvedIP = false;

if (data.column_label === "URL") {
  // Only URLs provided
  headerTitles = ["URL", "Resolved IP", "ISP", "Country", "Detections","Client Name"];
  useResolvedIP = true;
} else if (data.column_label === "IP") {
  // Only IPs provided
  headerTitles = ["IP", "ISP", "Country", "Detections","Client Name"];
  useResolvedIP = false;
} else {
  // Mixed IPs + URLs
  headerTitles = ["IP/URL", "Resolved IP", "ISP", "Country", "Detections","Client Name"];
  useResolvedIP = true;
}

   for (const title of headerTitles) {
      const th = document.createElement("th");
      th.innerText = title;
      th.className = "border px-3 py-2 text-center";
      headerRow.appendChild(th);
    }
    tableHead.appendChild(headerRow);

        tableBody.innerHTML = "";
      for (const row of data.raw_table || []) {
        const [inputValue, resolvedIP, isp, country, detections] = row;

      let cells = [];

      if (data.column_label === "IP") {
        // Only IPs → no Resolved IP column
        cells = [inputValue, isp, country, detections,clientName];
      } else if (data.column_label === "URL") {
        // Only URLs → show Resolved IP
        cells = [inputValue, resolvedIP || "-", isp, country, detections,clientName];
      } else {
        // Mixed input → if resolvedIP is different, it's a URL
        const isURL = resolvedIP && resolvedIP !== "-" && resolvedIP !== inputValue;
        if (isURL) {
          cells = [inputValue, resolvedIP, isp, country, detections,clientName];
        } else {
          cells = [inputValue, "-", isp, country, detections,clientName];
        }
      }

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
    // New: clear and build each line so tags are parsed
  // 1) Clear out old messages
// 1. Clear out old content
// clear out old content
console.log("Final messages array:", messages);

messageDiv.innerHTML = messages
  .map(m => `<div class="font-medium mb-3">${m}</div>`)
  .join("");

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
const clientName = document.getElementById("clientName").value.trim();

  fetch("/download_excel", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      table_data: window._latestTable || [],
      summary: window._latestSummary || "",
      column_label: window._columnLabel || "IP",
      client_name: clientName || "N/A"
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
