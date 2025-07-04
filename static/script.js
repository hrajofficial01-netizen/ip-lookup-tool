function isValidIP(ip) {
  const ipv4 = /^\b(\d{1,3}\.){3}\d{1,3}\b$/;
  const ipv6 = /^[0-9a-fA-F:]+$/;
  return ipv4.test(ip) || ipv6.test(ip);
}

function isPrivateIP(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return false;
  const [a, b] = parts.map(Number);
  return (
    a === 10 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    a === 127 ||
    (a === 169 && b === 254)
  );
}

const privateIPs = ipList.filter(ip => isPrivateIP(ip));
if (privateIPs.length > 0) {
  alert(`⚠️ Private IPs will be skipped:\n${privateIPs.join(", ")}`);
}


async function fetchIPData() {
  const inputField = document.getElementById('ipInput');
  const lookupButton = document.getElementById('lookupButton');
  const summaryDiv = document.getElementById('summary');
  const tableBody = document.getElementById('tableBody');
  const downloadBtn = document.getElementById('downloadExcelBtn');
  const summarySection = document.getElementById('summarySection');
  const tableSection = document.getElementById('tableSection');

  const input = inputField.value;
  const ipList = input
    .split(/[\s,\n]+/)
    .map(ip => ip.trim())
    .filter(ip => ip.length > 0);

  if (ipList.length === 0) {
    alert("Please enter at least one valid IP address.");
    return;
  }

  if (ipList.length > 50) {
    alert("⚠️ Please enter no more than 50 IP addresses at a time.");
    return;
  }

  lookupButton.disabled = true;
  lookupButton.textContent = "Fetching...";

  try {
    const response = await fetch("/get_ip_info", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ ips: ipList })
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || "Server error occurred.");
    }

    const data = await response.json();

    summaryDiv.innerText = data.summary;
    summarySection.classList.remove("hidden");

    tableBody.innerHTML = data.table;
    tableSection.classList.remove("hidden");

    window._latestSummary = data.summary;
    window._latestTable = data.raw_table;

    downloadBtn.style.display = "inline-block";
    downloadBtn.classList.remove("hidden");
  } catch (error) {
    console.error("Error:", error);
    alert("❌ Error retrieving IP info:\n" + error.message);
  } finally {
    lookupButton.disabled = false;
    lookupButton.textContent = "Get Info";
  }
}

function copyToClipboard(elementId, btnId) {
  const text = document.getElementById(elementId).innerText;
  navigator.clipboard.writeText(text).then(() => {
    const btn = document.getElementById(btnId);
    const original = btn.innerHTML;
    btn.innerHTML = '<i class="ph ph-check"></i> Copied!';
    setTimeout(() => btn.innerHTML = original, 1500);
  });
}

function copyTableToClipboard(btnId) {
  const headers = [...document.querySelectorAll('#tableSection thead th')]
    .map(th => th.innerText.trim())
    .join('\t');

  const rows = [...document.querySelectorAll('#tableBody tr')].map(row => {
    const cells = [...row.children].map((cell, i) => {
      let text = cell.innerText.trim();
      if (i === 3) text = `"${text}"`; // detection count
      return text;
    });
    return cells.join('\t');
  });

  const text = [headers, ...rows].join('\n');

  navigator.clipboard.writeText(text).then(() => {
    const btn = document.getElementById(btnId);
    const original = btn.innerHTML;
    btn.innerHTML = '<i class="ph ph-check"></i> Copied!';
    setTimeout(() => btn.innerHTML = original, 1500);
  });
}

function downloadExcel() {
  fetch('/download_excel', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      table_data: window._latestTable || [],
      summary: window._latestSummary || ''
    })
  })
    .then(resp => resp.blob())
    .then(blob => {
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'IP_Info.xlsx';
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);

      const btn = document.getElementById('downloadExcelBtn');
      btn.textContent = 'Downloaded';
      btn.classList.add('downloaded');
      btn.disabled = true;

      setTimeout(() => {
        btn.innerHTML = '<i class="ph ph-download-simple"></i> Export to Excel';
        btn.classList.remove('downloaded');
        btn.disabled = false;
      }, 5000);
    })
    .catch(error => {
      console.error('Download failed:', error);
      alert('Download failed. Please try again.');
    });
}

function resetTool() {
  document.getElementById('ipInput').value = '';
  document.getElementById('errorMsg').classList.add('hidden');
  document.getElementById('summarySection').classList.add('hidden');
  document.getElementById('summary').innerHTML = '';
  document.getElementById('tableSection').classList.add('hidden');
  document.getElementById('tableBody').innerHTML = '';

  const downloadBtn = document.getElementById('downloadExcelBtn');
  downloadBtn.classList.add('hidden');
  downloadBtn.textContent = 'Export to Excel';
  downloadBtn.classList.remove('downloaded');
  downloadBtn.disabled = false;

  window._latestSummary = '';
  window._latestTable = [];
}
