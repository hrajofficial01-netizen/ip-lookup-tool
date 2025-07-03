function isValidIP(ip) {
  const ipv4 = /^\b(\d{1,3}\.){3}\d{1,3}\b$/;
  const ipv6 = /^[0-9a-fA-F:]+$/;
  return ipv4.test(ip) || ipv6.test(ip);
}
module.exports = {
  theme: {
    extend: {
      fontFamily: {
        sans: ['-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'Helvetica', 'Arial', 'sans-serif']
      }
    }
  }
}

async function fetchIPData() {
  const input = document.getElementById('ipInput').value;
  const ipList = input.split(/[\n,\s]+/).map(ip => ip.trim()).filter(ip => ip.length > 0);
  const validIps = ipList.filter(ip => isValidIP(ip));

  const errorMsg = document.getElementById('errorMsg');
  if (validIps.length === 0) {
    errorMsg.classList.remove('hidden');
    return;
  } else {
    errorMsg.classList.add('hidden');
  }

  document.getElementById('spinner').classList.remove('hidden');
  document.getElementById('summarySection').classList.add('hidden');
  document.getElementById('tableSection').classList.add('hidden');

  const response = await fetch('/get_ip_info', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ips: validIps })
  });

  const result = await response.json();
  document.getElementById('summary').textContent = result.summary;
  document.getElementById('tableBody').innerHTML = result.table;
  window._latestTable = result.raw_table;
window._latestSummary = result.summary;
document.getElementById('downloadExcelBtn').classList.remove('hidden');


  document.getElementById('spinner').classList.add('hidden');
  document.getElementById('summarySection').classList.remove('hidden');
  document.getElementById('tableSection').classList.remove('hidden');
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
      // Wrap detection count (last column) with quotes to prevent Excel date autoformat
      if (i === 3) text = `"${text}"`;
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
  });
}
