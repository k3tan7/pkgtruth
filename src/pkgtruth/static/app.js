'use strict';

// 1. Scan and upload form submission feedback
const form = document.querySelector('#scan-form');
if (form) {
  form.addEventListener('submit', () => {
    const submitBtn = document.querySelector('#submit-scan');
    const progressNotice = document.querySelector('#scan-progress');
    if (submitBtn) submitBtn.disabled = true;
    if (progressNotice) progressNotice.hidden = false;
    form.setAttribute('aria-busy', 'true');
  });
}

// 2. File Explorer Search and Filtering
const fileSearch = document.querySelector('#file-search');
const statusFilter = document.querySelector('#status-filter');

function filterFiles() {
  if (!fileSearch && !statusFilter) return;
  const query = (fileSearch ? fileSearch.value : '').toLowerCase().trim();
  const selectedStatus = statusFilter ? statusFilter.value : 'all';
  let count = 0;

  document.querySelectorAll('.file-entry').forEach(entry => {
    const path = entry.dataset.path || '';
    const status = entry.dataset.status || '';
    const matchesQuery = !query || path.includes(query);
    const matchesStatus = selectedStatus === 'all' || status === selectedStatus;
    const isVisible = matchesQuery && matchesStatus;

    entry.hidden = !isVisible;
    if (isVisible) count++;
  });

  const countDisplay = document.querySelector('#filter-count');
  if (countDisplay) {
    countDisplay.textContent = `${count} shown`;
  }
  const noMatchesNotice = document.querySelector('#no-matches');
  if (noMatchesNotice) {
    noMatchesNotice.hidden = count !== 0;
  }
}

if (fileSearch) fileSearch.addEventListener('input', filterFiles);
if (statusFilter) statusFilter.addEventListener('change', filterFiles);

// 3. Investigations Library Search / Filter
const invSearch = document.querySelector('#investigation-search');
if (invSearch) {
  invSearch.addEventListener('input', () => {
    const q = invSearch.value.toLowerCase().trim();
    let visibleCount = 0;
    document.querySelectorAll('.investigation-row').forEach(row => {
      const text = row.textContent.toLowerCase();
      const match = !q || text.includes(q);
      row.hidden = !match;
      if (match) visibleCount++;
    });
    const invCount = document.querySelector('#investigation-count');
    if (invCount) invCount.textContent = `${visibleCount} investigations`;
    const noInv = document.querySelector('#no-investigations');
    if (noInv) noInv.hidden = visibleCount !== 0;
  });
}

// 4. One-Click Copy to Clipboard with temporary confirmation
document.querySelectorAll('[data-copy]').forEach(button => {
  button.addEventListener('click', async () => {
    const textToCopy = button.dataset.copy;
    const originalText = button.textContent;
    try {
      await navigator.clipboard.writeText(textToCopy);
      button.textContent = 'Copied!';
      button.classList.add('copied');
      window.setTimeout(() => {
        button.textContent = originalText;
        button.classList.remove('copied');
      }, 2000);
    } catch {
      button.textContent = textToCopy;
    }
  });
});

// 5. Restore form state on bfcache pageshow
window.addEventListener('pageshow', () => {
  if (form) {
    const submitBtn = document.querySelector('#submit-scan');
    const progressNotice = document.querySelector('#scan-progress');
    if (submitBtn) submitBtn.disabled = false;
    if (progressNotice) progressNotice.hidden = true;
    form.removeAttribute('aria-busy');
  }
});

// 6. Transparent Job Status Polling for Asynchronous Analyses
const jobStatus = document.querySelector('#job-status');
if (jobStatus) {
  const poll = async () => {
    try {
      const response = await fetch(`/jobs/${jobStatus.dataset.jobId}/status`, { cache: 'no-store' });
      if (!response.ok) throw new Error('Job status could not be retrieved. Reload to retry.');
      const job = await response.json();
      const stateEl = document.querySelector('#job-state');
      const errorEl = document.querySelector('#job-error');
      const phaseEl = document.querySelector('#job-phase');
      const indicator = document.querySelector('.job-indicator');

      if (stateEl) stateEl.textContent = job.status;
      if (phaseEl && job.phase) phaseEl.textContent = job.phase;
      if (errorEl) errorEl.textContent = job.error || '';

      if (job.status === 'COMPLETE' && /^[a-f0-9]{32}$/.test(job.scan_id)) {
        if (indicator) indicator.classList.add('done');
        window.location.assign(`/scans/${job.scan_id}`);
      } else if (['QUEUED', 'RUNNING'].includes(job.status)) {
        window.setTimeout(poll, 2000);
      } else if (job.status === 'FAILED' || job.status === 'INTERRUPTED') {
        if (indicator) indicator.classList.remove('working');
      }
    } catch (error) {
      const errorEl = document.querySelector('#job-error');
      if (errorEl) errorEl.textContent = error.message;
    }
  };
  poll();
}

// 7. Dynamic Release DNA comparison form action helper
const targetSelect = document.querySelector('#dna-target-select');
const dnaForm = document.querySelector('#dna-compare-form');
if (targetSelect && dnaForm) {
  targetSelect.addEventListener('change', () => {
    const selectedId = targetSelect.value;
    if (selectedId) {
      dnaForm.action = `/scans/${selectedId}/dna`;
    }
  });
}
