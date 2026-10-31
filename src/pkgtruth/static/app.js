'use strict';
const form = document.querySelector('#scan-form');
if (form) form.addEventListener('submit', () => {
  document.querySelector('#submit-scan').disabled = true;
  document.querySelector('#scan-progress').hidden = false;
  form.setAttribute('aria-busy', 'true');
});
const search = document.querySelector('#file-search');
const filter = document.querySelector('#status-filter');
function filterFiles() {
  let count = 0;
  document.querySelectorAll('.file-entry').forEach(entry => {
    const visible = entry.dataset.path.includes(search.value.toLowerCase()) &&
      (filter.value === 'all' || entry.dataset.status === filter.value);
    entry.hidden = !visible;
    if (visible) count++;
  });
  document.querySelector('#filter-count').textContent = `${count} shown`;
  document.querySelector('#no-matches').hidden = count !== 0;
}
if (search && filter) {
  search.addEventListener('input', filterFiles);
  filter.addEventListener('change', filterFiles);
}
document.querySelectorAll('[data-copy]').forEach(button => {
  button.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(button.dataset.copy); button.textContent = 'Copied'; }
    catch { button.textContent = button.dataset.copy; }
  });
});
window.addEventListener('pageshow', () => {
  if (form) {
    document.querySelector('#submit-scan').disabled = false;
    document.querySelector('#scan-progress').hidden = true;
    form.removeAttribute('aria-busy');
  }
});
const jobStatus = document.querySelector('#job-status');
if (jobStatus) {
  const poll = async () => {
    try {
      const response = await fetch(`/jobs/${jobStatus.dataset.jobId}/status`, {cache: 'no-store'});
      if (!response.ok) throw new Error('Job status could not be retrieved. Reload to retry.');
      const job = await response.json();
      document.querySelector('#job-state').textContent = job.status;
      document.querySelector('#job-error').textContent = job.error || '';
      if (job.status === 'COMPLETE' && /^[a-f0-9]{32}$/.test(job.scan_id)) {
        window.location.assign(`/scans/${job.scan_id}`);
      } else if (['QUEUED', 'RUNNING'].includes(job.status)) {
        window.setTimeout(poll, 2000);
      }
    } catch (error) { document.querySelector('#job-error').textContent = error.message; }
  };
  poll();
}
