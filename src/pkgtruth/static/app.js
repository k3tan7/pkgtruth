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
