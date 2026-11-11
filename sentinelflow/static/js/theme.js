/*
 * Apply the saved or system appearance before the stylesheet paints.
 * Loaded synchronously in <head>; contains no inline scripts.
 */
(function () {
  'use strict';

  const STORAGE_KEY = 'sentinelflow-theme';
  const root = document.documentElement;
  const system = matchMedia('(prefers-color-scheme: light)');
  let saved = null;
  try {
    saved = localStorage.getItem(STORAGE_KEY);
  } catch (_) {
    /* Storage can be unavailable in private modes. */
  }

  function apply(theme) {
    root.dataset.theme = theme;
    root.style.colorScheme = theme;
    const next = theme === 'dark' ? 'light' : 'dark';
    document.querySelectorAll('[data-theme-toggle]').forEach((button) => {
      button.setAttribute('aria-label', 'Switch to ' + next + ' mode');
      button.setAttribute('title', 'Switch to ' + next + ' mode');
      button.setAttribute('aria-pressed', String(theme === 'light'));
      const use = button.querySelector('use');
      if (use) use.setAttribute('href', '/static/img/icons.svg#' + (theme === 'light' ? 'moon' : 'sun'));
    });
    window.dispatchEvent(new Event('themechange'));
  }

  apply(saved === 'light' || saved === 'dark' ? saved : system.matches ? 'light' : 'dark');

  document.addEventListener('DOMContentLoaded', () => {
    apply(root.dataset.theme);
    document.querySelectorAll('[data-theme-toggle]').forEach((button) =>
      button.addEventListener('click', () => {
        const theme = root.dataset.theme === 'dark' ? 'light' : 'dark';
        try {
          localStorage.setItem(STORAGE_KEY, theme);
        } catch (_) {
          /* Preference is kept for this page only. */
        }
        saved = theme;
        apply(theme);
      }),
    );
  });

  system.addEventListener('change', (event) => {
    if (!saved) apply(event.matches ? 'light' : 'dark');
  });
})();
