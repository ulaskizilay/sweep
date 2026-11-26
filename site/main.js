(() => {
  "use strict";

  function selectPreviewTab(tabs, activeTab, imgEl, captionEl) {
    tabs.forEach((tab) => tab.setAttribute("aria-selected", String(tab === activeTab)));
    const { src, alt, caption } = activeTab.dataset;
    if (src) imgEl.src = src;
    if (alt) imgEl.alt = alt;
    if (caption) captionEl.textContent = caption;
  }

  function initPreviewTabs() {
    const imgEl = document.getElementById("preview-img");
    const captionEl = document.getElementById("preview-caption");
    const tabs = Array.from(document.querySelectorAll(".tab-btn"));
    if (!imgEl || !captionEl || tabs.length === 0) return;

    tabs.forEach((tab) => {
      tab.addEventListener("click", () => selectPreviewTab(tabs, tab, imgEl, captionEl));
    });
  }

  async function copyCommand(button) {
    const target = document.getElementById(button.dataset.copy);
    if (!target || !navigator.clipboard) return;
    await navigator.clipboard.writeText(target.textContent);
    const label = button.textContent;
    button.textContent = "Copied";
    window.setTimeout(() => {
      button.textContent = label;
    }, 1500);
  }

  function initCopyButtons() {
    document.querySelectorAll(".copy-btn").forEach((button) => {
      button.addEventListener("click", () => copyCommand(button));
    });
  }

  initPreviewTabs();
  initCopyButtons();
})();
