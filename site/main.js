(() => {
  const previewImg = document.getElementById("preview-img");
  const previewCaption = document.getElementById("preview-caption");
  const tabButtons = document.querySelectorAll(".tab-btn");

  tabButtons.forEach((button) => {
    button.addEventListener("click", () => {
      tabButtons.forEach((item) => item.setAttribute("aria-selected", "false"));
      button.setAttribute("aria-selected", "true");
      previewImg.src = button.dataset.src;
      previewImg.alt = button.dataset.alt;
      previewCaption.textContent = button.dataset.caption;
    });
  });

  document.querySelectorAll(".copy-btn").forEach((button) => {
    button.addEventListener("click", async () => {
      const target = document.getElementById(button.dataset.copy);
      if (!target || !navigator.clipboard) return;
      await navigator.clipboard.writeText(target.textContent);
      const original = button.textContent;
      button.textContent = "Copied";
      setTimeout(() => {
        button.textContent = original;
      }, 1500);
    });
  });
})();
