/* SNS Hub — améliorations progressives : filtres instantanés, confirmations.
   Sans JavaScript, la recherche et les catégories restent fonctionnelles (GET). */
(function () {
  "use strict";

  var searchInput = document.querySelector('[data-filter="search"]');
  var cards = Array.prototype.slice.call(document.querySelectorAll("[data-card]"));
  var chips = Array.prototype.slice.call(document.querySelectorAll("[data-category-chip]"));
  var emptyState = document.querySelector("[data-empty-state]");
  var counter = document.querySelector("[data-result-count]");
  var activeCategory = (
    chips.filter(function (chip) {
      return chip.classList.contains("chip-active") && chip.getAttribute("data-category");
    })[0] || { getAttribute: function () { return ""; } }
  ).getAttribute("data-category") || "";

  function normalize(value) {
    return (value || "").toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, "");
  }

  function applyFilters() {
    var query = normalize(searchInput ? searchInput.value : "");
    var visible = 0;
    cards.forEach(function (card) {
      var haystack = normalize(
        card.getAttribute("data-name") + " " + card.getAttribute("data-description")
      );
      var categoryOk = !activeCategory || card.getAttribute("data-category") === activeCategory;
      var queryOk = !query || haystack.indexOf(query) !== -1;
      var show = categoryOk && queryOk;
      card.hidden = !show;
      if (show) { visible += 1; }
    });
    if (emptyState) { emptyState.hidden = visible !== 0; }
    if (counter) {
      counter.textContent =
        visible + (visible === 1 ? " application affichée" : " applications affichées");
    }
  }

  if (searchInput && cards.length) {
    searchInput.addEventListener("input", applyFilters);
  }

  chips.forEach(function (chip) {
    chip.addEventListener("click", function (event) {
      if (!cards.length) { return; }
      event.preventDefault();
      chips.forEach(function (other) {
        other.classList.remove("chip-active");
        other.removeAttribute("aria-current");
      });
      chip.classList.add("chip-active");
      chip.setAttribute("aria-current", "true");
      activeCategory = chip.getAttribute("data-category") || "";
      if (searchInput && searchInput.value) {
        searchInput.dispatchEvent(new Event("input"));
      }
      if (window.history && window.history.replaceState) {
        var url = chip.getAttribute("href");
        if (url) { window.history.replaceState(null, "", url); }
      }
      applyFilters();
    });
  });

  document.querySelectorAll("form[data-confirm]").forEach(function (form) {
    form.addEventListener("submit", function (event) {
      var message = form.getAttribute("data-confirm");
      if (message && !window.confirm(message)) {
        event.preventDefault();
      }
    });
  });
})();
