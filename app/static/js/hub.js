/* SNS Hub — améliorations progressives : filtres instantanés, bascule de la vue
   catalogue (cartes / liste, mémorisée en localStorage), confirmations,
   bascule de thème (mémorisée en localStorage), création rapide de catégorie.
   Sans JavaScript, le portail et l'administration restent fonctionnels. */
(function () {
  "use strict";

  /* --- Thème clair / sombre ------------------------------------------------- */

  var THEME_KEY = "hub-theme";

  function systemTheme() {
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches
      ? "light"
      : "dark";
  }

  function currentTheme() {
    var attribute = document.documentElement.getAttribute("data-theme");
    return attribute === "light" || attribute === "dark" ? attribute : systemTheme();
  }

  function applyTheme(theme, persist) {
    var root = document.documentElement;
    root.setAttribute("data-theme", theme);
    try {
      root.style.colorScheme = theme;
    } catch (error) {
      /* ignoré */
    }
    if (persist) {
      try {
        window.localStorage.setItem(THEME_KEY, theme);
      } catch (error) {
        /* stockage indisponible : le choix ne persiste pas, le thème reste actif */
      }
    }
  }

  var themeToggle = document.querySelector("[data-theme-toggle]");

  function syncThemeToggle() {
    if (!themeToggle) { return; }
    themeToggle.setAttribute(
      "aria-label",
      currentTheme() === "dark" ? "Activer le mode clair" : "Activer le mode sombre"
    );
  }

  if (themeToggle) {
    syncThemeToggle();
    themeToggle.addEventListener("click", function () {
      applyTheme(currentTheme() === "dark" ? "light" : "dark", true);
      syncThemeToggle();
    });
  }

  if (window.matchMedia) {
    var schemeQuery = window.matchMedia("(prefers-color-scheme: light)");
    var onSchemeChange = function () {
      if (!document.documentElement.getAttribute("data-theme")) { syncThemeToggle(); }
    };
    if (schemeQuery.addEventListener) {
      schemeQuery.addEventListener("change", onSchemeChange);
    } else if (schemeQuery.addListener) {
      schemeQuery.addListener(onSchemeChange);
    }
  }

  /* --- Vue du catalogue : cartes / liste ------------------------------------ */

  var VIEW_KEY = "hub_catalog_view";
  var viewSwitch = document.querySelector("[data-view-switch]");
  var viewButtons = Array.prototype.slice.call(document.querySelectorAll("[data-view-button]"));

  function currentView() {
    return document.documentElement.getAttribute("data-catalog-view") === "list" ? "list" : "cards";
  }

  function panelItems(view) {
    var panel = document.querySelector('[data-view-panel="' + view + '"]');
    return panel ? Array.prototype.slice.call(panel.querySelectorAll("[data-app]")) : [];
  }

  function syncViewButtons() {
    var view = currentView();
    viewButtons.forEach(function (button) {
      button.setAttribute(
        "aria-pressed",
        button.getAttribute("data-view-button") === view ? "true" : "false"
      );
    });
  }

  /* --- Filtres de la landing page ------------------------------------------ */

  var searchInput = document.querySelector('[data-filter="search"]');
  var items = Array.prototype.slice.call(document.querySelectorAll("[data-app]"));
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

  /* Le moteur de filtre est unique : il marque les deux rendus (carte et ligne)
     du même catalogue ; seul le décompte suit la vue affichée. */
  function applyFilters() {
    var query = normalize(searchInput ? searchInput.value : "");
    items.forEach(function (item) {
      var haystack = normalize(
        item.getAttribute("data-name") + " " + item.getAttribute("data-description")
      );
      var categoryOk = !activeCategory || item.getAttribute("data-category") === activeCategory;
      var queryOk = !query || haystack.indexOf(query) !== -1;
      item.hidden = !(categoryOk && queryOk);
    });
    var visible = panelItems(currentView()).filter(function (item) {
      return !item.hidden;
    }).length;
    if (emptyState) { emptyState.hidden = visible !== 0; }
    if (counter) {
      counter.textContent =
        visible + (visible === 1 ? " application affichée" : " applications affichées");
    }
  }

  function setView(view, persist) {
    var root = document.documentElement;
    root.setAttribute("data-catalog-view", view === "list" ? "list" : "cards");
    if (persist) {
      try {
        window.localStorage.setItem(VIEW_KEY, view);
      } catch (error) {
        /* stockage indisponible : la bascule reste active pour la session */
      }
    }
    /* Transition légère : la classe est retirée aussitôt l'animation finie ;
       `prefers-reduced-motion` neutralise toute animation (voir hub.css). */
    root.classList.add("view-animate");
    window.setTimeout(function () { root.classList.remove("view-animate"); }, 260);
    syncViewButtons();
    applyFilters();
  }

  if (viewSwitch && viewButtons.length && items.length) {
    viewSwitch.hidden = false;
    syncViewButtons();
    viewButtons.forEach(function (button) {
      button.addEventListener("click", function () {
        setView(button.getAttribute("data-view-button") === "list" ? "list" : "cards", true);
      });
    });
  }

  if (searchInput && items.length) {
    searchInput.addEventListener("input", applyFilters);
  }

  chips.forEach(function (chip) {
    chip.addEventListener("click", function (event) {
      if (!items.length) { return; }
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

  /* --- Création rapide d'une catégorie (formulaire application) ------------- */

  var quickAdd = document.querySelector("[data-quick-add]");
  var quickToggle = document.querySelector("[data-quick-add-toggle]");
  var quickInput = document.querySelector("[data-quick-add-input]");
  var quickSubmit = document.querySelector("[data-quick-add-submit]");
  var quickStatus = document.querySelector("[data-quick-add-status]");
  var categorySelect = document.getElementById("category_id");

  if (quickAdd && quickToggle && quickInput && quickSubmit && quickStatus && categorySelect) {
    var csrfInput = document.querySelector('input[name="_csrf"]');
    quickToggle.hidden = false;

    function setQuickStatus(message, ok) {
      quickStatus.textContent = message;
      quickStatus.hidden = false;
      quickStatus.classList.toggle("form-hint-error", !ok);
    }

    function toggleQuickAdd(open) {
      quickAdd.hidden = !open;
      quickToggle.setAttribute("aria-expanded", String(open));
      if (open) {
        quickInput.focus();
      } else {
        quickInput.value = "";
        quickStatus.hidden = true;
      }
    }

    function createCategory() {
      var name = (quickInput.value || "").trim();
      if (!name) {
        setQuickStatus("Indiquez un nom de catégorie.", false);
        quickInput.focus();
        return;
      }
      var body = new URLSearchParams();
      body.set("name", name);
      if (csrfInput) { body.set("_csrf", csrfInput.value); }
      quickSubmit.disabled = true;
      var endpoint = quickAdd.getAttribute("data-endpoint") || "/admin/categories/quick-create";
      var finish = function () { quickSubmit.disabled = false; };
      window
        .fetch(endpoint, {
          method: "POST",
          credentials: "same-origin",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
            Accept: "application/json"
          },
          body: body.toString()
        })
        .then(function (response) {
          return response.json().then(function (data) {
            return { ok: response.ok, data: data };
          });
        })
        .then(function (result) {
          if (result.ok && result.data && result.data.ok) {
            var category = result.data.category;
            var option = document.createElement("option");
            option.value = String(category.id);
            option.textContent = category.name;
            categorySelect.appendChild(option);
            categorySelect.value = String(category.id);
            setQuickStatus("Catégorie « " + category.name + " » créée et sélectionnée.", true);
            quickInput.value = "";
            quickAdd.hidden = true;
          } else {
            setQuickStatus((result.data && result.data.error) || "Création impossible.", false);
          }
        })
        .catch(function () {
          setQuickStatus("Création impossible : le serveur n'a pas répondu.", false);
        })
        .then(finish, finish);
    }

    quickToggle.addEventListener("click", function () {
      toggleQuickAdd(quickAdd.hidden);
    });
    quickSubmit.addEventListener("click", createCategory);
    quickInput.addEventListener("keydown", function (event) {
      if (event.key === "Enter") {
        event.preventDefault();
        createCategory();
      } else if (event.key === "Escape") {
        toggleQuickAdd(false);
      }
    });
  }
})();
