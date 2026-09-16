/* SNS Hub — applique le thème mémorisé avant le premier rendu.
   Sans choix utilisateur, la préférence système s'applique (via color-scheme).
   Fichier chargé dans <head> avant la feuille de styles : aucun flash de thème. */
(function () {
  "use strict";
  var stored = null;
  try {
    stored = window.localStorage.getItem("hub-theme");
  } catch (error) {
    stored = null;
  }
  if (stored !== "dark" && stored !== "light") {
    return;
  }
  var root = document.documentElement;
  root.setAttribute("data-theme", stored);
  try {
    root.style.colorScheme = stored;
  } catch (error) {
    /* ignoré : le CSS reste autoritaire */
  }
})();
