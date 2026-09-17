/* SNS Hub — applique la vue de catalogue mémorisée (cartes / liste) avant le
   premier rendu, comme le thème. Sans choix mémorisé, la vue Cartes (par défaut)
   s'applique : les installations existantes ne changent pas.
   Fichier chargé dans <head> avant la feuille de styles : aucun clignotement. */
(function () {
  "use strict";
  var stored = null;
  try {
    stored = window.localStorage.getItem("hub_catalog_view");
  } catch (error) {
    stored = null;
  }
  if (stored !== "list") {
    return;
  }
  document.documentElement.setAttribute("data-catalog-view", "list");
})();
