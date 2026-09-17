/* Sécurité — transport email : n'affiche que le transport sélectionné.
   Amélioration progressive : sans JavaScript, les deux blocs restent visibles
   (le bloc actif est marqué côté serveur) et le formulaire fonctionne à
   l'identique. Masquer un bloc n'empêche pas ses champs d'être soumis : les
   paramètres de l'autre transport restent donc conservés (voir D23). */
(function () {
  "use strict";
  var radios = document.querySelectorAll("input[data-transport-radio]");
  var blocks = document.querySelectorAll("[data-transport-block]");
  if (!radios.length || !blocks.length) {
    return;
  }
  function sync() {
    var selected = "smtp";
    radios.forEach(function (radio) {
      if (radio.checked) {
        selected = radio.value;
      }
    });
    blocks.forEach(function (block) {
      var active = block.getAttribute("data-transport-block") === selected;
      block.classList.toggle("is-active", active);
      block.hidden = !active;
    });
  }
  radios.forEach(function (radio) {
    radio.addEventListener("change", sync);
  });
  sync();
})();
