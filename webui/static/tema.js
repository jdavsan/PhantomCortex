/* ======================================================================
   Tema manual (claro / oscuro) antes del primer pintado.

   Se carga en <head> SIN defer para que el atributo data-tema este puesto
   antes de que el navegador pinte: asi no hay parpadeo entre el tema del
   sistema y el elegido por el usuario. app.js gestiona el boton y guarda
   la eleccion; aqui solo se lee.

   Valores de localStorage['tema']: 'claro' | 'oscuro' | ausente (sistema).
   Cualquier otro valor se ignora. Si el almacenamiento no esta disponible
   (modo privado, politica del navegador) se sigue al sistema sin error.
   ====================================================================== */
(function () {
  "use strict";
  try {
    var tema = window.localStorage.getItem("tema");
    if (tema === "claro" || tema === "oscuro") {
      document.documentElement.dataset.tema = tema;
    }
  } catch (e) {
    /* almacenamiento no disponible: se sigue la preferencia del sistema */
  }
})();
// Estado de la barra lateral (contraída o expandida) antes del primer pintado,
// para que no salte al cargar. body puede no existir aun: se aplica al html y
// app.js lo respeta leyendo la misma clave.
(function () {
  try {
    if (localStorage.getItem("nav") === "colapsada") {
      document.documentElement.classList.add("nav-colapsada-inicial");
      document.addEventListener("DOMContentLoaded", function () { document.body.classList.add("nav-colapsada"); });
    }
  } catch (e) { /* sin almacenamiento */ }
})();
