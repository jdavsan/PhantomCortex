/* ======================================================================
   Comportamiento de la interfaz. Sin dependencias, sin codigo en linea.

   Existe para que la Content-Security-Policy pueda prescindir de
   'unsafe-inline' en script-src: cualquier XSS que lograse inyectar
   <script> o un atributo onclick= quedaria bloqueado por el navegador.
   Todo lo que antes era onclick="..." se declara ahora con atributos data-*.

     data-toggle="id"      muestra/oculta el elemento con ese id
     data-confirm="texto"  pide confirmacion antes de enviar o pulsar; la pregunta
                           se muestra en la propia pagina, no con window.confirm
     data-confirm-si="…"   texto del boton que confirma («Sí, continuar» por omision)
     data-confirmar="texto" pide confirmacion antes de aceptar el cambio de un
                            control (en un <select> puede ir en cada <option>,
                            con el mensaje propio de esa eleccion); si se cancela,
                            el control vuelve a su valor anterior
     data-autosubmit       envia el formulario al cambiar el control
     data-tema-toggle      alterna el tema claro/oscuro y lo persiste
   ====================================================================== */
(function () {
  "use strict";

  function alCargar(fn) {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", fn);
    } else {
      fn();
    }
  }

  // --- tema claro / oscuro ----------------------------------------------
  // tema.js (en <head>, sin defer) ya ha aplicado data-tema desde
  // localStorage antes del primer pintado. Aqui se gestiona el boton:
  // alterna entre claro y oscuro a partir del tema EFECTIVO (manual o del
  // sistema). Si el tema elegido coincide con el del sistema se borra la
  // eleccion y la pagina vuelve a seguir al sistema automaticamente.
  var ETIQUETA = {
    claro: "Cambiar a tema oscuro",
    oscuro: "Cambiar a tema claro"
  };

  function temaSistema() {
    try {
      return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches
        ? "oscuro" : "claro";
    } catch (e) {
      return "claro";
    }
  }

  function temaEfectivo() {
    var manual = document.documentElement.dataset.tema;
    return manual === "claro" || manual === "oscuro" ? manual : temaSistema();
  }

  function actualizarBotones() {
    var efectivo = temaEfectivo();
    document.querySelectorAll("[data-tema-toggle]").forEach(function (boton) {
      boton.setAttribute("aria-label", ETIQUETA[efectivo]);
      boton.setAttribute("title", ETIQUETA[efectivo]);
      boton.setAttribute("aria-pressed", String(efectivo === "oscuro"));
    });
  }

  function aplicarTema(nuevo) {
    var raiz = document.documentElement;
    if (nuevo === temaSistema()) {
      delete raiz.dataset.tema;
      try { window.localStorage.removeItem("tema"); } catch (e) { /* sin almacenamiento */ }
    } else {
      raiz.dataset.tema = nuevo;
      try { window.localStorage.setItem("tema", nuevo); } catch (e) { /* sin almacenamiento */ }
    }
    actualizarBotones();
  }

  // --- paleta de colores profesionales ---------------------------------------------------
  var PALETAS_DISPONIBLES = {
    "claro": {
      "--fondo": "#ffffff",
      "--fondo-panel": "#ffffff",
      "--fondo-alt": "#f9fafb",
      "--fondo-hover": "#f3f4f6",
      "--borde": "#e5e7eb",
      "--borde-fuerte": "#d1d5db",
      "--texto": "#111827",
      "--texto-suave": "#374151",
      "--texto-tenue": "#6b7280",
      "--acento": "#2563eb",
      "--acento-claro": "#dbeafe",
      "--acento-hover": "#1d4ed8",
      "--secundario": "#10b981",
      "--secundario-claro": "#d1fae5",
      "--critico": "#ef4444",
      "--critico-fondo": "#fee2e2",
      "--alto": "#f97316",
      "--alto-fondo": "#feedde",
      "--medio": "#eab308",
      "--medio-fondo": "#fefce8",
      "--bajo": "#0ea5e9",
      "--bajo-fondo": "#e0f2fe",
      "--exito": "#10b981",
      "--exito-fondo": "#d1fae5",
      "--critico-texto": "#dc2626",
      "--alto-texto": "#ea580c",
      "--medio-texto": "#ca8a04",
      "--bajo-texto": "#0369a1"
    },
    "predeterminado": {
      "--fondo": "#0b1220",
      "--fondo-panel": "#111a2b",
      "--fondo-alt": "#16213a",
      "--fondo-hover": "#1c2a45",
      "--borde": "#2a3555",
      "--borde-fuerte": "#3d4a66",
      "--texto": "#e0e6f0",
      "--texto-suave": "#b0b8ca",
      "--texto-tenue": "#808a99",
      "--acento": "#60a5fa",
      "--acento-claro": "#1e2f55",
      "--acento-hover": "#93c5fd",
      "--secundario": "#22d3ee",
      "--secundario-claro": "#0f3a44",
      "--critico": "#ff6b6b",
      "--critico-fondo": "#3f1d1d",
      "--alto": "#ffb347",
      "--alto-fondo": "#3d2812",
      "--medio": "#ffd54f",
      "--medio-fondo": "#3a3410",
      "--bajo": "#64b5f6",
      "--bajo-fondo": "#1a2f4a",
      "--exito": "#66bb6a",
      "--exito-fondo": "#1a3a1f",
      "--critico-texto": "#ff8787",
      "--alto-texto": "#ffc266",
      "--medio-texto": "#ffe082",
      "--bajo-texto": "#90caf9"
    },
    "github": {
      "--fondo": "#0d1117",
      "--fondo-panel": "#161b22",
      "--fondo-alt": "#21262d",
      "--fondo-hover": "#30363d",
      "--borde": "#444c56",
      "--borde-fuerte": "#565f6d",
      "--texto": "#c9d1d9",
      "--texto-suave": "#8b949e",
      "--texto-tenue": "#6e7681",
      "--acento": "#58a6ff",
      "--acento-claro": "#1f6feb",
      "--acento-hover": "#79c0ff",
      "--secundario": "#79c0ff",
      "--secundario-claro": "#0a3622",
      "--critico": "#f85149",
      "--critico-fondo": "#2d1319",
      "--alto": "#fb8500",
      "--alto-fondo": "#3d1f00",
      "--medio": "#d29922",
      "--medio-fondo": "#3d3100",
      "--bajo": "#1f6feb",
      "--bajo-fondo": "#0a2342",
      "--exito": "#3fb950",
      "--exito-fondo": "#0d2d20",
      "--critico-texto": "#f85149",
      "--alto-texto": "#fb8500",
      "--medio-texto": "#d29922",
      "--bajo-texto": "#58a6ff"
    },
    "catppuccinMocha": {
      "--fondo": "#1e1e2e",
      "--fondo-panel": "#181825",
      "--fondo-alt": "#2a2a3e",
      "--fondo-hover": "#313244",
      "--borde": "#45475a",
      "--borde-fuerte": "#585b70",
      "--texto": "#cdd6f4",
      "--texto-suave": "#bac2de",
      "--texto-tenue": "#a6adc8",
      "--acento": "#89b4fa",
      "--acento-claro": "#1e1e2e",
      "--acento-hover": "#a6e3ff",
      "--secundario": "#f5c2e7",
      "--secundario-claro": "#1e1e2e",
      "--critico": "#f38ba8",
      "--critico-fondo": "#3f1f28",
      "--alto": "#fab387",
      "--alto-fondo": "#3f2810",
      "--medio": "#f9e2af",
      "--medio-fondo": "#3f3810",
      "--bajo": "#89dceb",
      "--bajo-fondo": "#1f3a4a",
      "--exito": "#a6e3a1",
      "--exito-fondo": "#1f3a1f",
      "--critico-texto": "#ff8b94",
      "--alto-texto": "#ffb366",
      "--medio-texto": "#ffd580",
      "--bajo-texto": "#96e1ff"
    },
    "dracula": {
      "--fondo": "#282a36",
      "--fondo-panel": "#21222c",
      "--fondo-alt": "#1e1f29",
      "--fondo-hover": "#44475a",
      "--borde": "#44475a",
      "--borde-fuerte": "#6272a4",
      "--texto": "#f8f8f2",
      "--texto-suave": "#f1fa8c",
      "--texto-tenue": "#6272a4",
      "--acento": "#8be9fd",
      "--acento-claro": "#282a36",
      "--acento-hover": "#6be9fd",
      "--secundario": "#ff79c6",
      "--secundario-claro": "#282a36",
      "--critico": "#ff5555",
      "--critico-fondo": "#2d1215",
      "--alto": "#ffb86c",
      "--alto-fondo": "#2d1f10",
      "--medio": "#f1fa8c",
      "--medio-fondo": "#2d2810",
      "--bajo": "#8be9fd",
      "--bajo-fondo": "#0d1f2d",
      "--exito": "#50fa7b",
      "--exito-fondo": "#0d2d10",
      "--critico-texto": "#ff5555",
      "--alto-texto": "#ffb86c",
      "--medio-texto": "#f1fa8c",
      "--bajo-texto": "#8be9fd"
    },
    "monokaiPro": {
      "--fondo": "#2d2a2e",
      "--fondo-panel": "#221f22",
      "--fondo-alt": "#403f44",
      "--fondo-hover": "#4d4a4f",
      "--borde": "#403f44",
      "--borde-fuerte": "#5b595c",
      "--texto": "#fcfcfa",
      "--texto-suave": "#c1c0c0",
      "--texto-tenue": "#727072",
      "--acento": "#78dce8",
      "--acento-claro": "#2d2a2e",
      "--acento-hover": "#a1efe4",
      "--secundario": "#ab9df2",
      "--secundario-claro": "#2d2a2e",
      "--critico": "#ff6188",
      "--critico-fondo": "#3d1f28",
      "--alto": "#fd9830",
      "--alto-fondo": "#3d2810",
      "--medio": "#ffd866",
      "--medio-fondo": "#3d3610",
      "--bajo": "#78dce8",
      "--bajo-fondo": "#1f3d3d",
      "--exito": "#a9dc76",
      "--exito-fondo": "#1f3d1f",
      "--critico-texto": "#ff6188",
      "--alto-texto": "#fd9830",
      "--medio-texto": "#ffd866",
      "--bajo-texto": "#78dce8"
    },
    "oceanNight": {
      "--fondo": "#0f111b",
      "--fondo-panel": "#1a1d2e",
      "--fondo-alt": "#252a3a",
      "--fondo-hover": "#2f3449",
      "--borde": "#3f4556",
      "--borde-fuerte": "#4d5466",
      "--texto": "#c9d1d9",
      "--texto-suave": "#8b95a7",
      "--texto-tenue": "#6a7682",
      "--acento": "#4da6ff",
      "--acento-claro": "#1f3a5f",
      "--acento-hover": "#79c0ff",
      "--secundario": "#7dd3c0",
      "--secundario-claro": "#1f3a35",
      "--critico": "#ff6b6b",
      "--critico-fondo": "#3f1f1f",
      "--alto": "#ffb86c",
      "--alto-fondo": "#3f2810",
      "--medio": "#ffd866",
      "--medio-fondo": "#3f3810",
      "--bajo": "#7dd3c0",
      "--bajo-fondo": "#1f3f38",
      "--exito": "#7dd3c0",
      "--exito-fondo": "#1f3f1f",
      "--critico-texto": "#ff8787",
      "--alto-texto": "#ffb86c",
      "--medio-texto": "#ffd866",
      "--bajo-texto": "#79d4c1"
    },
    "oneDarkPro": {
      "--fondo": "#282c34",
      "--fondo-panel": "#21252b",
      "--fondo-alt": "#2c313a",
      "--fondo-hover": "#3e4452",
      "--borde": "#3e4452",
      "--borde-fuerte": "#565c64",
      "--texto": "#abb2bf",
      "--texto-suave": "#9ca3af",
      "--texto-tenue": "#5c6370",
      "--acento": "#61afef",
      "--acento-claro": "#282c34",
      "--acento-hover": "#81b1ff",
      "--secundario": "#c678dd",
      "--secundario-claro": "#282c34",
      "--critico": "#e06c75",
      "--critico-fondo": "#3e1f1f",
      "--alto": "#e5c07b",
      "--alto-fondo": "#3e3014",
      "--medio": "#98c379",
      "--medio-fondo": "#2d3d1f",
      "--bajo": "#56b6f2",
      "--bajo-fondo": "#1f3a4a",
      "--exito": "#98c379",
      "--exito-fondo": "#1f3a1f",
      "--critico-texto": "#ff7a7a",
      "--alto-texto": "#ffcc80",
      "--medio-texto": "#c8e6c9",
      "--bajo-texto": "#81d4fa"
    },
    "tokyoNight": {
      "--fondo": "#1a1b26",
      "--fondo-panel": "#16161e",
      "--fondo-alt": "#1f202a",
      "--fondo-hover": "#2a2b35",
      "--borde": "#3b3f4f",
      "--borde-fuerte": "#565f89",
      "--texto": "#c0caf5",
      "--texto-suave": "#9aa5ce",
      "--texto-tenue": "#565f89",
      "--acento": "#7aa2f7",
      "--acento-claro": "#1a1b26",
      "--acento-hover": "#89ddff",
      "--secundario": "#bb9af7",
      "--secundario-claro": "#1a1b26",
      "--critico": "#f7768e",
      "--critico-fondo": "#3f1f1f",
      "--alto": "#ff9e64",
      "--alto-fondo": "#3f2810",
      "--medio": "#e0af68",
      "--medio-fondo": "#3f3810",
      "--bajo": "#7dcfff",
      "--bajo-fondo": "#1f3a3f",
      "--exito": "#9ece6a",
      "--exito-fondo": "#1f3a1f",
      "--critico-texto": "#ff7a93",
      "--alto-texto": "#ffb366",
      "--medio-texto": "#ffd580",
      "--bajo-texto": "#7fcfff"
    },
    "gruvbox": {
      "--fondo": "#282828",
      "--fondo-panel": "#1d2021",
      "--fondo-alt": "#32302f",
      "--fondo-hover": "#3c3836",
      "--borde": "#504945",
      "--borde-fuerte": "#665c54",
      "--texto": "#ebdbb2",
      "--texto-suave": "#d5c4a1",
      "--texto-tenue": "#bdae93",
      "--acento": "#83a598",
      "--acento-claro": "#282828",
      "--acento-hover": "#a89984",
      "--secundario": "#8ec07c",
      "--secundario-claro": "#282828",
      "--critico": "#fb4934",
      "--critico-fondo": "#3f1f1f",
      "--alto": "#fe8019",
      "--alto-fondo": "#3f2810",
      "--medio": "#fabd2f",
      "--medio-fondo": "#3f3810",
      "--bajo": "#83a598",
      "--bajo-fondo": "#1f3a35",
      "--exito": "#b8bb26",
      "--exito-fondo": "#2d3a1f",
      "--critico-texto": "#ff7a7a",
      "--alto-texto": "#ffb366",
      "--medio-texto": "#ffd580",
      "--bajo-texto": "#a3d5b8"
    },
    "solarized": {
      "--fondo": "#002b36",
      "--fondo-panel": "#073642",
      "--fondo-alt": "#586e75",
      "--fondo-hover": "#657b83",
      "--borde": "#586e75",
      "--borde-fuerte": "#657b83",
      "--texto": "#93a1a1",
      "--texto-suave": "#839496",
      "--texto-tenue": "#6c71c4",
      "--acento": "#268bd2",
      "--acento-claro": "#002b36",
      "--acento-hover": "#2aa198",
      "--secundario": "#2aa198",
      "--secundario-claro": "#002b36",
      "--critico": "#dc322f",
      "--critico-fondo": "#3f1f1f",
      "--alto": "#cb4b16",
      "--alto-fondo": "#3f2810",
      "--medio": "#b58900",
      "--medio-fondo": "#3f3810",
      "--bajo": "#268bd2",
      "--bajo-fondo": "#1f3a4a",
      "--exito": "#859900",
      "--exito-fondo": "#2d3a1f",
      "--critico-texto": "#ff7a7a",
      "--alto-texto": "#ffb366",
      "--medio-texto": "#ffd580",
      "--bajo-texto": "#81d4fa"
    },
    "nightOwl": {
      "--fondo": "#011627",
      "--fondo-panel": "#0b2942",
      "--fondo-alt": "#122d42",
      "--fondo-hover": "#1a3a52",
      "--borde": "#2d5a7b",
      "--borde-fuerte": "#464f7f",
      "--texto": "#d6deeb",
      "--texto-suave": "#c5d4e0",
      "--texto-tenue": "#7f8c9a",
      "--acento": "#82aaff",
      "--acento-claro": "#011627",
      "--acento-hover": "#a8d4ff",
      "--secundario": "#7fdbca",
      "--secundario-claro": "#011627",
      "--critico": "#ef5350",
      "--critico-fondo": "#3f1f1f",
      "--alto": "#f78c6b",
      "--alto-fondo": "#3f2810",
      "--medio": "#ffd54f",
      "--medio-fondo": "#3f3810",
      "--bajo": "#7fdbca",
      "--bajo-fondo": "#1f3a35",
      "--exito": "#22da6e",
      "--exito-fondo": "#1f3a1f",
      "--critico-texto": "#ff7a7a",
      "--alto-texto": "#ffb366",
      "--medio-texto": "#ffd580",
      "--bajo-texto": "#7fcfff"
    },
    "materialPalenight": {
      "--fondo": "#292d3e",
      "--fondo-panel": "#2c2f40",
      "--fondo-alt": "#353a4f",
      "--fondo-hover": "#3f445a",
      "--borde": "#434d61",
      "--borde-fuerte": "#545e78",
      "--texto": "#eeffff",
      "--texto-suave": "#c3cee3",
      "--texto-tenue": "#8792a8",
      "--acento": "#82b1ff",
      "--acento-claro": "#292d3e",
      "--acento-hover": "#a4c8ff",
      "--secundario": "#c792ea",
      "--secundario-claro": "#292d3e",
      "--critico": "#f07178",
      "--critico-fondo": "#3f1f1f",
      "--alto": "#f78c6b",
      "--alto-fondo": "#3f2810",
      "--medio": "#ffcb8b",
      "--medio-fondo": "#3f3810",
      "--bajo": "#82b1ff",
      "--bajo-fondo": "#1f3a4a",
      "--exito": "#c3e88d",
      "--exito-fondo": "#1f3a1f",
      "--critico-texto": "#ff8b92",
      "--alto-texto": "#ffb366",
      "--medio-texto": "#ffd580",
      "--bajo-texto": "#b4e7ff"
    },
    "synthwave": {
      "--fondo": "#2a2139",
      "--fondo-panel": "#3e1e56",
      "--fondo-alt": "#482d6a",
      "--fondo-hover": "#573b7e",
      "--borde": "#6b4a92",
      "--borde-fuerte": "#7f5aa6",
      "--texto": "#f0f1fa",
      "--texto-suave": "#c0c8ff",
      "--texto-tenue": "#8891d9",
      "--acento": "#ff006e",
      "--acento-claro": "#2a2139",
      "--acento-hover": "#ff4d9f",
      "--secundario": "#00f7ff",
      "--secundario-claro": "#2a2139",
      "--critico": "#ff006e",
      "--critico-fondo": "#3f1f2d",
      "--alto": "#ffb61a",
      "--alto-fondo": "#3f2810",
      "--medio": "#ffd900",
      "--medio-fondo": "#3f3810",
      "--bajo": "#00f7ff",
      "--bajo-fondo": "#1f3a3f",
      "--exito": "#72f1b8",
      "--exito-fondo": "#1f3a2a",
      "--critico-texto": "#ff4d9f",
      "--alto-texto": "#ffb366",
      "--medio-texto": "#ffd580",
      "--bajo-texto": "#00f7ff"
    },
    "smoooothfancy": {
      "--fondo": "#16213e",
      "--fondo-panel": "#0f3460",
      "--fondo-alt": "#1a4d7f",
      "--fondo-hover": "#245099",
      "--borde": "#3a5f8f",
      "--borde-fuerte": "#5a7f9f",
      "--texto": "#eaeaea",
      "--texto-suave": "#bdbdbd",
      "--texto-tenue": "#909090",
      "--acento": "#00d4ff",
      "--acento-claro": "#16213e",
      "--acento-hover": "#33e0ff",
      "--secundario": "#00ff88",
      "--secundario-claro": "#1a3a2a",
      "--critico": "#ff4444",
      "--critico-fondo": "#3f1f1f",
      "--alto": "#ffaa44",
      "--alto-fondo": "#3f2810",
      "--medio": "#ffdd44",
      "--medio-fondo": "#3f3810",
      "--bajo": "#00d4ff",
      "--bajo-fondo": "#1f3a4a",
      "--exito": "#00ff88",
      "--exito-fondo": "#1f3a2a",
      "--critico-texto": "#ff7a7a",
      "--alto-texto": "#ffb366",
      "--medio-texto": "#ffd580",
      "--bajo-texto": "#00ffcc"
    }
  };

  function obtenerPaletaActual() {
    try {
      return window.localStorage.getItem("tema_paleta_actual") || "viva";
    } catch (e) {
      return "viva";
    }
  }

  function guardarPaletaActual(nombre) {
    try {
      window.localStorage.setItem("tema_paleta_actual", nombre);
    } catch (e) { /* sin localStorage */ }
  }

  function aplicarPaleta(nombrePaleta) {
    nombrePaleta = nombrePaleta || obtenerPaletaActual();
    var paleta = PALETAS_DISPONIBLES[nombrePaleta];
    if (!paleta) return;

    var raiz = document.documentElement;
    for (var variable in paleta) {
      if (paleta.hasOwnProperty(variable)) {
        raiz.style.setProperty(variable, paleta[variable]);
      }
    }
    guardarPaletaActual(nombrePaleta);

    // Actualizar el selector si existe
    var selector = document.getElementById("selector-paleta");
    if (selector) {
      selector.value = nombrePaleta;
    }
  }

  alCargar(function () {
    // --- boton de tema -------------------------------------------------------
    document.querySelectorAll("[data-tema-toggle]").forEach(function (boton) {
      boton.addEventListener("click", function (ev) {
        ev.preventDefault();
        aplicarTema(temaEfectivo() === "oscuro" ? "claro" : "oscuro");
      });
    });
    actualizarBotones();
    aplicarPaleta();

    // --- dropdown de paleta de colores -----------------------------------
    var selectorTema = document.getElementById("selector-tema-oscuro");
    if (selectorTema) {
      selectorTema.addEventListener("change", function (ev) {
        aplicarPaleta(ev.target.value);
      });
      var temaGuardado = obtenerPaletaActual();
      if (temaGuardado && selectorTema.querySelector("option[value='" + temaGuardado + "']")) {
        selectorTema.value = temaGuardado;
      }
    }

    try {
      // Si el usuario sigue al sistema y este cambia, la etiqueta del boton
      // debe reflejar el nuevo tema efectivo.
      var mq = window.matchMedia("(prefers-color-scheme: dark)");
      if (mq && typeof mq.addEventListener === "function") {
        mq.addEventListener("change", actualizarBotones);
      }
    } catch (e) { /* matchMedia no disponible */ }

    // --- mostrar / ocultar bloques ---------------------------------------
    // Delegado en «document» (2026-09-10): desde que las zonas de la pagina se
    // sustituyen sin recargar (motor de actualizacion parcial, mas abajo), un
    // escuchador colgado de cada boton se perderia en la primera actualizacion.
    document.addEventListener("click", function (ev) {
      var boton = ev.target.closest ? ev.target.closest("[data-toggle]") : null;
      if (!boton) { return; }
      ev.preventDefault();
      var objetivo = document.getElementById(boton.getAttribute("data-toggle"));
      if (objetivo) {
        objetivo.hidden = !objetivo.hidden;
        boton.setAttribute("aria-expanded", String(!objetivo.hidden));
      }
    });

    // --- confirmacion dentro de la propia pagina --------------------------
    // Sustituye a window.confirm (peticion del usuario del 2026-09-07: los
    // dialogos del navegador «se ven como si se ejecutara codigo JavaScript», no
    // se pueden maquetar ni redactar en espanol correcto y no dicen que va a pasar).
    // En su lugar se inserta un bloque en la pagina, con el mensaje y dos botones,
    // el foco en el que confirma y la tecla Escape para cancelar.
    // Sin style= ni on*=: todo con clases de estilo.css y escuchadores de aqui.
    var confirmacionAbierta = null;

    function cerrarConfirmacion(devolverFoco) {
      if (!confirmacionAbierta) { return; }
      var c = confirmacionAbierta;
      confirmacionAbierta = null;
      document.removeEventListener("keydown", c.alPulsarTecla, true);
      if (c.bloque.parentNode) { c.bloque.parentNode.removeChild(c.bloque); }
      c.ocultados.forEach(function (el) { el.hidden = false; });
      if (c.origen) { c.origen.setAttribute("aria-expanded", "false"); }
      if (devolverFoco && c.foco && typeof c.foco.focus === "function") { c.foco.focus(); }
      if (typeof c.alCancelar === "function") { c.alCancelar(); }
    }

    function pedirConfirmacion(opciones) {
      cerrarConfirmacion(true);          // solo una confirmacion abierta a la vez
      var bloque = document.createElement("div");
      bloque.className = "confirmacion-en-linea";
      bloque.setAttribute("role", "group");
      bloque.setAttribute("aria-live", "polite");

      var texto = document.createElement("p");
      texto.className = "confirmacion-texto";
      texto.textContent = opciones.mensaje;
      bloque.appendChild(texto);

      var botones = document.createElement("div");
      botones.className = "confirmacion-botones";
      var si = document.createElement("button");
      si.type = "button";
      si.className = "btn pequeno" + (opciones.peligro ? " peligro" : "");
      si.setAttribute("data-confirmar-si", "");
      si.textContent = opciones.textoSi || "Sí, continuar";
      var no = document.createElement("button");
      no.type = "button";
      no.className = "btn pequeno";
      no.setAttribute("data-confirmar-no", "");
      no.textContent = "Cancelar";
      botones.appendChild(si);
      botones.appendChild(no);
      bloque.appendChild(botones);

      var ocultados = (opciones.ocultar || []).filter(function (el) { return el && !el.hidden; });
      ocultados.forEach(function (el) { el.hidden = true; });

      function alPulsarTecla(ev) {
        if (ev.key === "Escape" || ev.key === "Esc") {
          ev.preventDefault();
          cerrarConfirmacion(true);
        }
      }

      confirmacionAbierta = {
        bloque: bloque, ocultados: ocultados, origen: opciones.origen || null,
        foco: opciones.foco || opciones.origen || null,
        alCancelar: opciones.alCancelar, alPulsarTecla: alPulsarTecla
      };

      opciones.insertar(bloque);
      si.addEventListener("click", function () {
        var seguir = opciones.alConfirmar;
        confirmacionAbierta.alCancelar = null;   // se confirmo: no deshacer nada
        cerrarConfirmacion(false);
        if (typeof seguir === "function") { seguir(); }
      });
      no.addEventListener("click", function () { cerrarConfirmacion(true); });
      document.addEventListener("keydown", alPulsarTecla, true);
      si.focus();
    }

    function enviarFormulario(form, boton) {
      form.setAttribute("data-confirmado", "1");
      if (typeof form.requestSubmit === "function") {
        form.requestSubmit(boton && boton.form === form ? boton : undefined);
      } else if (boton && typeof boton.click === "function") {
        boton.click();
      } else {
        form.submit();
      }
    }

    // Formularios de una accion delicada: al enviar se pregunta en la pagina.
    // Todo delegado en «document» (2026-09-10) para que siga funcionando en las
    // zonas que el motor de actualizacion parcial sustituye sin recargar. El
    // escuchador se registra AQUI, en el primer modulo del fichero, de modo que
    // corre ANTES que el del motor: una accion delicada se confirma primero y se
    // envia despues (stopImmediatePropagation corta el envio mientras se pregunta).
    document.addEventListener("submit", function (ev) {
      var form = ev.target;
      if (!form || form.tagName !== "FORM" || !form.hasAttribute("data-confirm")) { return; }
      if (form.getAttribute("data-confirmado") === "1") {
        form.removeAttribute("data-confirmado");
        return;                                // ya confirmado: dejar pasar
      }
      ev.preventDefault();
      ev.stopImmediatePropagation();           // el motor no lo envia todavia
      var enviadores = Array.prototype.slice.call(
        form.querySelectorAll("button[type=submit], input[type=submit]"));
      var origen = (ev.submitter && form.contains(ev.submitter)) ? ev.submitter : enviadores[0];
      pedirConfirmacion({
        mensaje: form.getAttribute("data-confirm"),
        textoSi: form.getAttribute("data-confirm-si"),
        peligro: !!(origen && origen.classList.contains("peligro")),
        origen: origen,
        ocultar: enviadores,
        insertar: function (bloque) { form.insertAdjacentElement("afterend", bloque); },
        alConfirmar: function () { enviarFormulario(form, origen); }
      });
    });

    // Botones con un segundo destino dentro del mismo formulario (formaction).
    document.addEventListener("click", function (ev) {
      var boton = ev.target.closest ? ev.target.closest("button[data-confirm]") : null;
      if (!boton) { return; }
      if (boton.getAttribute("data-confirmado") === "1") {
        boton.removeAttribute("data-confirmado");
        return;
      }
      ev.preventDefault();
      ev.stopImmediatePropagation();
      var form = boton.form;
      pedirConfirmacion({
        mensaje: boton.getAttribute("data-confirm"),
        textoSi: boton.getAttribute("data-confirm-si"),
        peligro: boton.classList.contains("peligro"),
        origen: boton,
        ocultar: [boton],
        insertar: function (bloque) {
          (form || boton).insertAdjacentElement("afterend", bloque);
        },
        alConfirmar: function () {
          boton.setAttribute("data-confirmado", "1");
          if (form) {
            form.setAttribute("data-confirmado", "1");
            enviarFormulario(form, boton);
          } else {
            boton.click();
          }
        }
      });
    });

    // --- confirmacion al cambiar un control que se envia solo -------------
    // Revision del 2026-09-06 (hallazgo 7): al pasar el rol y el estado de
    // Usuarios a selectores que se envian al cambiar (data-autosubmit) se perdio
    // la confirmacion de dos acciones delicadas (deshabilitar a alguien, cambiar
    // su rol). El mensaje puede ir en el control o, para que dependa de la opcion
    // elegida, en cada <option>. Se registra ANTES que data-autosubmit y usa
    // stopImmediatePropagation para que el formulario no llegue a enviarse hasta
    // que la persona confirme; si cancela, el control recupera su valor anterior.
    function mensajeDeCambio(control) {
      if (control.tagName === "SELECT" && control.selectedIndex >= 0) {
        var opcion = control.options[control.selectedIndex];
        if (opcion && opcion.getAttribute("data-confirmar")) {
          return opcion.getAttribute("data-confirmar");
        }
      }
      return control.getAttribute("data-confirmar");
    }

    // El valor «anterior» de un control es el que pinto el servidor
    // (defaultValue / la opcion con «selected»): asi cancelar devuelve el control
    // a lo que hay guardado de verdad y no hace falta recordar nada por control,
    // que con las zonas que se sustituyen sin recargar seria un estado obsoleto.
    function valorDelServidor(control) {
      if (control.tagName === "SELECT") {
        for (var i = 0; i < control.options.length; i++) {
          if (control.options[i].defaultSelected) { return control.options[i].value; }
        }
        return control.options.length ? control.options[0].value : "";
      }
      return control.defaultValue !== undefined ? control.defaultValue : control.value;
    }

    // Delegado en «document» y registrado ANTES que data-autosubmit y que el
    // motor de actualizacion parcial: si se cancela, ni se envia el formulario
    // ni se actualiza nada (stopImmediatePropagation).
    document.addEventListener("change", function (ev) {
      var control = ev.target;
      if (!control || !control.tagName) { return; }
      var mensaje = mensajeDeCambio(control);
      if (!mensaje) { return; }
      if (control.getAttribute("data-confirmado") === "1") {
        control.removeAttribute("data-confirmado");
        return;
      }
      var anterior = valorDelServidor(control);
      var elegido = control.value;
      ev.preventDefault();
      ev.stopImmediatePropagation();       // data-autosubmit no envia todavia
      pedirConfirmacion({
        mensaje: mensaje,
        textoSi: "Sí, aplicar el cambio",
        origen: control,
        insertar: function (bloque) { control.insertAdjacentElement("afterend", bloque); },
        alCancelar: function () { control.value = anterior; },
        alConfirmar: function () {
          control.value = elegido;
          if (control.form) {
            control.form.setAttribute("data-confirmado", "1");
            enviarFormulario(control.form, null);
          }
        }
      });
    });

    // --- enviar al cambiar (selector de periodo) --------------------------
    // Tambien delegado. Si el formulario lo lleva el motor de actualizacion
    // parcial (data-filtro-vivo), no se hace nada aqui: el motor ya escucha el
    // cambio y pide la pagina nueva sin recargar. Cuando no hay motor (sin
    // JavaScript no llega ni a ejecutarse; con JavaScript pero sin zona viva)
    // se envia el formulario de siempre.
    document.addEventListener("change", function (ev) {
      var control = ev.target;
      if (!control || !control.hasAttribute || !control.hasAttribute("data-autosubmit")) { return; }
      if (!control.form) { return; }
      if (control.form.hasAttribute("data-filtro-vivo")) { return; }
      control.form.submit();
    });
  });

  // --- barra lateral: contraer/expandir y cajon en movil -------------------
  alCargar(function () {
    var boton = document.querySelector("[data-colapsar-nav]");
    if (boton) {
      var actualizar = function () {
        var colapsada = document.body.classList.contains("nav-colapsada");
        boton.setAttribute("aria-expanded", String(!colapsada));
      };
      boton.addEventListener("click", function () {
        var colapsada = document.body.classList.toggle("nav-colapsada");
        try { localStorage.setItem("nav", colapsada ? "colapsada" : "expandida"); } catch (e) { /* sin almacenamiento */ }
        actualizar();
      });
      actualizar();
    }
    var abrir = document.querySelector("[data-abrir-nav]");
    if (abrir) {
      abrir.addEventListener("click", function () {
        var abierta = document.body.classList.toggle("nav-abierta");
        abrir.setAttribute("aria-expanded", String(abierta));
      });
      document.addEventListener("keydown", function (ev) {
        if (ev.key === "Escape" && document.body.classList.contains("nav-abierta")) {
          document.body.classList.remove("nav-abierta");
          abrir.setAttribute("aria-expanded", "false");
        }
      });
    }
    // --- atajo «/» para la busqueda global (salvo dentro de un campo) --------
    var busqueda = document.querySelector("[data-atajo-busqueda]");
    if (busqueda) {
      document.addEventListener("keydown", function (ev) {
        var objetivo = ev.target;
        var escribiendo = objetivo && (objetivo.tagName === "INPUT" || objetivo.tagName === "TEXTAREA" || objetivo.tagName === "SELECT" || objetivo.isContentEditable);
        if (ev.key === "/" && !escribiendo && !ev.ctrlKey && !ev.metaKey && !ev.altKey) {
          ev.preventDefault();
          busqueda.focus();
        }
      });
    }
  });
})();

/* ======================================================================
   Activos: filtro en vivo, orden, vistas rapidas y desplegable de
   vulnerabilidades por activo. Todo en el navegador, sin recargar: la
   tabla trae todas las filas con atributos data-* y aqui se ocultan o
   muestran. La URL se actualiza (history.replaceState) para poder
   compartir la vista y para que «Exportar CSV» respete los filtros.
   ====================================================================== */
(function () {
  "use strict";

  function alCargar(fn) {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", fn);
    } else {
      fn();
    }
  }

  function texto(etiqueta, contenido, clase) {
    var el = document.createElement(etiqueta);
    if (contenido !== undefined && contenido !== null) { el.textContent = String(contenido); }
    if (clase) { el.className = clase; }
    return el;
  }

  function numero(n) {
    try { return Number(n).toLocaleString("es-ES"); } catch (e) { return String(n); }
  }

  alCargar(function () {
    // El filtrado, el orden y la paginacion los hace el SERVIDOR desde el 2026-09-07
    // (webui/vistas/activos.py). Antes se repetian aqui sobre las filas ya servidas:
    // ocultaba filas que el servidor ya habia descartado, reordenaba solo la pagina
    // en curso y reescribia la URL por su cuenta. Aqui queda unicamente el
    // desplegable de vulnerabilidades de cada equipo, que no tiene equivalente en el
    // servidor porque se pide bajo demanda.

    // --- desplegable de vulnerabilidades ------------------------------------
    // La fila de detalle es la hermana siguiente de la fila del equipo.
    function detalleDe(fila) {
      return fila.nextElementSibling && fila.nextElementSibling.classList.contains("fila-detalle")
        ? fila.nextElementSibling : null;
    }

    function construirDetalle(fila, datos) {
      var tr = document.createElement("tr");
      tr.className = "fila-detalle";
      var td = document.createElement("td");
      td.colSpan = fila.children.length;
      var cab = texto("div", "", "detalle-cabecera");
      cab.appendChild(texto("strong", numero(datos.total) + (datos.total === 1 ? " vulnerabilidad confirmada" : " vulnerabilidades confirmadas") + " en " + datos.activo.nombre));
      var enlaces = texto("span", "", "detalle-enlaces");
      var a1 = texto("a", "Abrir la ficha del activo", "btn pequeno"); a1.href = datos.url_activo; enlaces.appendChild(a1);
      var a2 = texto("a", "Plan de remediación", "btn pequeno primario"); a2.href = datos.url_remediacion; enlaces.appendChild(a2);
      cab.appendChild(enlaces);
      td.appendChild(cab);
      var t = document.createElement("table");
      t.className = "tabla-compacta tabla-vulns";
      var thead = document.createElement("thead");
      var trh = document.createElement("tr");
      ["Amenaza", "Severidad", "Paquete", "Instalada", "Corregida"].forEach(function (h) { trh.appendChild(texto("th", h)); });
      thead.appendChild(trh); t.appendChild(thead);
      var tb = document.createElement("tbody");
      datos.vulnerabilidades.forEach(function (v) {
        var r = document.createElement("tr");
        var c1 = document.createElement("td");
        if (v.url) { var a = texto("a", v.titulo); a.href = v.url; c1.appendChild(a); } else { c1.appendChild(texto("span", v.titulo)); }
        c1.appendChild(texto("div", v.cve + (v.aviso ? " · " + v.aviso : ""), "pequeno tenue mono"));
        r.appendChild(c1);
        var c2 = document.createElement("td");
        if (v.severidad) { c2.appendChild(texto("span", v.severidad_es, "insignia " + String(v.severidad).toLowerCase())); }
        if (v.kev) { c2.appendChild(document.createTextNode(" ")); c2.appendChild(texto("span", "KEV", "insignia kev")); }
        r.appendChild(c2);
        // Una linea por paquete en las tres columnas: la version que corrige es la de ESE
        // paquete. Antes se pintaba una sola «corregida» por CVE y podia ser de otro
        // paquete distinto del que se nombraba (revision del 2026-09-06).
        var cPaq = document.createElement("td");
        cPaq.className = "mono pequeno envolver";
        var cIns = document.createElement("td");
        cIns.className = "mono pequeno envolver";
        var cCor = document.createElement("td");
        cCor.className = "mono pequeno envolver";
        (v.paquetes || []).forEach(function (p) {
          cPaq.appendChild(texto("div", p.paquete || "—"));
          cIns.appendChild(texto("div", p.instalada || "—"));
          cCor.appendChild(texto("div", p.corregida || p.sin_parche_texto || "pendiente de publicar",
                                 p.corregida ? "" : "tenue"));
        });
        if (!(v.paquetes || []).length) {
          cPaq.textContent = "—"; cIns.textContent = "—";
          cCor.textContent = v.corregida || "—";
        }
        r.appendChild(cPaq); r.appendChild(cIns); r.appendChild(cCor);
        tb.appendChild(r);
      });
      t.appendChild(tb);
      var envoltorio = texto("div", "", "tabla-envoltorio");
      envoltorio.appendChild(t);
      td.appendChild(envoltorio);
      tr.appendChild(td);
      return tr;
    }

    // Delegado en «document» y no en la tabla: la busqueda en vivo sustituye la zona
    // #lista-activos entera, asi que un escuchador colgado de la tabla se perderia en
    // el primer filtrado.
    document.addEventListener("click", function (ev) {
      var boton = ev.target.closest ? ev.target.closest("[data-vulns]") : null;
      if (!boton) { return; }
      var fila = boton.closest("tr[data-id]");
      var existente = detalleDe(fila);
      if (existente) {
        var cerrado = existente.dataset.cerrado === "1";
        existente.dataset.cerrado = cerrado ? "0" : "1";
        existente.hidden = !cerrado;
        boton.setAttribute("aria-expanded", String(cerrado));
        boton.textContent = numero(fila.dataset.afectados) + (cerrado ? " · ocultar" : " · ver");
        return;
      }
      boton.disabled = true;
      boton.textContent = "cargando…";
      fetch("/activos/" + encodeURIComponent(fila.dataset.id) + "/vulnerabilidades.json", { credentials: "same-origin", headers: { "Accept": "application/json" } })
        .then(function (r) { if (!r.ok) { throw new Error("HTTP " + r.status); } return r.json(); })
        .then(function (datos) {
          var det = construirDetalle(fila, datos);
          det.dataset.cerrado = "0";
          fila.parentNode.insertBefore(det, fila.nextSibling);
          boton.disabled = false;
          boton.textContent = numero(datos.total) + " · ocultar";
          boton.setAttribute("aria-expanded", "true");
        })
        .catch(function () {
          boton.disabled = false;
          boton.textContent = "no disponible";
        });
    });
  });
})();

/* ======================================================================
   Motor de actualizacion parcial (2026-09-10). Peticion del usuario: «ajusta
   que el uso de funcionalidades se utilice sin que la pagina se recargue
   porque eso es muy molesto».

   Mejora progresiva: SIN JavaScript todo sigue funcionando exactamente como
   antes (formularios y enlaces normales, con recarga completa). Con
   JavaScript se pide la MISMA direccion de siempre con fetch, se extrae del
   HTML devuelto la zona afectada y se sustituye solo esa parte. No hay
   interfaz de datos nueva ni plantillas en el navegador: el servidor sigue
   pintando el HTML y el modelo de seguridad no cambia (mismo metodo, mismo
   testigo CSRF, misma direccion).

   Contrato de atributos (docs/INTERACCION_SIN_RECARGA_2026-09-10.md):

     ZONAS VIVAS
       <div id="resultados" data-zona-viva data-zona-nombre="Resultados">
         El identificador es unico en la pagina y lo pinta el servidor igual en
         la respuesta completa que en el fragmento.
       [data-zona-foco]     (dentro de la zona) donde va el foco al terminar.
       [data-zona-resumen]  (dentro de la zona) su texto es lo que se anuncia.

     FILTROS, ORDEN Y BUSQUEDAS (GET)
       <form data-filtro-vivo="resultados cifras">    zonas que actualiza
             data-filtro-vivo-retardo="300"           gracia al escribir (220 ms)
             data-vivo-fragmento="/ruta/parcial">     direccion que devuelve solo
                                                      los trozos (mismos parametros)
       <select data-vivo-zonas="campos resultados">   zonas de ESE control
       <input data-sin-vivo>                          control que no actualiza nada

     ENLACES (paginacion, orden, vistas rapidas, pestanas)
       Todo <a> dentro de una zona viva se intercepta y actualiza esa zona.
       <a data-enlace-vivo="resultados">   enlace de fuera de la zona
       <a data-sin-vivo>                   enlace que nunca se intercepta

     ACCIONES DE ESCRITURA (POST)
       <form method="post" data-accion-viva="resultados"
             data-accion-espera="Guardando…"
             data-accion-tiempo="120000">
       Se envia el formulario tal cual (con su campo csrf), se sigue la
       redireccion que devuelve el servidor y del documento resultante se sacan
       la zona y el mensaje de resultado. data-accion-tiempo sube el tiempo de
       espera de las acciones que consultan la red (probar una fuente, verificar
       el correo), hasta el techo de 120 segundos que impone nginx.

     MENSAJES
       base.html trae <div id="mensajes-plataforma" role="status"
       aria-live="polite" aria-atomic="true">: el motor lo rellena desde la
       respuesta, asi que un lector de pantalla anuncia el resultado.

   Robustez: las respuestas que llegan fuera de orden se descartan (contador),
   hay tiempo de espera con mensaje, el boton se deshabilita mientras la accion
   esta en vuelo y no se admite un segundo envio del mismo formulario. Si algo
   no cuadra en una LECTURA (respuesta que no es HTML, zona ausente, error de
   red) se cae a la navegacion normal en vez de dejar la pantalla a medias. En
   una ESCRITURA no se reintenta NUNCA sola: la accion puede haberse aplicado
   ya, asi que se avisa y decide la persona.
   ====================================================================== */
(function () {
  "use strict";

  var soportado = (typeof window.fetch === "function"
                   && window.history && typeof window.history.pushState === "function"
                   && typeof window.DOMParser === "function"
                   && typeof window.URLSearchParams === "function"
                   && typeof window.CustomEvent === "function"
                   && !!document.documentElement.closest);
  if (!soportado) { return; }

  //: Tiempo de espera de una lectura y de una escritura, en milisegundos. Una
  //: escritura puede recalcular aplicabilidad, asi que se le da mas margen.
  var ESPERA_LECTURA = 20000;
  var ESPERA_ESCRITURA = 45000;
  //: Techo absoluto: nginx corta la respuesta a los 120 segundos
  //: (proxy_read_timeout), asi que esperar mas no sirve de nada. Una accion que
  //: consulta la red (probar una fuente, verificar el correo) lo pide con
  //: data-accion-tiempo.
  var ESPERA_MAXIMA = 120000;
  //: Gracia al escribir en un campo de texto: sin ella se pediria una consulta
  //: por pulsacion. Cada formulario puede subirlo con data-filtro-vivo-retardo.
  var RETARDO_ESCRIBIENDO = 220;
  var ID_MENSAJES = "mensajes-plataforma";
  //: Direcciones que no devuelven una pagina: descargas y datos. Se dejan al
  //: navegador tal cual (exportar CSV, informes en Word, JSON de detalle).
  var NO_ES_PAGINA = /\.(csv|docx?|xlsx?|pdf|json|zip|png|svg|txt)$/i;

  function alCargar(fn) {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", fn);
    } else {
      fn();
    }
  }

  //: Marca de ESTA carga del documento. Va en cada entrada del historial que crea el
  //: motor para que, al volver atras desde otra pagina distinta (una navegacion de
  //: verdad), no se intente reponer una zona que ya no es la de este documento.
  var DOCUMENTO = "vivo-" + Date.now() + "-" + Math.random().toString(36).slice(2);

  var peticion = 0;          // numero de la ultima peticion pedida
  var secuencia = 0;         // para que cada enlace cuente como origen distinto
  var ultimoOrigen = "";     // decide entre pushState (contenido nuevo) y replaceState
  var temporizadores = [];   // [{form, id}] retardo de gracia por formulario
  var enVuelo = [];          // formularios con una escritura en curso

  // ---------------------------------------------------------------- utiles
  function idsDe(valor) {
    return String(valor || "").split(/\s+/).filter(function (t) { return !!t; });
  }

  function zonaPorId(id) {
    return id ? document.getElementById(id) : null;
  }

  function rutaDe(url) {
    try { return new URL(url, window.location.href).pathname; } catch (e) { return ""; }
  }

  function zonaQueContiene(elemento) {
    var z = elemento.closest("[data-zona-viva]");
    return (z && z.id) ? z : null;
  }

  function textoDeZona(id) {
    var z = zonaPorId(id);
    if (!z) { return ""; }
    var resumen = z.querySelector("[data-zona-resumen]");
    if (resumen && resumen.textContent.trim()) {
      return resumen.textContent.trim().replace(/\s+/g, " ");
    }
    var nombre = z.getAttribute("data-zona-nombre");
    return nombre ? nombre + ": actualizado." : "";
  }

  // ------------------------------------------------------------- mensajes
  function regionMensajes() {
    return document.getElementById(ID_MENSAJES);
  }

  function anunciar(texto, clase) {
    var region = regionMensajes();
    if (!region) { return; }
    region.replaceChildren();
    if (!texto) { return; }
    var aviso = document.createElement("div");
    aviso.className = "aviso " + (clase || "info");
    aviso.textContent = texto;
    region.appendChild(aviso);
  }

  /* Copia el contenedor de mensajes de la respuesta. Devuelve true si traia
     algo: asi ningun mensaje del servidor (los flash de Flask) se pierde por
     haberse consumido en una peticion que no recargaba la pagina. */
  function copiarMensajes(doc) {
    var region = regionMensajes();
    var nueva = doc.getElementById(ID_MENSAJES);
    if (!region || !nueva) { return false; }
    if (!nueva.textContent.trim()) { return false; }
    region.replaceChildren.apply(region, Array.prototype.slice.call(nueva.childNodes));
    return true;
  }

  // ----------------------------------------------------------- sustitucion
  function aplicar(doc, ids) {
    var hechas = [];
    ids.forEach(function (id) {
      var actual = zonaPorId(id);
      var nueva = doc.getElementById(id);
      if (!actual || !nueva) { return; }
      actual.replaceChildren.apply(actual, Array.prototype.slice.call(nueva.childNodes));
      // El servidor puede cambiar las clases de la propia zona (por ejemplo la
      // que marca «sin resultados»): se copian para no quedarse con las viejas.
      if (typeof nueva.className === "string" && nueva.className !== actual.className) {
        actual.className = nueva.className;
      }
      hechas.push(id);
    });
    return hechas;
  }

  /* Reponer los valores de los formularios de filtro que viven FUERA de la
     zona (el caso normal): al volver atras la lista tiene que cuadrar con lo
     que muestran el campo de busqueda y los selectores. */
  function sincronizarFormularios(doc) {
    document.querySelectorAll("form[data-filtro-vivo]").forEach(function (form) {
      var clave = form.getAttribute("data-filtro-vivo");
      var otro = doc.querySelector('form[data-filtro-vivo="' + clave + '"]');
      if (!otro) { return; }
      var mios = Array.prototype.slice.call(form.elements);
      var suyos = Array.prototype.slice.call(otro.elements);
      mios.forEach(function (control) {
        if (!control.name) { return; }
        var propios = mios.filter(function (c) { return c.name === control.name; });
        var ajenos = suyos.filter(function (c) { return c.name === control.name; });
        var fuente = ajenos[propios.indexOf(control)];
        if (!fuente) { return; }
        if (control.type === "checkbox" || control.type === "radio") {
          control.checked = fuente.checked;
        } else if (control.value !== fuente.value) {
          control.value = fuente.value;
        }
      });
    });
  }

  // ------------------------------------------------------------------ foco
  function recordarFoco() {
    var el = document.activeElement;
    if (!el || el === document.body || el === document.documentElement) { return null; }
    return {
      el: el,
      id: el.id || "",
      inicio: (typeof el.selectionStart === "number") ? el.selectionStart : null,
      fin: (typeof el.selectionEnd === "number") ? el.selectionEnd : null
    };
  }

  function enfocar(destino) {
    if (!destino || typeof destino.focus !== "function") { return false; }
    if (!destino.hasAttribute("tabindex") && !/^(A|BUTTON|INPUT|SELECT|TEXTAREA|SUMMARY)$/.test(destino.tagName)) {
      destino.setAttribute("tabindex", "-1");
    }
    try { destino.focus({ preventScroll: true }); } catch (e) { destino.focus(); }
    return true;
  }

  /* Devuelve el foco a un sitio razonable SIN desplazar la pagina. Si quien lo
     tenia sigue en el documento (por ejemplo el campo en el que se escribe) no
     se le toca: nadie debe perder el cursor a media palabra. */
  function devolverFoco(memoria, zonas) {
    if (memoria && memoria.el && document.contains(memoria.el)) { return; }
    var destino = memoria && memoria.id ? document.getElementById(memoria.id) : null;
    if (destino && enfocar(destino)) {
      if (memoria.inicio !== null && typeof destino.setSelectionRange === "function") {
        try { destino.setSelectionRange(memoria.inicio, memoria.fin); } catch (e) { /* no admite seleccion */ }
      }
      return;
    }
    for (var i = 0; i < zonas.length; i++) {
      var z = zonaPorId(zonas[i]);
      if (!z) { continue; }
      if (enfocar(z.querySelector("[data-zona-foco]") || z)) { return; }
    }
  }

  // ------------------------------------------------------------- historial
  function anotarHistorial(url, origen) {
    if (!url) { return; }
    try {
      if (origen && origen === ultimoOrigen) {
        window.history.replaceState({ vivo: 1, doc: DOCUMENTO }, "", url);
      } else {
        window.history.pushState({ vivo: 1, doc: DOCUMENTO }, "", url);
      }
    } catch (e) { /* sin historial: la pagina sigue funcionando */ }
    ultimoOrigen = origen || "";
  }

  // ---------------------------------------------------------------- boton
  function ocuparBoton(boton, texto) {
    if (!boton) { return function () { }; }
    var antes = boton.textContent;
    var deshabilitado = boton.disabled;
    if (texto && boton.tagName === "BUTTON") { boton.textContent = texto; }
    boton.disabled = true;
    boton.setAttribute("aria-busy", "true");
    return function () {
      boton.disabled = deshabilitado;
      boton.removeAttribute("aria-busy");
      if (texto && boton.tagName === "BUTTON") { boton.textContent = antes; }
    };
  }

  // --------------------------------------------------------------- peticion
  /* opciones: url, urlHistorial, zonas, metodo, cuerpo, origen, escritura,
               boton, textoEspera, reponerFormularios, alFallar */
  function pedir(opciones) {
    var zonas = opciones.zonas.filter(function (id) { return !!zonaPorId(id); });
    if (!zonas.length) { return false; }        // sin zona no hay nada que sustituir
    var numero = ++peticion;
    var memoria = recordarFoco();
    var abortador = (typeof window.AbortController === "function") ? new AbortController() : null;
    var init = {
      credentials: "same-origin",
      redirect: "follow",
      headers: { "X-Requested-With": "fetch", "Accept": "text/html" }
    };
    if (abortador) { init.signal = abortador.signal; }
    if (opciones.metodo === "POST") { init.method = "POST"; init.body = opciones.cuerpo; }

    zonas.forEach(function (id) { zonaPorId(id).setAttribute("aria-busy", "true"); });
    var soltarBoton = ocuparBoton(opciones.boton, opciones.textoEspera);
    var espera = opciones.espera > 0 ? Math.min(opciones.espera, ESPERA_MAXIMA)
      : (opciones.escritura ? ESPERA_ESCRITURA : ESPERA_LECTURA);
    var reloj = window.setTimeout(function () {
      if (abortador) { abortador.abort(); }
    }, espera);

    function terminar() {
      window.clearTimeout(reloj);
      soltarBoton();
      var i = enVuelo.indexOf(opciones.formulario);
      if (i >= 0) { enVuelo.splice(i, 1); }
      zonas.forEach(function (id) {
        var z = zonaPorId(id);
        if (z) { z.removeAttribute("aria-busy"); }
      });
    }

    function caer(mensaje) {
      terminar();
      if (opciones.escritura) {
        // Nunca se reintenta una escritura sola: puede haberse aplicado ya.
        anunciar(mensaje, "error");
        return;
      }
      if (typeof opciones.alFallar === "function") { opciones.alFallar(); }
      else { anunciar(mensaje, "error"); }
    }

    window.fetch(opciones.url, init)
      .then(function (r) {
        var tipo = r.headers.get("Content-Type") || "";
        return r.text().then(function (html) {
          return { html: html, url: r.url || opciones.url, ok: r.ok, tipo: tipo,
                   redirigido: !!r.redirected };
        });
      })
      .then(function (respuesta) {
        if (!opciones.escritura && numero !== peticion) { terminar(); return; }
        if (respuesta.tipo.indexOf("text/html") < 0) {
          // No es una pagina (una descarga, un JSON o un error del proxy): lo
          // resuelve el navegador con una navegacion normal, nunca repitiendo
          // el POST, y la pantalla no se queda a medias.
          terminar();
          window.location.assign(opciones.escritura
            ? respuesta.url : (opciones.urlHistorial || opciones.url));
          return;
        }
        if (opciones.escritura && respuesta.redirigido
            && rutaDe(respuesta.url) !== window.location.pathname) {
          // El servidor ha decidido llevar a la persona a OTRA pagina (por ejemplo de
          // la ficha de un activo a la lista): eso no es actualizar un trozo, es
          // navegar, y se navega de verdad. Es una peticion GET, nunca se repite el
          // POST.
          terminar();
          window.location.assign(respuesta.url);
          return;
        }
        var doc = new DOMParser().parseFromString(respuesta.html, "text/html");
        var hechas = aplicar(doc, zonas);
        if (!hechas.length) {
          if (opciones.escritura) {
            // La escritura ya se hizo: se va a la pagina que devolvio el servidor
            // (una peticion GET, nunca se repite el POST).
            terminar();
            window.location.assign(respuesta.url);
          } else {
            caer("No se pudo actualizar solo esa parte de la página.");
          }
          return;
        }
        if (opciones.reponerFormularios) { sincronizarFormularios(doc); }
        var conMensaje = copiarMensajes(doc);
        if (!conMensaje) { anunciar(textoDeZona(hechas[0]), "info"); }
        if (opciones.escritura) {
          // Una escritura no ensucia el historial. La direccion solo se pone al dia
          // cuando el servidor REDIRIGIO (patron enviar-redirigir-mostrar): si
          // respondio en el sitio, la direccion visible seguiria siendo la de la
          // accion (por ejemplo /excepciones/crear, que solo admite POST) y recargar
          // daria un 405.
          if (respuesta.redirigido) {
            try {
              window.history.replaceState({ vivo: 1, doc: DOCUMENTO }, "", respuesta.url);
            } catch (e) { /* sin historial */ }
          }
        } else {
          anotarHistorial(opciones.urlHistorial, opciones.origen);
        }
        terminar();
        devolverFoco(memoria, hechas);
        document.dispatchEvent(new CustomEvent("vivo:zona-actualizada", {
          detail: { zonas: hechas, escritura: !!opciones.escritura }
        }));
      })
      .catch(function () {
        if (!opciones.escritura && numero !== peticion) { terminar(); return; }
        caer(opciones.escritura
          ? "No se pudo completar la acción: el servidor no respondió a tiempo. Actualice la página para ver el estado real antes de repetirla."
          : "No se pudo actualizar esa parte de la página.");
      });
    return true;
  }

  // ------------------------------------------------- formularios de filtro
  function urlDeFormulario(form, base) {
    var params = new URLSearchParams();
    new FormData(form).forEach(function (valor, clave) {
      if (typeof valor === "string" && valor.trim() !== "") { params.append(clave, valor); }
    });
    var destino = base || form.getAttribute("action") || window.location.pathname;
    destino = destino.split("#")[0].split("?")[0];
    var cadena = params.toString();
    return destino + (cadena ? "?" + cadena : "");
  }

  function zonasDeControl(form, control) {
    var propias = control ? control.getAttribute("data-vivo-zonas") : null;
    return idsDe(propias || form.getAttribute("data-filtro-vivo"));
  }

  function actualizarFiltro(form, control) {
    var url = urlDeFormulario(form);
    var fragmento = form.getAttribute("data-vivo-fragmento");
    // Devuelve false si en ESTA pagina no existe la zona que el formulario dice
    // actualizar (por ejemplo la busqueda global, que solo puede sustituir la lista
    // cuando ya se esta en Amenazas). Quien llama tiene que dejar entonces que el
    // navegador haga lo de siempre: enviar el formulario y recargar.
    return pedir({
      url: fragmento ? urlDeFormulario(form, fragmento) : url,
      urlHistorial: url,
      zonas: zonasDeControl(form, control),
      origen: "filtro:" + (form.getAttribute("data-filtro-vivo") || form.id || "unico"),
      alFallar: function () { form.submit(); }
    });
  }

  function relojDe(form) {
    for (var i = 0; i < temporizadores.length; i++) {
      if (temporizadores[i].form === form) { return temporizadores[i]; }
    }
    var nuevo = { form: form, id: null };
    temporizadores.push(nuevo);
    return nuevo;
  }

  function cancelarRetardo(form) {
    var reloj = relojDe(form);
    if (reloj.id !== null) { window.clearTimeout(reloj.id); reloj.id = null; }
  }

  function formularioVivo(control) {
    var form = control && control.form;
    if (!form || !form.hasAttribute("data-filtro-vivo")) { return null; }
    if (control.hasAttribute("data-sin-vivo")) { return null; }
    return form;
  }

  /* Los escuchadores se enganchan al cargar el documento y NO antes: asi los
     que ya tenia app.js (la confirmacion en la pagina de data-confirm y
     data-confirmar, registrados en el primer modulo del fichero) corren
     primero y una accion delicada sigue pidiendo confirmacion antes de que el
     motor la envie. Todo por delegacion en «document»: al sustituir una zona no
     hay que volver a enganchar nada. */
  alCargar(function () {

  document.addEventListener("input", function (ev) {
    var control = ev.target;
    if (!control || !control.tagName) { return; }
    var tipo = (control.getAttribute("type") || "").toLowerCase();
    if (control.tagName !== "TEXTAREA"
        && !(control.tagName === "INPUT" && (tipo === "text" || tipo === "search" || tipo === "number" || tipo === "date" || tipo === ""))) {
      return;
    }
    var form = formularioVivo(control);
    if (!form) { return; }
    var reloj = relojDe(form);
    var gracia = parseInt(form.getAttribute("data-filtro-vivo-retardo"), 10);
    if (!(gracia > 0)) { gracia = RETARDO_ESCRIBIENDO; }
    if (reloj.id !== null) { window.clearTimeout(reloj.id); }
    reloj.id = window.setTimeout(function () {
      reloj.id = null;
      actualizarFiltro(form, control);
    }, gracia);
  }, true);

  document.addEventListener("change", function (ev) {
    var control = ev.target;
    if (!control || !control.tagName) { return; }
    var form = formularioVivo(control);
    if (!form) { return; }
    if (control.tagName === "INPUT" && (control.type === "text" || control.type === "search")) { return; }
    cancelarRetardo(form);
    actualizarFiltro(form, control);
  });

  // ------------------------------------------------------------- enlaces
  document.addEventListener("click", function (ev) {
    if (ev.defaultPrevented || ev.button !== 0 || ev.metaKey || ev.ctrlKey
        || ev.shiftKey || ev.altKey) { return; }
    var a = ev.target.closest ? ev.target.closest("a[href]") : null;
    if (!a || a.hasAttribute("data-sin-vivo") || a.hasAttribute("download")
        || (a.getAttribute("target") || "") !== "") { return; }
    if (a.protocol !== "http:" && a.protocol !== "https:") { return; }
    if (a.origin !== window.location.origin) { return; }
    if (NO_ES_PAGINA.test(a.pathname)) { return; }
    var zonas = idsDe(a.getAttribute("data-enlace-vivo"));
    if (!zonas.length) {
      var z = zonaQueContiene(a);
      if (!z) { return; }
      // Dentro de una zona viva solo se interceptan los enlaces que llevan a la
      // MISMA pagina con otros parametros (paginacion, orden, vistas rapidas,
      // pestanas). Uno que lleva a otra pagina (la ficha de una amenaza) es una
      // navegacion de verdad: se deja al navegador, sin pedirla dos veces.
      if (a.pathname !== window.location.pathname) { return; }
      zonas = [z.id];
    }
    // Un enlace a un ancla de la MISMA direccion es un salto dentro de la
    // pagina: eso lo hace el navegador, no el motor.
    if (a.hash && a.pathname === window.location.pathname && a.search === window.location.search) { return; }
    if (pedir({
      url: a.href,
      urlHistorial: a.href,
      zonas: zonas,
      origen: "enlace:" + (++secuencia),
      alFallar: function () { window.location.assign(a.href); }
    })) {
      ev.preventDefault();
    }
  });

  // --------------------------------------------------- envio de formularios
  document.addEventListener("submit", function (ev) {
    if (ev.defaultPrevented) { return; }
    var form = ev.target;
    if (!form || form.tagName !== "FORM") { return; }
    var metodo = (form.getAttribute("method") || "get").toLowerCase();
    var enviador = (ev.submitter && form.contains(ev.submitter)) ? ev.submitter : null;

    if (metodo !== "post") {
      if (!form.hasAttribute("data-filtro-vivo")) { return; }
      cancelarRetardo(form);
      // Solo se corta el envio si el motor puede sustituir la zona de verdad; si no,
      // el formulario se envia como siempre y la pagina se recarga.
      if (actualizarFiltro(form, null)) { ev.preventDefault(); }
      return;
    }
    if (!form.hasAttribute("data-accion-viva")) { return; }
    if (enVuelo.indexOf(form) >= 0) { ev.preventDefault(); return; }  // doble envio
    var zonas = idsDe(form.getAttribute("data-accion-viva"));
    if (!zonas.length) {
      var z = zonaQueContiene(form);
      if (z) { zonas = [z.id]; }
    }
    if (!zonas.length) { return; }              // sin zona: envio normal, con recarga

    var datos;
    try { datos = new FormData(form, enviador || undefined); }
    catch (e) { datos = new FormData(form); }
    if (enviador && enviador.name && !datos.has(enviador.name)) {
      datos.append(enviador.name, enviador.value || "");
    }
    var accion = (enviador && enviador.getAttribute("formaction"))
      || form.getAttribute("action") || window.location.href;
    enVuelo.push(form);
    if (pedir({
      url: accion,
      urlHistorial: null,
      zonas: zonas,
      metodo: "POST",
      cuerpo: datos,
      escritura: true,
      formulario: form,
      boton: enviador,
      espera: parseInt(form.getAttribute("data-accion-tiempo"), 10) || 0,
      textoEspera: form.getAttribute("data-accion-espera") || "Guardando…"
    })) {
      ev.preventDefault();
    } else {
      enVuelo.splice(enVuelo.indexOf(form), 1);   // sin zona: que lo envie el navegador
    }
  });

  // ------------------------------------------------------- boton de atras
  window.addEventListener("popstate", function (ev) {
    if (!ev.state || !ev.state.vivo || ev.state.doc !== DOCUMENTO) { return; }
    var zonas = [];
    document.querySelectorAll("[data-zona-viva][id]").forEach(function (z) {
      if (zonas.indexOf(z.id) < 0) { zonas.push(z.id); }
    });
    document.querySelectorAll("form[data-filtro-vivo]").forEach(function (f) {
      idsDe(f.getAttribute("data-filtro-vivo")).forEach(function (id) {
        if (zonas.indexOf(id) < 0) { zonas.push(id); }
      });
    });
    ultimoOrigen = "";
    if (!zonas.length) { window.location.reload(); return; }
    pedir({
      url: window.location.href,
      urlHistorial: null,
      zonas: zonas,
      origen: "atras",
      reponerFormularios: true,
      alFallar: function () { window.location.reload(); }
    });
  });

  // La entrada actual del historial se marca como propia del motor para que
  // volver a ella con el boton de atras reponga la zona en vez de no hacer nada.
  try {
    window.history.replaceState({ vivo: 1, doc: DOCUMENTO }, "", window.location.href);
  } catch (e) { /* sin historial */ }

  // El boton «Filtrar» sobra cuando el motor esta activo: los cambios se
  // aplican solos. Sin JavaScript sigue visible y es la unica forma de filtrar.
  function ocultarEnviosDeFiltro() {
    document.querySelectorAll("form[data-filtro-vivo] button[type=submit], form[data-filtro-vivo] input[type=submit]").forEach(function (b) {
      if (!b.hasAttribute("data-sin-vivo")) { b.hidden = true; }
    });
  }
  ocultarEnviosDeFiltro();
  document.addEventListener("vivo:zona-actualizada", ocultarEnviosDeFiltro);

  });
})();

/* ======================================================================
   Recorrido guiado. Cada pagina marca sus pasos con atributos:
     data-tour="3" data-tour-titulo="..." data-tour-texto="..."
   El boton [data-iniciar-tour] de la barra superior recorre los pasos de la
   pagina, resaltando cada bloque con un foco y una tarjeta explicativa.
   Teclado: flechas para avanzar o retroceder, Escape para salir.

   Recorrido completo (usuarios nuevos): <body data-tour-estado="pendiente">
   significa que el usuario nunca respondio a la invitacion. Se le ofrece UNA
   vez un recorrido encadenado por todas las secciones del menu lateral; su
   respuesta (empezado, rechazado, completado) se guarda en el servidor con
   POST a data-tour-url, asi que no se repite en cada acceso ni depende del
   navegador. El encadenado avanza de seccion en seccion con sessionStorage.
   Sin codigo en linea (CSP).
   ====================================================================== */
(function () {
  "use strict";

  var CLAVE_CADENA = "tour:completo";

  function alCargar(fn) {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", fn);
    } else {
      fn();
    }
  }

  function el(etiqueta, clase, texto) {
    var e = document.createElement(etiqueta);
    if (clase) { e.className = clase; }
    if (texto !== undefined) { e.textContent = texto; }
    return e;
  }

  function leerCadena() {
    try { return JSON.parse(window.sessionStorage.getItem(CLAVE_CADENA) || "null"); } catch (e) { return null; }
  }
  function guardarCadena(valor) {
    try {
      if (valor) { window.sessionStorage.setItem(CLAVE_CADENA, JSON.stringify(valor)); }
      else { window.sessionStorage.removeItem(CLAVE_CADENA); }
    } catch (e) { /* sin almacenamiento */ }
  }

  alCargar(function () {
    var boton = document.querySelector("[data-iniciar-tour]");
    if (!boton) { return; }
    var cuerpo = document.body;
    // Los pasos se recalculan cada vez que hacen falta (2026-09-10): las zonas de
    // la pagina se sustituyen sin recargar, asi que una lista guardada al cargar
    // apuntaria a nodos que ya no estan en el documento.
    function calcularPasos() {
      return Array.prototype.slice.call(document.querySelectorAll("[data-tour]"))
        .filter(function (n) { return n.getAttribute("data-tour-titulo"); })
        .sort(function (a, b) { return Number(a.getAttribute("data-tour")) - Number(b.getAttribute("data-tour")); });
    }
    var pasos = calcularPasos();

    // Secciones del menu lateral, en orden, para el recorrido completo.
    var secciones = Array.prototype.slice.call(document.querySelectorAll("aside nav a[href]")).map(function (a) {
      return { url: a.getAttribute("href"), ruta: a.pathname, nombre: (a.querySelector("span") || a).textContent.trim() };
    });
    var indiceSeccion = -1;
    secciones.forEach(function (s, i) {
      if (indiceSeccion === -1 && s.ruta === window.location.pathname) { indiceSeccion = i; }
    });
    if (indiceSeccion === -1) {
      var mejor = -1;
      secciones.forEach(function (s, i) {
        if (window.location.pathname.indexOf(s.ruta) === 0 && (mejor === -1 || s.ruta.length > secciones[mejor].ruta.length)) { mejor = i; }
      });
      indiceSeccion = mejor;
    }
    var cadena = leerCadena();
    var enCadena = !!(cadena && cadena.activo);
    var siguienteSeccion = (indiceSeccion >= 0 && indiceSeccion + 1 < secciones.length) ? secciones[indiceSeccion + 1] : null;

    function enviarEstado(estado) {
      var url = cuerpo.getAttribute("data-tour-url");
      var csrf = cuerpo.getAttribute("data-csrf");
      if (!url || !csrf || !window.fetch) { return; }
      var datos = new FormData();
      datos.append("csrf", csrf);
      datos.append("estado", estado);
      try {
        window.fetch(url, { method: "POST", body: datos, credentials: "same-origin", keepalive: true }).catch(function () { /* sin red */ });
      } catch (e) { /* nada */ }
      cuerpo.setAttribute("data-tour-estado", estado);
    }

    function irASeccion(seccion) {
      guardarCadena({ activo: true });
      window.location.assign(seccion.url);
    }

    function terminarCadena() {
      guardarCadena(null);
      enCadena = false;
      enviarEstado("completado");
    }

    if (!pasos.length) {
      boton.disabled = true;
      boton.setAttribute("title", "Esta página no tiene recorrido guiado");
      boton.setAttribute("aria-label", "Esta página no tiene recorrido guiado");
      // En el recorrido completo, una seccion sin pasos se salta.
      if (enCadena) {
        if (siguienteSeccion) { irASeccion(siguienteSeccion); } else { terminarCadena(); }
      }
      return;
    }
    boton.setAttribute("title", "Recorrido guiado de esta página (" + pasos.length + " pasos)");

    var estado = { indice: 0, fondo: null, foco: null, caja: null, activo: false, anteriorFoco: null };

    function cerrar(motivo) {
      if (!estado.activo) { return; }
      estado.activo = false;
      [estado.fondo, estado.foco, estado.caja].forEach(function (n) { if (n && n.parentNode) { n.parentNode.removeChild(n); } });
      pasos.forEach(function (p) { p.classList.remove("tour-destacado"); });
      document.body.classList.remove("tour-activo");
      window.removeEventListener("resize", posicionar);
      window.removeEventListener("scroll", posicionar, true);
      document.removeEventListener("keydown", teclas);
      if (estado.anteriorFoco && estado.anteriorFoco.focus) { estado.anteriorFoco.focus(); }
      // Salir a mitad del recorrido completo lo da por terminado: no se vuelve a preguntar
      // (siempre puede repetirlo por seccion con el icono de ayuda o completo desde la tarjeta).
      if (enCadena && motivo !== "siguiente") { terminarCadena(); }
    }

    function posicionar() {
      if (!estado.activo) { return; }
      var objetivo = pasos[estado.indice];
      var r = objetivo.getBoundingClientRect();
      var sx = window.pageXOffset, sy = window.pageYOffset;
      var margen = 8;
      estado.foco.style.top = (r.top + sy - margen) + "px";
      estado.foco.style.left = (r.left + sx - margen) + "px";
      estado.foco.style.width = (r.width + margen * 2) + "px";
      estado.foco.style.height = (r.height + margen * 2) + "px";
      var caja = estado.caja;
      var anchoCaja = Math.min(400, window.innerWidth - 24);
      caja.style.width = anchoCaja + "px";
      var izquierda = Math.max(12, Math.min(r.left + sx, window.innerWidth + sx - anchoCaja - 12));
      var espacioAbajo = window.innerHeight - r.bottom;
      var altoCaja = caja.offsetHeight || 220;
      var arriba;
      if (espacioAbajo > altoCaja + 24 || r.top < altoCaja + 24) {
        arriba = r.bottom + sy + 14;
        caja.classList.remove("arriba");
      } else {
        arriba = r.top + sy - altoCaja - 14;
        caja.classList.add("arriba");
      }
      caja.style.top = arriba + "px";
      caja.style.left = izquierda + "px";
    }

    function avanzar() {
      if (estado.indice < pasos.length - 1) { mostrar(estado.indice + 1); return; }
      if (enCadena && siguienteSeccion) { cerrar("siguiente"); irASeccion(siguienteSeccion); return; }
      cerrar("fin");
    }

    function mostrar(indice) {
      estado.indice = Math.max(0, Math.min(indice, pasos.length - 1));
      var objetivo = pasos[estado.indice];
      pasos.forEach(function (p) { p.classList.remove("tour-destacado"); });
      objetivo.classList.add("tour-destacado");
      if (objetivo.hidden) { objetivo.hidden = false; }
      var caja = estado.caja;
      caja.replaceChildren();
      var cabecera = el("div", "tour-cabecera");
      var etiquetaPaso = "Paso " + (estado.indice + 1) + " de " + pasos.length;
      if (enCadena && indiceSeccion >= 0) {
        etiquetaPaso = secciones[indiceSeccion].nombre + " (sección " + (indiceSeccion + 1) + " de " + secciones.length + ") · " + etiquetaPaso;
      }
      cabecera.appendChild(el("span", "tour-paso", etiquetaPaso));
      var cerrarBtn = el("button", "tour-cerrar", "×");
      cerrarBtn.type = "button"; cerrarBtn.setAttribute("aria-label", enCadena ? "Salir del recorrido completo" : "Cerrar el recorrido");
      cerrarBtn.addEventListener("click", function () { cerrar("cerrar"); });
      cabecera.appendChild(cerrarBtn);
      caja.appendChild(cabecera);
      var titulo = el("h2", "tour-titulo", objetivo.getAttribute("data-tour-titulo"));
      titulo.id = "tour-titulo";
      caja.appendChild(titulo);
      caja.appendChild(el("p", "tour-texto", objetivo.getAttribute("data-tour-texto") || ""));
      var barra = el("div", "tour-barra");
      var progreso = el("div", "tour-progreso");
      progreso.style.width = Math.round(((estado.indice + 1) / pasos.length) * 100) + "%";
      barra.appendChild(progreso);
      caja.appendChild(barra);
      var acciones = el("div", "tour-acciones");
      if (!enCadena && secciones.length > 1) {
        var completo = el("button", "enlace pequeno tour-completo", "Recorrido completo por todas las secciones");
        completo.type = "button";
        completo.addEventListener("click", function () { cerrar("cerrar"); enviarEstado("empezado"); irASeccion(secciones[0]); });
        acciones.appendChild(completo);
      }
      var anterior = el("button", "btn pequeno", "Anterior"); anterior.type = "button";
      anterior.disabled = estado.indice === 0;
      anterior.addEventListener("click", function () { mostrar(estado.indice - 1); });
      var ultimo = estado.indice === pasos.length - 1;
      var textoSiguiente = ultimo ? (enCadena && siguienteSeccion ? "Siguiente sección: " + siguienteSeccion.nombre : (enCadena ? "Terminar el recorrido" : "Terminar")) : "Siguiente";
      var siguiente = el("button", "btn pequeno primario", textoSiguiente); siguiente.type = "button";
      siguiente.addEventListener("click", avanzar);
      acciones.appendChild(anterior); acciones.appendChild(siguiente);
      caja.appendChild(acciones);
      try { objetivo.scrollIntoView({ behavior: "smooth", block: "center" }); } catch (e) { objetivo.scrollIntoView(); }
      window.setTimeout(function () { posicionar(); siguiente.focus(); }, 60);
      window.setTimeout(posicionar, 450);
    }

    function teclas(ev) {
      if (!estado.activo) { return; }
      if (ev.key === "Escape") { ev.preventDefault(); cerrar("cerrar"); }
      else if (ev.key === "ArrowRight" || ev.key === "Enter") { ev.preventDefault(); avanzar(); }
      else if (ev.key === "ArrowLeft") { ev.preventDefault(); mostrar(estado.indice - 1); }
    }

    function iniciar() {
      if (estado.activo) { cerrar("cerrar"); return; }
      pasos = calcularPasos();
      if (!pasos.length) { return; }
      estado.activo = true;
      estado.anteriorFoco = document.activeElement;
      document.body.classList.add("tour-activo");
      estado.fondo = el("div", "tour-fondo"); estado.fondo.addEventListener("click", function () { cerrar("cerrar"); });
      estado.foco = el("div", "tour-foco");
      estado.caja = el("div", "tour-caja");
      estado.caja.setAttribute("role", "dialog"); estado.caja.setAttribute("aria-modal", "true"); estado.caja.setAttribute("aria-labelledby", "tour-titulo");
      document.body.appendChild(estado.fondo); document.body.appendChild(estado.foco); document.body.appendChild(estado.caja);
      window.addEventListener("resize", posicionar);
      window.addEventListener("scroll", posicionar, true);
      document.addEventListener("keydown", teclas);
      ocultarInvitacion();
      mostrar(0);
    }
    boton.addEventListener("click", function (ev) { ev.preventDefault(); iniciar(); });

    // Al sustituir una zona sin recargar pueden aparecer o desaparecer pasos: se
    // vuelve a contar para que el titulo del boton y su estado digan la verdad.
    document.addEventListener("vivo:zona-actualizada", function () {
      pasos = calcularPasos();
      boton.disabled = !pasos.length;
      var titulo = pasos.length
        ? "Recorrido guiado de esta página (" + pasos.length + " pasos)"
        : "Esta página no tiene recorrido guiado";
      boton.setAttribute("title", titulo);
      boton.setAttribute("aria-label", pasos.length ? "Recorrido guiado de esta página" : titulo);
    });

    // --- recorrido completo en curso: arranca solo al cargar la seccion ---------
    if (enCadena) {
      window.setTimeout(iniciar, 250);
      return;
    }

    // --- invitacion unica a los usuarios nuevos ---------------------------------
    var invitacion = null;
    function ocultarInvitacion() {
      if (invitacion && invitacion.parentNode) { invitacion.parentNode.removeChild(invitacion); }
      invitacion = null;
      boton.classList.remove("tour-boton-pulso");
    }
    if (cuerpo.getAttribute("data-tour-estado") === "pendiente" && secciones.length) {
      invitacion = el("div", "tour-sugerencia");
      invitacion.setAttribute("role", "status");
      invitacion.appendChild(el("strong", null, "¿Es su primera vez en la plataforma?"));
      invitacion.appendChild(document.createTextNode(" Le proponemos un recorrido guiado por las " + secciones.length +
        " secciones del menú, paso a paso. Después podrá repetirlo por sección con el icono de ayuda. Esta invitación no se volverá a mostrar."));
      var ir = el("button", "btn pequeno primario", "Empezar el recorrido"); ir.type = "button";
      ir.addEventListener("click", function () {
        ocultarInvitacion();
        enviarEstado("empezado");
        if (indiceSeccion === 0) { enCadena = true; guardarCadena({ activo: true }); iniciar(); }
        else { irASeccion(secciones[0]); }
      });
      var no = el("button", "btn pequeno", "Ahora no"); no.type = "button";
      no.addEventListener("click", function () { ocultarInvitacion(); enviarEstado("rechazado"); });
      var fila = el("div", "tour-sugerencia-acciones"); fila.appendChild(ir); fila.appendChild(no);
      invitacion.appendChild(fila);
      (document.querySelector(".barra-superior") || document.body).appendChild(invitacion);
      boton.classList.add("tour-boton-pulso");
    }
  });

  // ------------------------------------------------------------------
  // Excepciones: vigencia permanente o con fecha (2026-09-10). El grupo de opciones
  // lleva data-grupo-vigencia="<id del campo de fecha>" y el campo data-campo-vigencia.
  // Al elegir «Permanente» la fecha se deshabilita, porque no va a usarse; al volver a
  // «Con fecha» se habilita y recibe el foco. Es SOLO comodidad: el servidor exige la
  // fecha cuando el plazo no es permanente y la ignora cuando lo es, asi que sin
  // JavaScript el formulario sigue siendo correcto. Delegado en «document» para que
  // siga funcionando si el motor de actualizacion parcial sustituye la zona.
  // ------------------------------------------------------------------
  alCargar(function () {
    function ajustarVigencia(grupo) {
      if (!grupo) { return; }
      var id = grupo.getAttribute("data-grupo-vigencia");
      var campo = id ? document.getElementById(id) : grupo.querySelector("[data-campo-vigencia]");
      if (!campo) { return; }
      var elegido = grupo.querySelector('input[name="vigencia"]:checked');
      var permanente = !!elegido && elegido.value === "permanente";
      campo.disabled = permanente;
      if (permanente) { campo.removeAttribute("aria-invalid"); }
    }
    document.querySelectorAll("[data-grupo-vigencia]").forEach(ajustarVigencia);
    document.addEventListener("change", function (ev) {
      var control = ev.target;
      if (!control || control.name !== "vigencia" || !control.closest) { return; }
      var grupo = control.closest("[data-grupo-vigencia]");
      if (!grupo) { return; }
      ajustarVigencia(grupo);
      var id = grupo.getAttribute("data-grupo-vigencia");
      var campo = id ? document.getElementById(id) : null;
      if (campo && !campo.disabled && control.value !== "permanente") { campo.focus(); }
    });
  });

  // ------------------------------------------------------------------
  // «Copiar» al portapapeles (2026-09-08). Un boton con data-copiar="<id>" copia el valor
  // del control indicado y lo dice en el propio boton («Copiada») durante unos segundos;
  // si el navegador no permite el portapapeles, selecciona el texto para copiarlo a mano.
  // Sin HTML en linea: la CSP no lo admite.
  // ------------------------------------------------------------------
  alCargar(function () {
    // Delegado en «document» (2026-09-10): el boton puede estar dentro de una
    // zona que el motor de actualizacion parcial sustituye sin recargar.
    document.addEventListener("click", function (ev) {
      var boton = ev.target.closest ? ev.target.closest("[data-copiar]") : null;
      if (!boton) { return; }
      var original = boton.getAttribute("data-copiar-texto-original");
      if (original === null) {
        original = boton.textContent;
        boton.setAttribute("data-copiar-texto-original", original);
      }
      (function () {
        var control = document.getElementById(boton.getAttribute("data-copiar"));
        if (!control) { return; }
        var valor = ("value" in control) ? control.value : control.textContent;
        function hecho() {
          boton.textContent = boton.getAttribute("data-copiado-texto") || "Copiado";
          boton.setAttribute("aria-live", "polite");
          window.setTimeout(function () { boton.textContent = original; }, 3000);
        }
        function aMano() {
          if (control.select) { control.focus(); control.select(); }
          boton.textContent = "Seleccionado: copie con Ctrl+C";
          window.setTimeout(function () { boton.textContent = original; }, 4000);
        }
        if (navigator.clipboard && window.isSecureContext) {
          navigator.clipboard.writeText(valor).then(hecho, aMano);
        } else {
          aMano();
        }
      }());
    });
  });

})();

// Modal de activos afectados por una amenaza (2026-11-16): envuelto en su propio
// cierre, igual que los bloques anteriores de este fichero, porque «alCargar» es un
// ayudante local de cada bloque, no una función global; sin este cierre, las dos
// llamadas de más abajo lanzaban «alCargar is not defined» y ni el botón «Ver
// activos» ni el cierre con Escape llegaban a conectarse nunca (fallo detectado solo
// al revisar el fichero entero: las pruebas de Python no ejecutan JavaScript).
(function () {
  "use strict";

  function alCargar(fn) {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", fn);
    } else {
      fn();
    }
  }

  // Estado del modal de activos afectados (lista de Amenazas)
  var modalActivosEstado = {
    threatId: null,
    cveText: null,
    paginaActual: 1,
    busqueda: '',
    puedeRemediar: false
  };

  // Estado del cuadro inline de activos afectados (ficha de una amenaza)
  var gridActivosEstado = {
    threatId: null,
    paginaActual: 1,
    busqueda: ''
  };

  function cargarActivosAfectados(threatId, pagina, busqueda) {
    pagina = pagina || 1;
    busqueda = busqueda || '';

    var cuerpo = document.getElementById('modal-cuerpo-activos');
    var paginacion = document.getElementById('modal-paginacion-activos');
    var contador = document.getElementById('modal-contador-activos');

    cuerpo.innerHTML = '<p class="cargando">Cargando activos afectados…</p>';

    var url = '/amenazas/activos-afectados/' + threatId + '?pagina=' + pagina;
    if (busqueda) url += '&buscar=' + encodeURIComponent(busqueda);

    fetch(url)
      .then(function(resp) {
        if (!resp.ok) throw new Error('Error al cargar');
        return resp.json();
      })
      .then(function(datos) {
        modalActivosEstado.paginaActual = datos.pagina;
        modalActivosEstado.puedeRemediar = !!datos.puede_remediar;

        if (datos.activos.length === 0 && datos.total === 0) {
          cuerpo.innerHTML = '<p>No hay activos afectados confirmados.</p>';
          paginacion.classList.add('oculto');
          contador.textContent = '';
          return;
        }

        contador.textContent = datos.total + (datos.total === 1 ? ' activo afectado' : ' activos afectados');

        if (datos.activos.length === 0) {
          cuerpo.innerHTML = '<p>No hay resultados en esta página.</p>';
          paginacion.classList.remove('oculto');
        } else {
          cuerpo.innerHTML = _tarjetasActivos(datos.activos, datos.puede_remediar);

          if (datos.total > datos.por_pagina) {
            paginacion.classList.remove('oculto');
            document.getElementById('modal-anterior').disabled = datos.pagina <= 1;
            document.getElementById('modal-siguiente').disabled = datos.pagina >= datos.max_paginas;
            document.getElementById('modal-info-pagina').textContent = 'Página ' + datos.pagina + ' de ' + datos.max_paginas + ' (' + datos.total + ' activos)';
          } else {
            paginacion.classList.add('oculto');
          }
        }
      })
      .catch(function(err) {
        cuerpo.innerHTML = '<p class="error">Error al cargar los activos: ' + err.message + '</p>';
        paginacion.classList.add('oculto');
      });
  }

  function _tarjetasActivos(activos, puedeRemediar) {
    var html = '<div class="tabla-envoltorio"><table class="tabla-compacta tabla-activos-afectados">';
    html += '<thead><tr>';
    html += '<th>Activo</th><th>Tipo</th><th>IP</th><th>Paquete</th>';
    html += '<th>Versión instalada</th><th>Versión que corrige</th><th>Estado</th>';
    html += '<th class="acciones"><span class="oculto-visual">Acciones</span></th>';
    html += '</tr></thead><tbody>';
    activos.forEach(function(a) {
      html += '<tr data-fila-activo="' + a.id + '">';
      html += '<td>' + _textoEscapado(a.nombre || '(sin nombre)');
      if (a.riesgo_aceptado) {
        html += '<div class="pequeno"><span class="insignia medio">Riesgo aceptado'
              + (a.riesgo_aceptado_permanente ? ' (permanente)' : '') + '</span></div>';
      }
      html += '</td>';
      html += '<td class="pequeno">' + _textoEscapado(a.tipo) + '</td>';
      html += '<td class="mono pequeno nowrap">' + _textoEscapado(a.ip || '-') + '</td>';
      html += '<td class="pequeno"><span class="mono envolver">' + _textoEscapado(a.paquete || '-') + '</span></td>';
      html += '<td class="pequeno mono txt-critico-b">' + _textoEscapado(a.version_instalada || '-') + '</td>';
      html += '<td class="pequeno mono' + (a.version_corregida ? ' txt-exito-b' : ' txt-medio') + '">'
            + _textoEscapado(a.version_corregida || 'sin corrección publicada');
      if (a.comparacion_texto && !a.comparacion_texto.match(/^identic/i)) {
        html += '<div class="pequeno tenue envolver">' + _textoEscapado(a.comparacion_texto) + '</div>';
      }
      if (a.verificacion) {
        html += '<details class="detalle-ayuda mt-8"><summary>Cómo verificarlo en la máquina</summary>'
              + '<div class="pequeno tenue mono envolver mt-8">' + _textoEscapado(a.verificacion) + '</div></details>';
      }
      html += '</td>';
      html += '<td class="nowrap">' + _insigniaRemediacion(a) + '</td>';
      html += '<td class="acciones nowrap">';
      if (puedeRemediar && a.remediacion_id && !a.remediacion_corregida) {
        html += '<button type="button" class="btn pequeno" data-comprobar-remediacion="' + a.remediacion_id + '">Comprobar</button>';
      }
      html += '</td>';
      html += '</tr>';
    });
    html += '</tbody></table></div>';
    return html;
  }

  function _insigniaRemediacion(a) {
    if (!a.remediacion_id) {
      return '<span class="insignia neutro" title="No hay una remediación en seguimiento para este paquete">Sin seguimiento</span>';
    }
    var clase = a.remediacion_corregida ? 'ok' : (a.remediacion_estado === 'esperando_datos' ? 'medio' : 'critico');
    return '<span class="insignia ' + clase + '">' + _textoEscapado(a.remediacion_estado_es) + '</span>';
  }

  // Cuadro inline de activos afectados en la ficha de una amenaza (/amenazas/<id>):
  // mismo endpoint y mismas tarjetas que el modal de la lista, pero siempre visible,
  // sin esperar un clic, y sin el límite de 60 filas que tenía la tabla antigua.
  function cargarGridActivosPagina(threatId, pagina, busqueda) {
    pagina = pagina || 1;
    busqueda = busqueda || '';

    var cuerpo = document.getElementById('grid-cuerpo-activos');
    var paginacion = document.getElementById('grid-paginacion-activos');
    var contador = document.getElementById('grid-contador-activos');
    if (!cuerpo) return;

    cuerpo.innerHTML = '<p class="cargando">Cargando activos afectados…</p>';

    var url = '/amenazas/activos-afectados/' + threatId + '?pagina=' + pagina;
    if (busqueda) url += '&buscar=' + encodeURIComponent(busqueda);

    fetch(url)
      .then(function(resp) {
        if (!resp.ok) throw new Error('Error al cargar');
        return resp.json();
      })
      .then(function(datos) {
        gridActivosEstado.threatId = threatId;
        gridActivosEstado.paginaActual = datos.pagina;
        gridActivosEstado.busqueda = busqueda;

        if (datos.activos.length === 0 && datos.total === 0) {
          cuerpo.innerHTML = '<p>No hay activos afectados confirmados.</p>';
          paginacion.classList.add('oculto');
          contador.textContent = '';
          return;
        }

        contador.textContent = datos.total + (datos.total === 1 ? ' activo afectado' : ' activos afectados');

        if (datos.activos.length === 0) {
          cuerpo.innerHTML = '<p>No hay resultados en esta página.</p>';
          paginacion.classList.remove('oculto');
        } else {
          cuerpo.innerHTML = _tarjetasActivos(datos.activos, datos.puede_remediar);

          if (datos.total > datos.por_pagina) {
            paginacion.classList.remove('oculto');
            document.getElementById('grid-anterior').disabled = datos.pagina <= 1;
            document.getElementById('grid-siguiente').disabled = datos.pagina >= datos.max_paginas;
            document.getElementById('grid-info-pagina').textContent = 'Página ' + datos.pagina + ' de ' + datos.max_paginas + ' (' + datos.total + ' activos)';
          } else {
            paginacion.classList.add('oculto');
          }
        }
      })
      .catch(function(err) {
        cuerpo.innerHTML = '<p class="error">Error al cargar los activos: ' + err.message + '</p>';
        paginacion.classList.add('oculto');
      });
  }

  // Genérica: la usan tanto el modal de la lista de Amenazas como el cuadro inline de
  // la ficha de una amenaza. «alRecargar» es lo que hay que repetir para reflejar el
  // nuevo estado (más sencillo y fiable que mutar solo esta tarjeta).
  function comprobarRemediacion(threatId, remediacionId, boton, alRecargar) {
    var csrf = document.body.getAttribute('data-csrf');
    boton.disabled = true;
    var textoOriginal = boton.textContent;
    boton.textContent = 'Comprobando…';
    var datos = new FormData();
    datos.append('csrf', csrf);
    fetch('/amenazas/activos-afectados/' + threatId + '/comprobar/' + remediacionId, {
      method: 'POST', body: datos, credentials: 'same-origin'
    })
      .then(function(resp) { return resp.json().then(function(j) { return { ok: resp.ok, datos: j }; }); })
      .then(function(r) {
        if (!r.ok) {
          boton.disabled = false;
          boton.textContent = textoOriginal;
          window.alert(r.datos.error || 'No se pudo comprobar la remediación.');
          return;
        }
        alRecargar();
      })
      .catch(function() {
        boton.disabled = false;
        boton.textContent = textoOriginal;
        window.alert('No se pudo comprobar la remediación: sin conexión con el servidor.');
      });
  }

  // Los nombres de activo, el tipo y el paquete proceden del inventario (OCS Inventory
  // o, con el adaptador CSV, de cualquier fuente externa) y se insertan con innerHTML:
  // sin este escapado, un nombre de activo con «<script>» en una fuente de inventario
  // hostil o mal depurada se ejecutaría en el navegador de quien abre el modal.
  function _textoEscapado(texto) {
    var div = document.createElement('div');
    div.textContent = texto == null ? '' : String(texto);
    return div.innerHTML;
  }

  function mostrarActivosAfectados(threatId, cveText) {
    var modal = document.getElementById('modal-activos-afectados');
    var buscarInput = document.getElementById('modal-buscar-activos');
    var btnExportar = document.getElementById('btn-exportar-activos');

    modalActivosEstado.threatId = threatId;
    modalActivosEstado.cveText = cveText;
    modalActivosEstado.paginaActual = 1;
    modalActivosEstado.busqueda = '';

    modal.setAttribute('aria-hidden', 'false');
    modal.classList.remove('oculto');

    buscarInput.value = '';
    btnExportar.href = '/amenazas/activos-afectados/' + threatId + '/excel';
    btnExportar.download = 'activos_afectados_' + cveText.replace(/\//g, '_') + '.xlsx';

    cargarActivosAfectados(threatId, 1, '');
  }

  function cerrarModalActivos() {
    var modal = document.getElementById('modal-activos-afectados');
    modal.classList.add('oculto');
    modal.setAttribute('aria-hidden', 'true');
  }

  // Delegación de eventos para botones "Ver activos"
  alCargar(function() {
    document.addEventListener('click', function(ev) {
      var btn = ev.target.closest ? ev.target.closest('.ver-activos-btn') : null;
      if (!btn) return;
      var threatId = btn.getAttribute('data-threat-id');
      var cve = btn.getAttribute('data-cve');
      mostrarActivosAfectados(parseInt(threatId, 10), cve);
    });

    // Botones de cerrar modal
    document.addEventListener('click', function(ev) {
      if (ev.target.closest && ev.target.closest('.btn-cerrar-modal')) {
        cerrarModalActivos();
      }
    });

    // Botón "Comprobar" de cada tarjeta de activo: sirve tanto al modal de la lista de
    // Amenazas como al cuadro inline de la ficha de una amenaza. El contenedor más
    // cercano con «data-threat-id» dice de cuál de los dos es la tarjeta y cómo
    // recargarlo tras comprobar.
    document.addEventListener('click', function(ev) {
      var boton = ev.target.closest ? ev.target.closest('[data-comprobar-remediacion]') : null;
      if (!boton) return;
      var remediacionId = boton.getAttribute('data-comprobar-remediacion');
      var contenedor = boton.closest('[data-threat-id]');
      if (!contenedor) return;
      var threatId = contenedor.getAttribute('data-threat-id');
      if (contenedor.id === 'grid-cuerpo-activos') {
        comprobarRemediacion(threatId, remediacionId, boton, function() {
          cargarGridActivosPagina(threatId, gridActivosEstado.paginaActual, gridActivosEstado.busqueda);
        });
      } else {
        comprobarRemediacion(threatId, remediacionId, boton, function() {
          cargarActivosAfectados(modalActivosEstado.threatId, modalActivosEstado.paginaActual, modalActivosEstado.busqueda);
        });
      }
    });

    // Botones de paginación
    var btnAnterior = document.getElementById('modal-anterior');
    var btnSiguiente = document.getElementById('modal-siguiente');

    if (btnAnterior) {
      btnAnterior.addEventListener('click', function() {
        if (modalActivosEstado.paginaActual > 1) {
          cargarActivosAfectados(modalActivosEstado.threatId, modalActivosEstado.paginaActual - 1, modalActivosEstado.busqueda);
        }
      });
    }

    if (btnSiguiente) {
      btnSiguiente.addEventListener('click', function() {
        cargarActivosAfectados(modalActivosEstado.threatId, modalActivosEstado.paginaActual + 1, modalActivosEstado.busqueda);
      });
    }

    // Búsqueda en modal
    var buscarInput = document.getElementById('modal-buscar-activos');
    if (buscarInput) {
      var buscarTimeout;
      buscarInput.addEventListener('input', function() {
        clearTimeout(buscarTimeout);
        buscarTimeout = setTimeout(function() {
          modalActivosEstado.busqueda = buscarInput.value;
          cargarActivosAfectados(modalActivosEstado.threatId, 1, modalActivosEstado.busqueda);
        }, 300);
      });
    }
  });

  // Cerrar modal al presionar ESC
  alCargar(function() {
    document.addEventListener('keydown', function(e) {
      if (e.key === 'Escape') {
        var modal = document.getElementById('modal-activos-afectados');
        if (modal && !modal.classList.contains('oculto')) {
          cerrarModalActivos();
        }
      }
    });
  });

  // Cuadro inline de activos afectados en la ficha de una amenaza: se carga solo, sin
  // esperar ningún clic, en cuanto la página tiene el contenedor.
  alCargar(function() {
    var contenedor = document.getElementById('grid-cuerpo-activos');
    if (!contenedor) return;
    var threatId = contenedor.getAttribute('data-threat-id');

    cargarGridActivosPagina(threatId, 1, '');

    var btnAnterior = document.getElementById('grid-anterior');
    var btnSiguiente = document.getElementById('grid-siguiente');
    if (btnAnterior) {
      btnAnterior.addEventListener('click', function() {
        if (gridActivosEstado.paginaActual > 1) {
          cargarGridActivosPagina(threatId, gridActivosEstado.paginaActual - 1, gridActivosEstado.busqueda);
        }
      });
    }
    if (btnSiguiente) {
      btnSiguiente.addEventListener('click', function() {
        cargarGridActivosPagina(threatId, gridActivosEstado.paginaActual + 1, gridActivosEstado.busqueda);
      });
    }

    var buscarInput = document.getElementById('grid-buscar-activos');
    if (buscarInput) {
      var buscarTimeout;
      buscarInput.addEventListener('input', function() {
        clearTimeout(buscarTimeout);
        buscarTimeout = setTimeout(function() {
          cargarGridActivosPagina(threatId, 1, buscarInput.value);
        }, 300);
      });
    }
  });

})();

// Personalizar qué bloques se ven en el Panel de estado (2026-11-16): preferencia
// solo de este navegador, igual que la paleta de colores (sin cambio de servidor ni
// de base de datos). Sin JavaScript, las casillas no existen y se ven todos los
// bloques: es el comportamiento de siempre.
(function () {
  "use strict";

  function alCargar(fn) {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", fn);
    } else {
      fn();
    }
  }

  var CLAVE_ALMACENAMIENTO = "panel_widgets_ocultos";

  function widgetsOcultos() {
    try {
      var bruto = window.localStorage.getItem(CLAVE_ALMACENAMIENTO);
      return bruto ? JSON.parse(bruto) : [];
    } catch (e) {
      return [];
    }
  }

  function guardarWidgetsOcultos(lista) {
    try {
      window.localStorage.setItem(CLAVE_ALMACENAMIENTO, JSON.stringify(lista));
    } catch (e) { /* sin localStorage: la preferencia no persiste, pero no rompe nada */ }
  }

  function aplicarVisibilidad() {
    var ocultos = widgetsOcultos();
    document.querySelectorAll("[data-widget]").forEach(function (el) {
      var id = el.getAttribute("data-widget");
      el.classList.toggle("widget-oculto", ocultos.indexOf(id) !== -1);
    });
    document.querySelectorAll("[data-widget-casilla]").forEach(function (casilla) {
      casilla.checked = ocultos.indexOf(casilla.getAttribute("data-widget-casilla")) === -1;
    });
  }

  alCargar(function () {
    var contenedor = document.querySelector("[data-personalizar-panel]");
    if (!contenedor) return;
    aplicarVisibilidad();
    contenedor.addEventListener("change", function (ev) {
      var casilla = ev.target.closest ? ev.target.closest("[data-widget-casilla]") : null;
      if (!casilla) return;
      var id = casilla.getAttribute("data-widget-casilla");
      var ocultos = widgetsOcultos();
      var pos = ocultos.indexOf(id);
      if (casilla.checked && pos !== -1) {
        ocultos.splice(pos, 1);
      } else if (!casilla.checked && pos === -1) {
        ocultos.push(id);
      }
      guardarWidgetsOcultos(ocultos);
      aplicarVisibilidad();
    });
  });
})();

// Paginación de cuadro en el cliente, por GRUPOS completos de filas (2026-11-16):
// para tablas renderizadas por el servidor con `rowspan`, donde no se puede cortar a la
// mitad un grupo sin romper la tabla. Cada <tr> del grupo lleva el mismo
// «data-grupo="N"»; la tabla lleva «data-paginar-grupos» y «data-grupos-por-pagina»; el
// bloque de controles lleva «data-paginar-de="<id de la tabla>"» con sus dos botones
// («data-pag-anterior», «data-pag-siguiente») y el texto de información
// («data-pag-info»). Sin JavaScript se ven todas las filas, no hay nada roto.
(function () {
  "use strict";

  function alCargar(fn) {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", fn);
    } else {
      fn();
    }
  }

  alCargar(function () {
    document.querySelectorAll("table[data-paginar-grupos]").forEach(function (tabla) {
      var controles = document.querySelector('[data-paginar-de="' + tabla.id + '"]');
      if (!controles) return;

      var filas = Array.prototype.slice.call(tabla.querySelectorAll("tbody tr[data-grupo]"));
      var grupos = [];
      filas.forEach(function (fila) {
        var g = fila.getAttribute("data-grupo");
        if (grupos.indexOf(g) === -1) grupos.push(g);
      });
      var porPagina = parseInt(tabla.getAttribute("data-grupos-por-pagina"), 10) || 10;
      var totalPaginas = Math.max(1, Math.ceil(grupos.length / porPagina));
      var pagina = 1;

      var btnAnterior = controles.querySelector("[data-pag-anterior]");
      var btnSiguiente = controles.querySelector("[data-pag-siguiente]");
      var info = controles.querySelector("[data-pag-info]");

      function mostrar() {
        var desde = (pagina - 1) * porPagina;
        var hasta = desde + porPagina;
        var gruposVisibles = grupos.slice(desde, hasta);
        filas.forEach(function (fila) {
          fila.hidden = gruposVisibles.indexOf(fila.getAttribute("data-grupo")) === -1;
        });
        if (btnAnterior) btnAnterior.disabled = pagina <= 1;
        if (btnSiguiente) btnSiguiente.disabled = pagina >= totalPaginas;
        if (info) {
          var unidad = tabla.getAttribute("data-unidad-grupo") || "fila";
          var unidadPlural = tabla.getAttribute("data-unidad-grupo-plural") || (unidad + "s");
          info.textContent = "Página " + pagina + " de " + totalPaginas
                            + " (" + grupos.length + " " + (grupos.length === 1 ? unidad : unidadPlural) + ")";
        }
        if (totalPaginas <= 1) controles.classList.add("oculto");
      }

      if (btnAnterior) {
        btnAnterior.addEventListener("click", function () {
          if (pagina > 1) { pagina -= 1; mostrar(); }
        });
      }
      if (btnSiguiente) {
        btnSiguiente.addEventListener("click", function () {
          if (pagina < totalPaginas) { pagina += 1; mostrar(); }
        });
      }

      mostrar();
    });
  });
})();

