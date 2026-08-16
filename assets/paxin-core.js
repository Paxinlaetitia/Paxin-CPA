(function () {
  "use strict";

  const CORE_MARK_PATH = "M8 11h28.5l9 10.5-6.2 7.2-7-8.2H15.8l4.7 5.5h11.8l5.7 6.7-7.2 8.3H20.5l-5.7 12H8l5.8-20h15.3l-4.8-5.6H14.2L8 20.2V11Zm39.8 0H57L43.9 26.2l4.6 5.4L58 20.5h-8.2L38.2 34H31l-6.3 7.3h10.9L46.5 54H58L46.7 40.8l-5.1 6-4.7-5.5L57 17.8V11h-9.2Z";

  function coreMarkup() {
    return `
      <div class="paxin-core__frame">
        <svg class="paxin-core__svg" viewBox="0 0 520 520" focusable="false" aria-hidden="true">
          <circle class="paxin-core__guide" cx="260" cy="260" r="226" />
          <circle class="paxin-core__orbit-line" cx="260" cy="260" r="184" />
          <circle class="paxin-core__orbit-line paxin-core__orbit-line--inner" cx="260" cy="260" r="126" />

          <g class="paxin-core__rotator paxin-core__rotator--outer">
            <path class="paxin-core__arc" d="M260 76 A184 184 0 0 1 419.3 168" />
            <path class="paxin-core__arc paxin-core__arc--quiet" d="M101 352 A184 184 0 0 1 76 260" />
            <circle class="paxin-core__node-halo" cx="260" cy="76" r="12" />
            <circle class="paxin-core__node" cx="260" cy="76" r="4" />
            <circle class="paxin-core__node-halo" cx="444" cy="260" r="10" />
            <circle class="paxin-core__node paxin-core__node--two" cx="444" cy="260" r="3.5" />
            <circle class="paxin-core__node-halo" cx="130" cy="390" r="9" />
            <circle class="paxin-core__node paxin-core__node--three" cx="130" cy="390" r="3" />
          </g>

          <g class="paxin-core__rotator paxin-core__rotator--inner">
            <path class="paxin-core__arc" d="M171 171 A126 126 0 0 1 349 171" />
            <path class="paxin-core__arc paxin-core__arc--quiet" d="M349 349 A126 126 0 0 1 171 349" />
            <circle class="paxin-core__node-halo" cx="171" cy="171" r="9" />
            <circle class="paxin-core__node paxin-core__node--two" cx="171" cy="171" r="3.5" />
            <circle class="paxin-core__node-halo" cx="349" cy="349" r="8" />
            <circle class="paxin-core__node paxin-core__node--quiet paxin-core__node--three" cx="349" cy="349" r="3" />
          </g>

          <g class="paxin-core__heart">
            <circle class="paxin-core__heart-halo" cx="260" cy="260" r="92" />
            <circle class="paxin-core__heart-disc" cx="260" cy="260" r="70" />
            <circle class="paxin-core__heart-edge" cx="260" cy="260" r="58" />
            <g class="paxin-core__mark" transform="translate(206 206) scale(1.68)">
              <path fill="currentColor" d="${CORE_MARK_PATH}" />
            </g>
          </g>
        </svg>
        <span class="paxin-core__label paxin-core__label--instances">Instâncias</span>
        <span class="paxin-core__label paxin-core__label--flows">Fluxos</span>
        <span class="paxin-core__label paxin-core__label--records">Registros</span>
        <span class="paxin-core__caption">Central coordenada</span>
      </div>`;
  }

  function mountCore(root) {
    if (!root || root.dataset.paxinCoreReady === "true") return;
    root.dataset.paxinCoreReady = "true";
    root.innerHTML = coreMarkup();

    const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
    let offscreen = false;

    const refreshState = () => {
      root.classList.toggle("is-reduced", reducedMotion.matches);
      root.classList.toggle("is-paused", document.hidden || offscreen);
    };

    document.addEventListener("visibilitychange", refreshState, { passive: true });
    if (typeof reducedMotion.addEventListener === "function") {
      reducedMotion.addEventListener("change", refreshState);
    }

    if ("IntersectionObserver" in window) {
      const observer = new IntersectionObserver((entries) => {
        offscreen = !entries[0]?.isIntersecting;
        refreshState();
      }, { threshold: 0.02 });
      observer.observe(root);
    }

    refreshState();
  }

  function boot() {
    const authHero = document.querySelector(".auth-hero");
    if (authHero && !authHero.querySelector("[data-paxin-core]")) {
      const appCore = document.createElement("div");
      appCore.className = "paxin-core paxin-core--app";
      appCore.dataset.paxinCore = "";
      appCore.setAttribute("aria-hidden", "true");
      authHero.insertBefore(appCore, authHero.querySelector(".auth-hero-mid"));
    }

    document.querySelectorAll("[data-paxin-core]").forEach(mountCore);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot, { once: true });
  } else {
    boot();
  }
})();
