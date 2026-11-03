/*
 * Accessibility fixes for the Furo theme and the Sphinx extensions it's used
 * with (WCAG 2.2). Each part names the success criterion it serves. These are
 * things Furo, Sphinx and the extensions have no option for. Re-check them
 * when upgrading any of those.
 */
(function () {
  "use strict";

  /* Visually hidden live region for short status messages. 4.1.3 Status Messages (AA) */
  let liveRegion = null;
  function announce(message) {
    if (!liveRegion) {
      liveRegion = document.createElement("div");
      liveRegion.className = "visually-hidden";
      liveRegion.setAttribute("role", "status");
      document.body.appendChild(liveRegion);
    }
    liveRegion.textContent = "";
    // Change the text on the next frame, so the same message is announced twice in a row
    window.requestAnimationFrame(() => {
      liveRegion.textContent = message;
    });
  }

  /* Text of an element, without its permalink and "[source]" link */
  function textOf(el) {
    const copy = el.cloneNode(true);
    copy.querySelectorAll(".headerlink, .viewcode-link").forEach((n) => n.remove());
    return copy.textContent.replace(/\s+/g, " ").trim();
  }

  /*
   * Code blocks and tables that scroll sideways must be reachable by keyboard,
   * so their content can be scrolled. 2.1.1 Keyboard (A)
   */
  function updateScrollables() {
    const items = document.querySelectorAll("div.highlight > pre, .table-wrapper");
    let codeCount = 0;
    let tableCount = 0;
    items.forEach((el) => {
      // Number each block, so every region on the page has its own name
      const isCode = el.matches("pre");
      const number = isCode ? ++codeCount : ++tableCount;
      const scrolls = el.scrollWidth > el.clientWidth + 1;
      if (scrolls && !el.hasAttribute("tabindex")) {
        el.setAttribute("tabindex", "0");
        el.setAttribute("role", "region");
        el.setAttribute(
          "aria-label",
          `${isCode ? "Code block" : "Table"} ${number}, scrolls sideways`,
        );
        el.dataset.a11yScroll = "";
      } else if (!scrolls && "a11yScroll" in el.dataset) {
        el.removeAttribute("tabindex");
        el.removeAttribute("role");
        el.removeAttribute("aria-label");
        delete el.dataset.a11yScroll;
      }
    });
  }

  /*
   * Furo's mobile drawers (site navigation and "On this page"). Their toggles
   * are labels for hidden checkboxes, so they can't be reached by keyboard,
   * and a closed drawer's links stay in the tab order off-screen.
   * 2.1.1 Keyboard (A), 2.4.3 Focus Order (A), 4.1.2 Name, Role, Value (A)
   */
  const drawers = [];
  let openDrawer = null;
  let inertByUs = [];

  function isOffCanvas(drawer) {
    return getComputedStyle(drawer).position === "fixed";
  }

  function releaseBackground() {
    inertByUs.forEach((el) => {
      el.inert = false;
    });
    inertByUs = [];
  }

  /* While a drawer covers the page, make everything behind it inert, so focus
     can't move under the drawer or the dark overlay. 2.4.11 Focus Not Obscured */
  function inertBackground(drawer) {
    releaseBackground();
    let node = drawer;
    while (node && node !== document.body) {
      const parent = node.parentElement;
      for (const sibling of parent.children) {
        if (sibling === node || sibling.inert) continue;
        if (sibling.matches("script, svg, input.sidebar-toggle, label.overlay")) continue;
        sibling.inert = true;
        inertByUs.push(sibling);
      }
      node = parent;
    }
  }

  function updateDrawers(moveFocus) {
    openDrawer = null;
    drawers.forEach((d) => {
      const offCanvas = isOffCanvas(d.drawer);
      const open = d.checkbox.checked && offCanvas;
      d.toggles.forEach((toggle) => toggle.setAttribute("aria-expanded", String(open)));
      d.drawer.inert = offCanvas && !open;
      d.close.hidden = !open;
      if (open) openDrawer = d;
    });
    if (openDrawer) {
      inertBackground(openDrawer.drawer);
      if (moveFocus) openDrawer.close.focus();
    } else {
      releaseBackground();
    }
  }

  function closeDrawer(d) {
    d.checkbox.checked = false;
    updateDrawers(false);
    // Return focus to the visible toggle that opens this drawer
    const target = d.toggles.find((toggle) => toggle.offsetParent !== null);
    if (target) target.focus();
  }

  function setupDrawer(checkboxId, drawerSelector, toggleSelector, name) {
    const checkbox = document.getElementById(checkboxId);
    const drawer = document.querySelector(drawerSelector);
    const labels = Array.from(document.querySelectorAll(toggleSelector));
    if (!checkbox || !drawer || labels.length === 0) return;

    drawer.id = drawer.id || `a11y-${checkboxId.replace(/_/g, "")}-drawer`;
    const close = document.createElement("button");
    close.type = "button";
    close.className = "a11y-drawer-close";
    close.textContent = `Close ${name}`;
    close.hidden = true;
    drawer.prepend(close);

    // Swap each toggle <label> for a real <button> with the same classes, so
    // Furo's styles still apply. (A <label> isn't allowed role="button".)
    const buttons = labels.map((label) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = label.className;
      button.innerHTML = label.innerHTML;
      button.setAttribute("aria-controls", drawer.id);
      button.setAttribute("aria-label", name.charAt(0).toUpperCase() + name.slice(1));
      button.addEventListener("click", (event) => {
        checkbox.checked = !checkbox.checked;
        // Move focus into the drawer when opened from the keyboard (detail is 0)
        updateDrawers(event.detail === 0);
      });
      label.replaceWith(button);
      return button;
    });
    const d = { checkbox, drawer, toggles: buttons, close };
    close.addEventListener("click", () => closeDrawer(d));
    checkbox.addEventListener("change", () => updateDrawers(false));
    drawers.push(d);
  }

  /*
   * Furo's sticky mobile header and floating "Back to top" button can cover
   * the element that has focus, mostly when tabbing backwards. Browsers don't
   * apply scroll-padding when deciding whether a focused element is already in
   * view, so nudge the page down when something covers it.
   * 2.4.11 Focus Not Obscured (Minimum, AA), 2.4.12 (Enhanced, AAA)
   */
  function coveredTop(rect) {
    let limit = 0;
    document.querySelectorAll(".mobile-header, .back-to-top").forEach((bar) => {
      const cs = getComputedStyle(bar);
      if (cs.display === "none" || cs.visibility === "hidden") return;
      if (cs.position !== "fixed" && cs.position !== "sticky") return;
      const r = bar.getBoundingClientRect();
      if (r.height === 0 || r.bottom <= 0) return;
      if (r.right <= rect.left || r.left >= rect.right) return;
      limit = Math.max(limit, r.bottom);
    });
    return limit;
  }
  function keepFocusClear(el, tries = 3) {
    if (!el.isConnected || document.activeElement !== el) return;
    const rect = el.getBoundingClientRect();
    const limit = coveredTop(rect);
    const gap = 8;
    if (limit > 0 && rect.top < limit + gap) {
      window.scrollBy({ top: rect.top - limit - gap, behavior: "instant" });
      // Scrolling up makes Furo show "Back to top", which may now cover the
      // element, so check again once it has appeared
      if (tries > 1) window.setTimeout(() => keepFocusClear(el, tries - 1), 50);
    }
  }
  function watchFocusObscured() {
    document.addEventListener("focusin", (event) => {
      const el = event.target;
      if (!(el instanceof Element)) return;
      // Things that are themselves fixed or in a drawer can't be scrolled clear
      if (el.closest(".mobile-header, .back-to-top, .sidebar-drawer, .toc-drawer")) return;
      // Check now, and again once any smooth scroll to the element has finished
      window.requestAnimationFrame(() => keepFocusClear(el));
      const onScrollEnd = () => keepFocusClear(el);
      window.addEventListener("scrollend", onScrollEnd, { once: true });
      // Don't react to a later scroll the reader makes themselves
      window.setTimeout(() => window.removeEventListener("scrollend", onScrollEnd), 1000);
    });
  }

  /* Sidebar captions ("Getting started", ...) have role="heading" but no level.
     docs/_templates/sidebar/navigation.html adds aria-level; this covers any
     caption it missed. 4.1.2 Name, Role, Value (A) */
  function fixCaptions() {
    document.querySelectorAll('[role="heading"]:not([aria-level])').forEach((el) => {
      el.setAttribute("aria-level", "2");
    });
  }

  /* Name the two sidebars, so they can be told apart. Best practice (landmark-unique) */
  function labelLandmarks() {
    const left = document.querySelector(".sidebar-drawer");
    const right = document.querySelector(".toc-drawer");
    if (left) left.setAttribute("aria-label", "Site sidebar");
    if (right) right.setAttribute("aria-label", "Page contents sidebar");
    const toc = document.querySelector(".toc-tree-container");
    if (toc) {
      toc.setAttribute("role", "navigation");
      toc.setAttribute("aria-label", "On this page");
    }
    // The theme toggle and "View this page" link sit outside every landmark
    const tools = document.querySelector(".content-icon-container");
    if (tools) {
      tools.setAttribute("role", "region");
      tools.setAttribute("aria-label", "Page tools");
    }
  }

  /* Tell screen readers which colour theme is in use after it's changed.
     4.1.2 Name, Role, Value (A) */
  function updateThemeToggle() {
    const names = {
      auto: "auto (follows your system setting)",
      light: "light",
      dark: "dark",
    };
    const theme = document.body.dataset.theme || "auto";
    const label = `Change color theme. Current theme: ${names[theme] || theme}`;
    document.querySelectorAll(".theme-toggle").forEach((button) => {
      button.setAttribute("aria-label", label);
    });
    return names[theme] || theme;
  }
  function watchThemeToggle() {
    updateThemeToggle();
    new MutationObserver(() => {
      const current = updateThemeToggle();
      if (document.activeElement && document.activeElement.matches(".theme-toggle")) {
        announce(`Color theme: ${current}`);
      }
    }).observe(document.body, { attributes: true, attributeFilter: ["data-theme"] });
  }

  /* sphinx-copybutton shows "Copied!" only as a visual tooltip. Announce it.
     4.1.3 Status Messages (AA) */
  function watchCopyButtons() {
    const buttons = document.querySelectorAll("button.copybtn");
    if (buttons.length === 0) return;
    const observer = new MutationObserver((records) => {
      records.forEach((record) => {
        const button = record.target;
        if (button.classList.contains("success")) announce("Copied to clipboard");
      });
    });
    buttons.forEach((b) => observer.observe(b, { attributes: true, attributeFilter: ["class"] }));
  }

  /* sphinx-inline-tabs: give each set of tabs a group name, and link each tab
     to its panel. 1.3.1 Info and Relationships (A), 4.1.2 (A) */
  function labelTabs() {
    document.querySelectorAll(".tab-set").forEach((set, i) => {
      const section = set.closest("section");
      const heading = section && section.querySelector("h1, h2, h3, h4, h5, h6");
      set.setAttribute("role", "group");
      set.setAttribute("aria-label", heading ? `${textOf(heading)}: tabs` : "Tabs");
      set.querySelectorAll(":scope > input").forEach((input, j) => {
        const panel = input.nextElementSibling && input.nextElementSibling.nextElementSibling;
        if (panel && panel.classList.contains("tab-content")) {
          panel.id = panel.id || `a11y-tab-panel-${i}-${j}`;
          input.setAttribute("aria-controls", panel.id);
        }
      });
    });
  }

  /*
   * Give "¶", "[source]" and "[docs]" links names that make sense on their
   * own. 2.4.4 Link Purpose (In Context, A), 2.4.9 Link Purpose (Link Only, AAA)
   */
  function nameLinks() {
    document.querySelectorAll("a.headerlink").forEach((a) => {
      const parent = a.parentElement;
      const text = textOf(parent);
      let kind = "section";
      if (parent.matches("dt") && parent.closest("dl.glossary")) kind = "term";
      else if (parent.matches("dt")) kind = "definition";
      else if (parent.closest(".code-block-caption, figcaption, caption")) kind = "item";
      a.setAttribute("aria-label", `Link to this ${kind}: ${text}`);
    });
    document.querySelectorAll(".viewcode-link").forEach((span) => {
      const a = span.closest("a");
      const dt = span.closest("dt");
      if (a && dt) a.setAttribute("aria-label", `Source code of ${dt.id || textOf(dt)}`);
    });
    document.querySelectorAll("a.viewcode-back").forEach((a) => {
      const name = decodeURIComponent(a.hash.slice(1));
      if (name) a.setAttribute("aria-label", `Documentation for ${name}`);
    });
  }

  /* Python module index: the collapse toggle is a click-only image.
     2.1.1 Keyboard (A), 4.1.2 Name, Role, Value (A) */
  function fixIndexTogglers() {
    document.querySelectorAll("img.toggler").forEach((img) => {
      const row = img.closest("tr");
      const name = row ? textOf(row) : "";
      const update = () => {
        const expanded = !img.src.endsWith("plus.png");
        img.setAttribute("aria-expanded", String(expanded));
      };
      img.setAttribute("role", "button");
      img.setAttribute("tabindex", "0");
      img.setAttribute("alt", `Show or hide the modules in ${name}`);
      img.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          img.click();
        }
      });
      img.addEventListener("click", () => window.setTimeout(update));
      update();
    });
  }

  function init() {
    fixCaptions();
    labelLandmarks();
    labelTabs();
    nameLinks();
    fixIndexTogglers();
    watchThemeToggle();
    watchCopyButtons();
    watchFocusObscured();

    setupDrawer("__navigation", ".sidebar-drawer", "label.nav-overlay-icon", "site navigation");
    setupDrawer("__toc", ".toc-drawer", "label.toc-overlay-icon", "table of contents");
    updateDrawers(false);
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape" && openDrawer) closeDrawer(openDrawer);
    });

    updateScrollables();
    let resizeTimer = null;
    window.addEventListener("resize", () => {
      window.clearTimeout(resizeTimer);
      resizeTimer = window.setTimeout(() => {
        updateScrollables();
        updateDrawers(false);
      }, 100);
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
