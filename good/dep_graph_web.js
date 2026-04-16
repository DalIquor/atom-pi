// dep_graph_web.js
// ============================================================
// Browser‑safe dependency graph renderer for AtomPI wrappers
// ============================================================
//
// Wrappers must define:
//   wrapper.name
//   wrapper.atoms = [ "wadd", "wxor", ... ]
//
// This produces the same ASCII tree as the Node version,
// but works entirely in the browser.
// ============================================================

(function(global) {

  function renderDependencyGraph(wrapper) {
    const name  = wrapper.name  || "<unnamed>";
    const atoms = wrapper.atoms || [];

    let out = "";
    out += `${name}\n`;
    out += `  └─ COMPRESS\n`;

    const last = atoms.length - 1;
    atoms.forEach((atom, i) => {
      const branch = (i === last) ? "└─" : "├─";
      out += `       ${branch} ${atom}\n`;
    });

    return out;
  }

  // expose globally
  global.renderDependencyGraph = renderDependencyGraph;

})(window);
