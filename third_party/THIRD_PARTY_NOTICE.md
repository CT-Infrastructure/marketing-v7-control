# Renderer provenance and notices

`mermaid-runtime.js` contains the actual Mermaid flowchart parser and Dagre layout modules bundled from the preinstalled Gradio frontend assets in this build environment. The document application/preloader glue was locally stubbed to load those modules offline; Mermaid graph parsing/layout/rendering was not replaced by hand-drawn graphics. Its exact hash is recorded in the render validation report. This is a documentation-only bundle, not a recommended production frontend.

Mermaid is distributed by its project under the MIT license; its rendering dependencies have their own upstream notices and licenses. Preserve the comments/notices present in the bundled source and review the applicable upstream Mermaid, Dagre and D3 dependency licenses before redistributing a modified renderer. The editable diagrams themselves do not require this particular bundle: the official Mermaid CLI or an approved compatible Mermaid renderer can consume them. No proprietary font files or credentials are included.

Upstream project references: https://github.com/mermaid-js/mermaid ; https://github.com/mermaid-js/mermaid-cli ; https://github.com/dagrejs/dagre ; https://github.com/d3 .
