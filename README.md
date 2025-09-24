# MermaidJsWebView — Total Commander Lister

A tiny, modern Mermaid.js viewer for **Total Commander (64-bit)**.
Renders diagrams either **locally via the Mermaid CLI (`mmdc.bat`)** or **directly in WebView using the Mermaid CDN** depending on the build.
Powered by **WebView2** — no Qt or zlib required.

---

## Why this plugin?

* 🪶 **Small footprint** – just a WLX DLL, a config INI, and `WebView2Loader.dll`.
* ⚡ **Fast preview** – render locally with the Mermaid CLI (`mmdc.bat`).
* 🔧 **Configurable** – choose **SVG** or **PNG**, and configure the CLI path.
* 📋 **Copy to clipboard** – **Ctrl+C** copies **SVG text** or a **PNG bitmap** from Lister.

---

## Requirements

* **Total Commander 64-bit** (Lister/WLX plugin support).
* **Microsoft Edge WebView2 Runtime** (evergreen).
  👉 Download from Microsoft: <https://developer.microsoft.com/en-us/microsoft-edge/webview2/#download>
* **Mermaid CLI** (`mmdc.bat`) – required for the `_local` release. Shipped with the package and requires **Node.js** plus Chromium via Puppeteer.
* The `_web` release renders using the Mermaid CDN and does **not** require the CLI (or Node.js).

---

## Installation

1. Download the latest **release ZIP** from this repository’s **Releases** page.
2. Open the ZIP in **Total Commander**.
3. TC will offer **“Install plugin”** → click **OK** and follow the prompts.

That’s it. The plugin will be installed to your TC plugins folder.

---

## Release variants

Two ZIPs are produced for every release:

* **`MermaidJsWebView_local.zip`** – matches the original behaviour. Uses the bundled Mermaid CLI for offline rendering and ships the local `third_party/mermaidjs` payload.
* **`MermaidJsWebView_web.zip`** – a lighter package. It renders diagrams inside the WebView using the Mermaid CDN plus `save-svg-as-png` for downloads, so no CLI (or Node.js) is required. Internet access is needed for the CDN assets.

Pick the variant that best suits your environment.

---

## Usage

* Select a Mermaid file (e.g. `.mmd`, `.mermaid`) and press **F3** (Lister).
* `_local` build: renders diagrams via the bundled `mmdc.bat`. Configure `[mmdc]` in the INI if you need explicit paths or timeouts.
* `_web` build: renders diagrams in the embedded WebView by streaming Mermaid from the CDN. Refresh and Save remain available, and SVG/PNG downloads happen in-browser.
* **Ctrl+C** inside the preview:
  * **SVG mode:** copies the SVG markup as text.
  * **PNG mode:** copies a PNG bitmap.

---

## Configuration

**INI path (after install):**
`%COMMANDER_PATH%\Plugins\wlx\MermaidJsWebView\mermaidjswebview.ini`

Default contents:

```ini
; Rendering is performed locally via Mermaid CLI (mmdc.bat).

[render]
; "svg" (default) or "png"
prefer=svg

[mmdc]
; If empty, the plugin auto-tries "mmdc.bat" placed next to the plugin DLL.
; You can also point to a custom CLI path here.
cli=mmdc.bat

; Kill the CLI process if it hangs (milliseconds)
timeout_ms=8000

[detect]
; Detect string reported to Total Commander during installation.
string=EXT="MERMAID" | EXT="MM"

[debug]
; Optional log file path (defaults next to the plugin DLL)
; Set log_enabled=0 to disable logging entirely
log_enabled=1
log=
```

### SVG vs PNG

* **SVG (default):** crisp, scalable, selectable text, small output.
* **PNG:** universal compatibility; larger bitmap output.

---

## Data handling

* `_local` build — all rendering happens locally via `mmdc.bat`; the plugin does not perform any network requests beyond what the CLI needs to launch Chromium.
* `_web` build — Mermaid assets are loaded from <https://cdn.jsdelivr.net> and `save-svg-as-png` from <https://cdnjs.cloudflare.com>; no CLI is invoked.

---

## Troubleshooting

* **Blank panel / “Render error”**

  * Verify the `mmdc.bat` path in `[mmdc]` is correct.
* **Logging** – keep `[debug] log_enabled=1` (default) and inspect `mermaidjswebview.log` (or a custom `[debug] log=` path) for details.
* **“WebView2 Runtime not found”**

  * Install the **WebView2 Runtime (Evergreen)** from Microsoft (link above) and retry.
* **Mermaid CLI fails**

  * Ensure Node.js, Chromium dependencies, and the Mermaid CLI are installed.
  * Ensure `mmdc.bat` is present (or set `[mmdc] cli=...`).
  * Increase `[mmdc] timeout_ms` for large diagrams.
* **Copy to clipboard doesn’t work**

  * Click inside the preview to focus, then press **Ctrl+C**.

---

## Development

* License: **MIT** — contributions welcome.
* Toolchain: **MSVC x64**, **CMake + Ninja**.
* Dependencies:

  * Headers: `WebView2.h` from the WebView2 SDK.
  * Runtime: `WebView2Loader.dll` is **loaded dynamically** (no import library needed).

Minimal CMake outline:

```cmake
add_library(MermaidJsWebView SHARED src/mermaidjs_wlx_ev2.cpp)
target_include_directories(MermaidJsWebView PRIVATE third_party/WebView2/build/native/include)
target_link_libraries(MermaidJsWebView PRIVATE shlwapi)
set_target_properties(MermaidJsWebView PROPERTIES OUTPUT_NAME "MermaidJsWebView" SUFFIX ".wlx64")
```

---

## Acknowledgements

* [Mermaid](https://mermaid.js.org/) – the rendering engine.
* Microsoft **WebView2** – lightweight HTML rendering inside Lister.
* **Total Commander** – for the flexible Lister plugin interface.
