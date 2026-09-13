#ifndef C_HTTP_TPL_H
#define C_HTTP_TPL_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>

#include "c_http.h"

/* ============================================================
 * Template runtime (ctmpl)
 *
 * Writer/escaper used by components generated from .thtml files
 * (see tools/ctmpl.c) and by hand-written "code-only" components.
 * The design follows Go's templ: components are plain functions
 *
 *     void tpl_hello(TplOut *out, const char *name)
 *     {
 *         tpl_lit(out, "<div>");
 *         tpl_esc(out, name);
 *         tpl_lit(out, "</div>");
 *     }
 *
 * that write into a growable buffer. Rendering never truncates and
 * never aborts: on allocation failure the FAILED flag is set, all
 * further writes become no-ops and the caller sees tpl_ok() == false
 * (analogous to templ's Render returning an error).
 *
 * ctx is the templ "context" analog: an opaque per-render pointer
 * (e.g. the request, a theme, a user session) never touched here.
 *
 * The arena is scratch memory for the value helpers (tpl_int,
 * tpl_fmt, tpl_url). Strings returned by them live until
 * tpl_out_free() — always long enough for one render.
 * ============================================================ */

/* Render-once handle (templ's templ.NewOnceHandle analog).
 * Declare one per logical dependency (a static in the generated .c
 * via the "once <name>" directive, or your own variable):
 *
 *     static TplOnce my_handle = {0};
 *
 * The handle itself is just an identity token — the fired-state is
 * tracked PER RENDER inside the TplOut (thread-safe: two workers
 * with their own TplOut never share once state). name is used for
 * diagnostics only. */
/* Typed attribute values (templ's templ.SafeURL/SafeCSS analogs):
 * ctmpl emits tpl_attr_url/tpl_attr_css for URL and style attribute
 * expressions, and those ONLY accept these types — so the C
 * compiler forces an explicit tpl_url()/tpl_safe_url() (or
 * tpl_css()/tpl_css_safe()) choice in the template. The struct is
 * transparent; construct one only via the functions above. */
typedef struct {
    const char *s;
} TplUrl;

typedef struct {
    const char *s;
} TplCss;

typedef struct {
    const char *name; /* optional, for debugging */
} TplOnce;

typedef struct {
    /* Growable output buffer (heap; NULL until the first write).
     * NOT NUL-terminated — use tpl_str() for a C string view. */
    char *data;
    size_t len;
    size_t cap;
    /* Sticky failure flag (out of memory). Check with tpl_ok() and
     * turn it into a 500 at the handler level; rendering continues
     * as a no-op so the rest of the component still "runs". */
    bool failed;
    /* User context — see the block comment above. */
    void *ctx;
    /* Opaque scratch arena (TplArena *) — owned, freed in
     * tpl_out_free(). */
    void *arena;

    /* ---- fragment rendering (tpl_frag_select) — internal ---- */
    /* Selected fragment name (NULL = render everything). */
    const char *frag_sel;
    /* Nesting depth of open fragment blocks while a fragment is
     * selected, and the depth of the innerst MATCHING open
     * fragment (0 = currently discarding). */
    int frag_depth;
    int frag_match;

    /* ---- once registry — internal (tpl_once_begin) ---- */
    /* Handles that already rendered in THIS render (arena-owned
     * array); a fresh TplOut starts empty, so once state is
     * per-render like templ's context-bound OnceHandler. */
    TplOnce **once_fired;
    size_t once_fired_count;
} TplOut;

/* Child content passed to a component (templ's children analog).
 * A component that renders child content takes a final
 * "TplChildren *children" parameter; callers use the .thtml syntax
 *     @layout(args) { <p>child markup</p> }
 * and ctmpl generates a static render function plus this struct.
 * fn renders the block into out; data is caller-controlled scratch
 * (ctmpl passes NULL — carry dynamic state through out->ctx instead,
 * the same role templ's context plays). */
typedef struct {
    void (*fn)(TplOut *out, void *data);
    void *data;
} TplChildren;

/* ---- writing (generated code uses these) ---- */

/* Writes a literal (raw, NOT escaped). NULL writes nothing. */
void tpl_lit(TplOut *out, const char *s);
/* Same, with an explicit length (may contain NULs). */
void tpl_lit_n(TplOut *out, const char *s, size_t len);

/* Escape hatch for trusted HTML (templ's templ.Raw): raw write,
 * identical to tpl_lit. NEVER pass user input here. */
void tpl_raw(TplOut *out, const char *s);
void tpl_raw_n(TplOut *out, const char *s, size_t len);

/* Writes s HTML-escaped for TEXT context (& < > " ' -> entities).
 * NULL is tolerated and writes nothing. */
void tpl_esc(TplOut *out, const char *s);

/* Writes s escaped for a double-quoted ATTRIBUTE value context
 * (adds no quotes — the generator emits those as literals). */
void tpl_attr(TplOut *out, const char *s);

/* ---- value helpers (return arena strings, valid until
 * tpl_out_free() — safe because a component writes each value
 * exactly once, immediately) ---- */

/* Formats value as a decimal string. */
const char *tpl_int(TplOut *out, long long value);

/* printf-style formatting. Returns "" on a NULL/failed format. */
const char *tpl_fmt(TplOut *out, const char *fmt, ...);

/* URL sanitizer for href/src style attributes (templ's templ.URL):
 * allows http, https, mailto and relative URLs (no scheme); rejects
 * control characters, whitespace and other schemes (javascript:)
 * by returning "about:invalid#ctmpl".
 *
 * NOTE: returns TplUrl, not a string — href/src style attribute
 * expressions REQUIRE it (ctmpl emits tpl_attr_url, which only
 * accepts TplUrl), so the C compiler forces the sanitization
 * choice: tpl_url() here, or tpl_safe_url() below for the
 * deliberate bypass. */
TplUrl tpl_url(TplOut *out, const char *url);

/* Marks a URL as trusted (templ's templ.SafeURL): returned
 * verbatim, NO scheme sanitization. Use only for URLs you control
 * — this is the documented escape hatch, visible in the template. */
TplUrl tpl_safe_url(const char *url);

/* Writes a URL attribute value, HTML-attribute escaped. Generated
 * by ctmpl for href/src/action/formaction/poster/cite/background
 * attribute expressions. */
void tpl_attr_url(TplOut *out, TplUrl url);

/* ---- CSS attribute values (style=...) ---- */

/* CSS declaration sanitizer for style attributes (templ's
 * templ.SanitizeCSS analog): splits declarations, validates the
 * property name, and replaces a value containing dangerous
 * patterns (javascript:/vbscript:/expression(/behavior:/@import,
 * '<'/'>' or control characters, url(...) with an unexpected
 * scheme) with "zctmplUnsafeCSS". Safe input is returned as the
 * same pointer (zero copy). */
TplCss tpl_css(TplOut *out, const char *declarations);

/* Marks CSS declarations as trusted — verbatim, NO sanitization
 * (still attribute-escaped when written). The escape hatch. */
TplCss tpl_css_safe(const char *declarations);

/* Writes a style attribute value, HTML-attribute escaped.
 * Generated by ctmpl for style= attribute expressions. */
void tpl_attr_css(TplOut *out, TplCss css);

/* ---- buffer access ---- */

/* false = an allocation failed during rendering. */
bool tpl_ok(const TplOut *out);

/* NUL-terminated view of the output ("" for an empty buffer). Valid
 * until the next write; the view is NOT stolen — see tpl_out_free(). */
const char *tpl_str(TplOut *out);
size_t tpl_len(const TplOut *out);

/* Frees the buffer and the arena; the struct itself is reset to {0}
 * and can be reused (stack-allocated TplOut needs no other cleanup). */
void tpl_out_free(TplOut *out);

/* ---- fragments (templ's templ.Fragment analog) ---- */

/* Selects the fragment to render: with a selection, ONLY markup
 * inside matching @fragment(name) blocks reaches the output — the
 * rest of the template still EXECUTES (like templ), its writes are
 * discarded. Nested fragments render with their parent; fragments
 * with the same name are all rendered; an unknown name produces an
 * empty output. NULL renders everything (the default). */
void tpl_frag_select(TplOut *out, const char *name);

/* Generator-facing fragment block markers — emitted by ctmpl as
 *     tpl_frag_begin(out, name); <body> tpl_frag_end(out);
 * and otherwise never called by hand. */
void tpl_frag_begin(TplOut *out, const char *name);
void tpl_frag_end(TplOut *out);

/* ---- render once (templ's OnceHandler analog) ---- */

/* Returns true exactly once per handle PER RENDER (per TplOut) —
 * ctmpl wraps an @once(handle) block in it. Thread-safe by design:
 * the fired-state lives in the TplOut, not in the handle. */
bool tpl_once_begin(TplOut *out, TplOnce *handle);

/* ---- HTTP integration ---- */

/* Renders a template response: status + "Content-Type: text/html" +
 * the buffer (copied; the caller keeps ownership — call
 * tpl_out_free() afterwards as usual). Bodies that do not fit the
 * fixed 4096-byte response buffer are stored in a heap body that the
 * library frees after the send. Returns 0 = OK, -1 on NULL args, an
 * invalid status or a failed render (tpl_ok() == false) — on -1
 * nothing is written. */
int http_res_html(HttpResponse *res, int status, const TplOut *out);

#endif