#ifndef CTMPL_H
#define CTMPL_H

#include <stddef.h>
#include <stdio.h>

/* ============================================================
 * ctmpl — .thtml to C code generator
 *
 * A templ-inspired template compiler: .thtml files contain
 * components (HTML markup + C expressions) and are compiled into
 * plain C functions writing into a TplOut. The generator does NOT
 * understand C — expressions, conditions and for-heads are copied
 * verbatim and type-checked by the C compiler (like templ copies
 * Go expressions for the Go compiler to check).
 *
 *     component greeting(const char *name) {
 *       <div class="greeting">Hello, { name }!</div>
 *     }
 *
 * becomes (page_templ.h / page_templ.c):
 *
 *     void tpl_greeting(TplOut *out, const char *name);
 *
 *     void tpl_greeting(TplOut *out, const char *name)
 *     {
 *         tpl_lit(out, "<div class=\"greeting\">Hello, ");
 *         tpl_esc(out, (name));
 *         tpl_lit(out, "!</div>");
 *     }
 *
 * Syntax summary (see README):
 *   component IDENT ( <C params> ) { <body> }   component definition
 *   <tag attr="value { expr }">                  markup, {expr} in
 *                                                quoted attr values
 *   { expr }                                      HTML-escaped interp
 *   { children... }                               render child content
 *   attr?={ cond }                                boolean attribute
 *   @component(args)                              render a component
 *   @component(args) { <body> }                   pass child content
 *   @component(args) with (expr) { <body> }       bind child data
 *   @raw(expr)                                    trusted HTML, raw
 *   @fragment(name) { <body> }                    fragment (render
 *                                                selectively via
 *                                                tpl_frag_select)
 *   once <name>                                   declare an
 *                                                @once handle
 *   @once(handle) { <body> }                      render once per
 *                                                render (per TplOut)
 *   if <C cond> { } else { }                      condition
 *   for <C for-head> { }                          loop
 *   #<line>                                       copied into the
 *                                                generated .h
 *
 * Child blocks: C has no closures, so a block captures what the
 * generator can hand it — the ENCLOSING component's single
 * parameter (via the children data pointer; the block just uses
 * it by name). With zero parameters the block sees only `out`.
 * For anything else use `with (expr)`: the block receives the
 * bound expression as `tpl_data` (void *) and out->ctx.
 *
 * Fragments (@fragment): the body ALWAYS executes; with a fragment
 * selected (tpl_frag_select on the TplOut) only the matching
 * blocks' output reaches the buffer — the htmx pattern (render a
 * partial for hx-get). Nested fragments render with their parent,
 * same-named fragments all render, unknown names yield empty.
 *
 * Render once (@once): declare handles with `once <name>` (emitted
 * as a file-static TplOnce) and wrap blocks in @once(handle) — the
 * block renders the first time per RENDER (per TplOut), e.g. a
 * component's <style>/<script> dependency used twice on one page.
 *
 * Rules and guarantees:
 *
 * - Tags must be closed: ctmpl tracks a tag stack per component and
 *   errors on mismatched/unclosed tags and on non-void self-closing
 *   tags (browsers IGNORE a trailing '/', so <div/> is a real bug).
 *   Void elements (img, br, input, ...) need no closing tag; a
 *   closing tag on a void element is an error. Comments and the
 *   doctype skip the stack; tag names compare case-insensitively.
 *
 * - Context-aware escaping, templ's injection rules translated to
 *   C's type system:
 *     - href/src/action/formaction/poster/cite/background attribute
 *       expressions are emitted as tpl_attr_url(...) which accepts
 *       ONLY TplUrl — tpl_url() sanitizes (javascript: and friends
 *       become about:invalid#ctmpl), tpl_safe_url() is the visible
 *       bypass. Unwrapped values are a C compile error.
 *     - style= expressions are emitted as tpl_attr_css(...) which
 *       accepts ONLY TplCss — tpl_css() sanitizes declarations
 *       (dangerous values become zctmplUnsafeCSS), tpl_css_safe()
 *       bypasses.
 *     - on... and hx-on:... attributes REJECT expressions at compile
 *       time — pass data via data-* and wire it in a <script> block
 *       (CSP-friendly).
 *     - Everything else keeps the text/attribute escaping.
 *
 * Statement keywords (if/for/else) are recognized only at the start
 * of a text run; literal braces in text must use { "..." }.
 * ============================================================ */

typedef struct {
    /* Human-readable message; empty when no error occurred. */
    char message[256];
    /* 1-based source location of the error (0 = not located). */
    size_t line;
    size_t col;
} CtmplError;

/* Compiles .thtml source into C. On success writes the declarations
 * to out_h and the definitions to out_c (both must be open for
 * writing). in_name is used for #line directives, the include guard
 * and error messages (NULL = "input").
 *
 * Returns 0 = OK. On -1 nothing was written to the streams and err
 * describes the problem (message + source location). */
int ctmpl_compile(const char *src, size_t src_len, const char *in_name,
                  FILE *out_h, FILE *out_c, CtmplError *err);

#endif /* CTMPL_H */