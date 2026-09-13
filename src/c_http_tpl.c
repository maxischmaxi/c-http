#include "c_http_tpl.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* ============================================================
 * Scratch arena (value helpers)
 *
 * tpl_int/tpl_fmt/tpl_url need to hand strings to the generated
 * code. Go has garbage collection; we bump-allocate small blocks
 * that live as long as the TplOut. A block is a linked-list node
 * with flexible payload; freeing walks the list.
 * ============================================================ */

typedef struct TplArenaBlock {
    struct TplArenaBlock *next;
    size_t used;
    size_t cap; /* payload capacity */
} TplArenaBlock;

#define TPL_ARENA_BLOCK_SIZE 512

/* Allocates len bytes in the arena, or NULL on OOM. */
static char *arena_alloc(TplOut *out, size_t len)
{
    if (out->arena == NULL || ((TplArenaBlock *)out->arena)->cap -
                                      ((TplArenaBlock *)out->arena)->used <
                                  len) {
        size_t cap = len > TPL_ARENA_BLOCK_SIZE ? len : TPL_ARENA_BLOCK_SIZE;
        TplArenaBlock *block = malloc(sizeof(TplArenaBlock) + cap);
        if (block == NULL) {
            out->failed = true;
            return NULL;
        }
        block->next = out->arena;
        block->used = 0;
        block->cap = cap;
        out->arena = block;
    }
    TplArenaBlock *block = out->arena;
    char *p = (char *)(block + 1) + block->used;
    block->used += len;
    return p;
}

void tpl_out_free(TplOut *out)
{
    if (out == NULL) {
        return;
    }
    TplArenaBlock *block = out->arena;
    while (block != NULL) {
        TplArenaBlock *next = block->next;
        free(block);
        block = next;
    }
    free(out->data);
    memset(out, 0, sizeof(*out));
}

/* ============================================================
 * Buffer writes
 * ============================================================ */

/* Ensures room for len more bytes; false on OOM (failed is set). */
static bool buf_reserve(TplOut *out, size_t len)
{
    if (out->failed) {
        return false;
    }
    if (len > SIZE_MAX - out->len) {
        out->failed = true; /* overflow guard: size_t wrapped */
        return false;
    }
    size_t need = out->len + len;
    if (need <= out->cap) {
        return true;
    }
    size_t new_cap = out->cap == 0 ? 256 : out->cap;
    while (new_cap < need) {
        if (new_cap > SIZE_MAX / 2) {
            new_cap = need;
            break;
        }
        new_cap *= 2;
    }
    char *tmp = realloc(out->data, new_cap);
    if (tmp == NULL) {
        out->failed = true;
        return false;
    }
    out->data = tmp;
    out->cap = new_cap;
    return true;
}

void tpl_lit_n(TplOut *out, const char *s, size_t len)
{
    if (out == NULL || s == NULL || len == 0) {
        return;
    }
    /* Fragment filtering: discard writes outside the selected
     * fragment (the component code still runs — tpl_frag_begin). */
    if (out->frag_sel != NULL && out->frag_match <= 0) {
        return;
    }
    if (!buf_reserve(out, len)) {
        return;
    }
    memcpy(out->data + out->len, s, len);
    out->len += len;
}

void tpl_lit(TplOut *out, const char *s)
{
    if (s == NULL) {
        return;
    }
    tpl_lit_n(out, s, strlen(s));
}

void tpl_raw(TplOut *out, const char *s)
{
    /* Raw == literal; a separate name documents the intent
     * (trusted HTML, templ's templ.Raw). */
    tpl_lit(out, s);
}

void tpl_raw_n(TplOut *out, const char *s, size_t len)
{
    tpl_lit_n(out, s, len);
}

/* ============================================================
 * Escaping
 * ============================================================
 *
 * Both contexts escape the same set (& < > " ' -> named/numeric
 * entities). Separate functions keep the contexts distinct in the
 * generated code and let the rules diverge later (templ is
 * context-aware; attribute values additionally reject raw
 * control characters, which is handled here by escaping them).
 */

typedef struct {
    const char *entity;
    size_t entity_len;
} TplEntity;

/* Index by unsigned char: NULL = pass through. Named/numeric forms
 * follow templ's EscapeString output. */
static const TplEntity tpl_entities[256] = {
    ['&'] = {"&amp;", 5}, ['<'] = {"&lt;", 4},   ['>'] = {"&gt;", 4},
    ['"'] = {"&#34;", 5}, ['\''] = {"&#39;", 5},
};

/* Characters that need a lookup, for a strpbrk-style fast path. */
static const char TPL_ESCAPE_CHARS[] = "&<>\"'";

static void write_escaped(TplOut *out, const char *s)
{
    const char *p = s;
    for (;;) {
        const char *hit = strpbrk(p, TPL_ESCAPE_CHARS);
        if (hit == NULL) {
            tpl_lit_n(out, p, strlen(p));
            return;
        }
        tpl_lit_n(out, p, (size_t)(hit - p));
        const TplEntity *e = &tpl_entities[(unsigned char)*hit];
        tpl_lit_n(out, e->entity, e->entity_len);
        p = hit + 1;
    }
}

void tpl_esc(TplOut *out, const char *s)
{
    if (out == NULL || s == NULL) {
        return;
    }
    write_escaped(out, s);
}

void tpl_attr(TplOut *out, const char *s)
{
    if (out == NULL || s == NULL) {
        return;
    }
    /* Same rules as text context today — kept separate so the
     * generator can rely on the context being explicit. */
    write_escaped(out, s);
}

/* ============================================================
 * Value helpers
 * ============================================================ */

const char *tpl_int(TplOut *out, long long value)
{
    if (out == NULL) {
        return "";
    }
    /* Longest long long: -9223372036854775808 = 20 chars + NUL. */
    char *buf = arena_alloc(out, 21);
    if (buf == NULL) {
        return "";
    }
    snprintf(buf, 21, "%lld", value);
    return buf;
}

const char *tpl_fmt(TplOut *out, const char *fmt, ...)
{
    if (out == NULL || fmt == NULL) {
        return "";
    }
    va_list ap;
    va_start(ap, fmt);
    va_list measure;
    va_copy(measure, ap);
    int need = vsnprintf(NULL, 0, fmt, measure);
    va_end(measure);
    if (need < 0) {
        out->failed = true;
        va_end(ap);
        return "";
    }
    char *buf = arena_alloc(out, (size_t)need + 1);
    if (buf == NULL) {
        va_end(ap);
        return "";
    }
    (void)vsnprintf(buf, (size_t)need + 1, fmt, ap);
    va_end(ap);
    return buf;
}

/* ============================================================
 * URL sanitization (templ's templ.URL)
 * ============================================================ */

/* ASCII whitespace per the WHATWG URL spec (leading run is skipped
 * by browsers — a " javascript:..." prefix must still be caught). */
static bool is_url_space(unsigned char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' ||
           c == '\v';
}

/* Is s (already trimmed) a scheme prefix like "https:"? Fills
 * scheme_len with the length of "scheme:" when true. */
static bool has_scheme(const char *s, size_t *scheme_len)
{
    /* scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ) ":" */
    if (s[0] == '\0') {
        return false;
    }
    size_t i = 0;
    if (!((s[0] >= 'a' && s[0] <= 'z') || (s[0] >= 'A' && s[0] <= 'Z'))) {
        return false;
    }
    while (s[i] != '\0' && s[i] != ':') {
        char c = s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.')) {
            return false;
        }
        i++;
    }
    if (s[i] != ':') {
        return false;
    }
    *scheme_len = i + 1;
    return true;
}

static bool scheme_equals(const char *s, size_t len, const char *want)
{
    if (strlen(want) != len) {
        return false;
    }
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        if (c >= 'A' && c <= 'Z') {
            c = (char)(c - 'A' + 'a');
        }
        if (c != want[i]) {
            return false;
        }
    }
    return true;
}

/* Validates a trimmed, NUL-terminated URL candidate. */
static bool url_is_safe(const char *s, size_t len)
{
    size_t scheme_len = 0;
    if (has_scheme(s, &scheme_len)) {
        if (!(scheme_equals(s, scheme_len, "http:") ||
              scheme_equals(s, scheme_len, "https:") ||
              scheme_equals(s, scheme_len, "mailto:"))) {
            return false;
        }
    }
    /* No control characters anywhere (tab/newline tricks). */
    for (size_t i = 0; i < len; i++) {
        if ((unsigned char)s[i] < 0x20 || s[i] == 0x7f) {
            return false;
        }
    }
    return true;
}

static TplUrl tpl_url_val(const char *s)
{
    TplUrl v = {.s = s};
    return v;
}

TplUrl tpl_url(TplOut *out, const char *url)
{
    if (out == NULL || url == NULL) {
        return tpl_url_val("about:invalid#ctmpl");
    }
    const char *p = url;
    while (is_url_space((unsigned char)*p)) {
        p++;
    }
    size_t len = strlen(p);
    while (len > 0 && is_url_space((unsigned char)p[len - 1])) {
        len--;
    }

    /* No whitespace to trim: validate in place and return the input
     * pointer (documented zero-copy fast path for safe URLs). */
    if (p == url && len == strlen(url)) {
        return tpl_url_val(url_is_safe(url, len) ? url : "about:invalid#ctmpl");
    }

    /* Trimmed copy (NUL-terminated scratch, arena-owned). */
    char *trimmed = arena_alloc(out, len + 1);
    if (trimmed == NULL) {
        return tpl_url_val("about:invalid#ctmpl");
    }
    memcpy(trimmed, p, len);
    trimmed[len] = '\0';
    return tpl_url_val(url_is_safe(trimmed, len) ? trimmed
                                                 : "about:invalid#ctmpl");
}

TplUrl tpl_safe_url(const char *url)
{
    /* The deliberate bypass — visible in the template, like templ's
     * templ.SafeURL. NULL still degrades to the invalid marker so
     * the render never crashes. */
    return tpl_url_val(url != NULL ? url : "about:invalid#ctmpl");
}

void tpl_attr_url(TplOut *out, TplUrl url)
{
    if (out == NULL || url.s == NULL) {
        return;
    }
    write_escaped(out, url.s);
}

/* ============================================================
 * Buffer access
 * ============================================================ */

bool tpl_ok(const TplOut *out)
{
    return out != NULL && !out->failed;
}

const char *tpl_str(TplOut *out)
{
    if (out == NULL) {
        return "";
    }
    /* NUL-terminate on demand (room reserved for exactly this). */
    if (out->data == NULL) {
        return "";
    }
    if (out->len == out->cap) {
        if (!buf_reserve(out, 1)) {
            return "";
        }
    }
    out->data[out->len] = '\0';
    return out->data;
}

size_t tpl_len(const TplOut *out)
{
    return out == NULL ? 0 : out->len;
}

/* ============================================================
 * CSS attribute sanitization (templ's templ.SanitizeCSS analog)
 * ============================================================ */

static bool ci_starts(const char *s, size_t len, const char *prefix)
{
    size_t n = strlen(prefix);
    return len >= n && strncasecmp(s, prefix, n) == 0;
}

static bool ci_contains(const char *haystack, size_t len, const char *needle)
{
    size_t n = strlen(needle);
    if (n == 0 || len < n) {
        return false;
    }
    for (size_t i = 0; i + n <= len; i++) {
        if (strncasecmp(haystack + i, needle, n) == 0) {
            return true;
        }
    }
    return false;
}

/* property-name = ALPHA / "-" 1*( ALPHA / DIGIT / "-" ) */
static bool css_prop_valid(const char *s, size_t len)
{
    if (len == 0) {
        return false;
    }
    if (!isalpha((unsigned char)s[0]) && s[0] != '-') {
        return false;
    }
    for (size_t i = 1; i < len; i++) {
        char c = s[i];
        if (!isalnum((unsigned char)c) && c != '-') {
            return false;
        }
    }
    return true;
}

/* url(...) contents may only be scheme-relative, http(s) or
 * data:image — anything else (javascript:, vbscript:, …) or an
 * unterminated url( is unsafe. */
static bool css_url_unsafe(const char *v, size_t len)
{
    size_t i = 0;
    for (;;) {
        size_t pos = 0;
        bool found = false;
        for (size_t j = i; j + 4 <= len; j++) {
            if (strncasecmp(v + j, "url(", 4) == 0) {
                pos = j;
                found = true;
                break;
            }
        }
        if (!found) {
            return false;
        }
        size_t end = pos + 4;
        while (end < len && v[end] != ')') {
            end++;
        }
        if (end >= len) {
            return true; /* unterminated url( */
        }
        const char *inner = v + pos + 4;
        size_t inner_len = end - (pos + 4);
        if (memchr(inner, ':', inner_len) != NULL &&
            !ci_starts(inner, inner_len, "http://") &&
            !ci_starts(inner, inner_len, "https://") &&
            !ci_starts(inner, inner_len, "data:image")) {
            return true;
        }
        i = end + 1;
    }
}

static bool css_value_unsafe(const char *v, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)v[i];
        if (c < 0x20 || c == 0x7f || c == '<' || c == '>') {
            return true;
        }
    }
    if (ci_contains(v, len, "javascript:") ||
        ci_contains(v, len, "vbscript:") ||
        ci_contains(v, len, "expression(") ||
        ci_contains(v, len, "behavior:") || ci_contains(v, len, "@import")) {
        return true;
    }
    return css_url_unsafe(v, len);
}

/* Walks the declarations; reports whether ALL of them are safe. */
static bool css_all_safe(const char *s)
{
    size_t len = strlen(s);
    size_t i = 0;
    while (i < len) {
        /* declaration span up to the next ';' OUTSIDE parentheses
         * (url(data:image/png;base64,…) contains ';') */
        size_t start = i;
        int paren = 0;
        while (i < len && (paren > 0 || s[i] != ';')) {
            if (s[i] == '(') {
                paren++;
            } else if (s[i] == ')') {
                paren--;
            }
            i++;
        }
        const char *d = s + start;
        size_t dlen = i - start;
        if (i < len) {
            i++; /* the ';' */
        }
        while (dlen > 0 && isspace((unsigned char)*d)) {
            d++;
            dlen--;
        }
        while (dlen > 0 && isspace((unsigned char)d[dlen - 1])) {
            dlen--;
        }
        if (dlen == 0) {
            continue; /* empty declaration (trailing ';') */
        }
        const char *colon = memchr(d, ':', dlen);
        if (colon == NULL) {
            return false; /* not a declaration */
        }
        size_t prop_len = (size_t)(colon - d);
        while (prop_len > 0 && isspace((unsigned char)d[prop_len - 1])) {
            prop_len--;
        }
        const char *value = colon + 1;
        size_t value_len = dlen - prop_len - 1;
        if (!css_prop_valid(d, prop_len) ||
            css_value_unsafe(value, value_len)) {
            return false;
        }
    }
    return true;
}

/* Rebuilds declarations, replacing unsafe values with the
 * zctmplUnsafeCSS placeholder (keeps valid property names). */
static void css_rebuild(const char *s, char *buf, size_t cap)
{
    size_t used = 0;
    size_t len = strlen(s);
    size_t i = 0;
    bool first = true;
    while (i < len) {
        size_t start = i;
        int paren = 0;
        while (i < len && (paren > 0 || s[i] != ';')) {
            if (s[i] == '(') {
                paren++;
            } else if (s[i] == ')') {
                paren--;
            }
            i++;
        }
        const char *d = s + start;
        size_t dlen = i - start;
        if (i < len) {
            i++;
        }
        while (dlen > 0 && isspace((unsigned char)*d)) {
            d++;
            dlen--;
        }
        while (dlen > 0 && isspace((unsigned char)d[dlen - 1])) {
            dlen--;
        }
        if (dlen == 0) {
            continue;
        }
        if (!first) {
            if (used + 2 >= cap) {
                break;
            }
            buf[used++] = ';';
            buf[used++] = ' ';
        }
        first = false;
        const char *colon = memchr(d, ':', dlen);
        if (colon == NULL || !css_prop_valid(d, (size_t)(colon - d))) {
            used += (size_t)snprintf(buf + used, cap - used, "zctmplUnsafeCSS");
        } else if (css_value_unsafe(colon + 1,
                                    dlen - (size_t)(colon - d) - 1)) {
            used +=
                (size_t)snprintf(buf + used, cap - used, "%.*s:zctmplUnsafeCSS",
                                 (int)((size_t)(colon - d)), d);
        } else {
            used +=
                (size_t)snprintf(buf + used, cap - used, "%.*s", (int)dlen, d);
        }
        if (used >= cap) {
            used = cap - 1; /* clamp — cannot happen with the bound */
            break;
        }
    }
    buf[used] = '\0';
}

TplCss tpl_css(TplOut *out, const char *declarations)
{
    TplCss empty = {.s = ""};
    if (out == NULL || declarations == NULL) {
        return empty;
    }
    if (css_all_safe(declarations)) {
        TplCss safe = {.s = declarations}; /* zero copy */
        return safe;
    }
    /* Rebuild: the bound covers the placeholder for EVERY possible
     * declaration (each ';' starts one). */
    size_t seps = 1;
    for (const char *p = declarations; *p != '\0'; p++) {
        if (*p == ';') {
            seps++;
        }
    }
    size_t cap = strlen(declarations) + seps * 32 + 1;
    char *buf = arena_alloc(out, cap);
    if (buf == NULL) {
        out->failed = true;
        return empty;
    }
    css_rebuild(declarations, buf, cap);
    TplCss result = {.s = buf};
    return result;
}

TplCss tpl_css_safe(const char *declarations)
{
    TplCss v = {.s = declarations != NULL ? declarations : ""};
    return v;
}

void tpl_attr_css(TplOut *out, TplCss css)
{
    if (out == NULL || css.s == NULL) {
        return;
    }
    write_escaped(out, css.s);
}

/* ============================================================
 * Fragments
 * ==========================================================
 *
 * State machine (see TplOut fields): while a fragment is selected,
 * every @fragment block pushes its depth. Writes are kept only
 * when frag_match > 0 — set when the selected name matches and
 * cleared when the matching block closes. Nesting falls out
 * naturally:
 *
 *   selected "outer":  begin(outer) -> match=1 (keep),
 *                       begin(inner) -> still inside (keep),
 *                       end(inner), end(outer) -> match cleared.
 *   selected "inner":  begin(outer) -> discard,
 *                       begin(inner) -> match=2 (keep),
 *                       end(inner)   -> discard, end(outer).
 */

void tpl_frag_select(TplOut *out, const char *name)
{
    if (out == NULL) {
        return;
    }
    out->frag_sel = name;
    out->frag_depth = 0;
    out->frag_match = 0;
}

void tpl_frag_begin(TplOut *out, const char *name)
{
    if (out == NULL || out->frag_sel == NULL) {
        return; /* no selection: blocks are transparent */
    }
    out->frag_depth++;
    if (out->frag_match > 0) {
        return; /* nested inside an already-matching fragment */
    }
    if (name != NULL && strcmp(out->frag_sel, name) == 0) {
        out->frag_match = out->frag_depth;
    }
}

void tpl_frag_end(TplOut *out)
{
    if (out == NULL || out->frag_sel == NULL) {
        return;
    }
    out->frag_depth--;
    if (out->frag_match > out->frag_depth) {
        out->frag_match = 0; /* the matching block closed */
    }
}

/* ============================================================
 * Render once
 * ============================================================ */

bool tpl_once_begin(TplOut *out, TplOnce *handle)
{
    if (out == NULL || handle == NULL) {
        return false;
    }
    for (size_t i = 0; i < out->once_fired_count; i++) {
        if (out->once_fired[i] == handle) {
            return false;
        }
    }
    /* Registry grows by re-copy in the arena (few handles per
     * render — the copy cost is irrelevant, and it keeps all state
     * per-render with no cleanup). */
    TplOnce **fired = (TplOnce **)arena_alloc(out, (out->once_fired_count + 1) *
                                                       sizeof(*fired));
    if (fired == NULL) {
        return false; /* treat an OOM as "already rendered" */
    }
    /* memcpy(NULL, 0) is UB — the registry starts empty. */
    if (out->once_fired_count > 0) {
        memcpy(fired, out->once_fired,
               out->once_fired_count * sizeof(*fired));
    }
    fired[out->once_fired_count] = handle;
    out->once_fired = fired;
    out->once_fired_count++;
    return true;
}

/* ============================================================
 * HTTP integration
 * ============================================================ */

int http_res_html(HttpResponse *res, int status, const TplOut *out)
{
    if (res == NULL || out == NULL || !tpl_ok(out)) {
        return -1;
    }
    return http_res_body(res, status, "text/html", out->data, out->len);
}