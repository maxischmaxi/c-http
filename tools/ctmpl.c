/* ctmpl — .thtml to C compiler (see ctmpl.h for the syntax).
 *
 * Two phases: the whole file is PARSED into an AST first (so a parse
 * error never produces partial output), then the AST is EMITTED as C
 * code. C expressions, conditions and for-heads are scanned only
 * well enough to find their boundaries (string literals, comments,
 * balanced braces/parens) and are copied verbatim — the C compiler
 * type-checks them, exactly like templ copies Go expressions for
 * the Go compiler to check.
 */
#include "ctmpl.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* ============================================================ */
/* small utilities                                                */
/* ============================================================ */

/* Growable string buffer for literal emission. */
typedef struct {
    char *d;
    size_t len;
    size_t cap;
    int failed;
} SBuf;

/* ============================================================ */
/* HTML tag validation                                              */
/* ============================================================ */

/* Tag stack depth cap — deeper nesting than this is almost
 * certainly an unclosed-tag bug, not a real page. */
#define TAG_STACK_MAX 32
/* Tag names are ASCII and short; a longer name is rejected. */
#define TAG_NAME_MAX 31

typedef struct {
    char name[TAG_NAME_MAX + 1];
    size_t name_len;
    size_t pos;  /* source offset of the opening '<' */
    size_t line; /* 1-based line of the opening '<' */
} TagFrame;

/* HTML5 void elements (no closing tag, no content). */
static bool is_void_tag(const char *name, size_t len)
{
    static const char *voids[] = {
        "area",  "base", "br",   "col",   "embed",  "hr",    "img",
        "input", "link", "meta", "param", "source", "track", "wbr",
    };
    if (len > 8) {
        return false; /* longest name above is 5 chars */
    }
    for (size_t i = 0; i < sizeof(voids) / sizeof(voids[0]); i++) {
        if (strlen(voids[i]) == len && strncasecmp(name, voids[i], len) == 0) {
            return true;
        }
    }
    return false;
}

static void sb_putn(SBuf *sb, const char *s, size_t n)
{
    if (sb->failed || n == 0) {
        return;
    }
    if (sb->len + n > sb->cap) {
        size_t cap = sb->cap == 0 ? 64 : sb->cap;
        while (cap < sb->len + n) {
            cap *= 2;
        }
        char *tmp = realloc(sb->d, cap);
        if (tmp == NULL) {
            sb->failed = 1;
            return;
        }
        sb->d = tmp;
        sb->cap = cap;
    }
    memcpy(sb->d + sb->len, s, n);
    sb->len += n;
}

static void sb_puts(SBuf *sb, const char *s)
{
    sb_putn(sb, s, strlen(s));
}

/* Copies [start, end) verbatim into a NUL-terminated heap string. */
static char *dup_raw(const char *start, const char *end)
{
    size_t n = (size_t)(end - start);
    char *out = malloc(n + 1);
    if (out == NULL) {
        return NULL;
    }
    memcpy(out, start, n);
    out[n] = '\0';
    return out;
}

/* Trims ASCII whitespace from both ends before copying. */
static char *dup_trim(const char *start, const char *end)
{
    while (start < end && isspace((unsigned char)*start)) {
        start++;
    }
    while (end > start && isspace((unsigned char)end[-1])) {
        end--;
    }
    return dup_raw(start, end);
}

/* ============================================================ */
/* AST                                                            */
/* ============================================================ */

typedef struct Component Component;

typedef enum {
    N_TEXT,   /* literal markup, copied raw */
    N_INTERP, /* { expr } — escaped interpolation */
    N_CALL,   /* @name(args) — component call */
    N_IF,     /* if cond { } else { } */
    N_FOR,    /* for head { } */
} NodeType;

typedef struct Node Node;
struct Node {
    NodeType type;
    size_t line; /* .thtml line for #line directives */
    Node *next;  /* sibling within a body */

    /* N_TEXT: raw slice (owned copy) */
    char *text;
    size_t text_len;

    /* N_INTERP: C expression (owned); ctx = the escaping context
     * the generator derived from the surrounding markup (text,
     * plain attribute, URL attribute, style attribute);
     * children = the { children... } form */
    char *expr;
    int ctx;
    bool children;

    /* N_CALL: callee + verbatim argument list (NULL when the call
     * has no parens or an empty one); block = child content nodes;
     * data_expr = per-call child data ("with (expr)"), NULL when
     * absent; comp = the ENCLOSING component (parameter capture);
     * gen_name = lambda name, assigned for calls with a block */
    char *callee;
    char *args;
    char *data_expr;
    Node *block;
    const Component *comp;
    char *gen_name;

    /* N_IF: expr = condition; N_FOR: expr = for-head */
    Node *then;
    Node *otherwise; /* N_IF else-branch (NULL when absent) */
};

typedef struct Component {
    char *name;   /* identifier as written in the source */
    char *params; /* C parameter list, verbatim */
    size_t line;  /* line of the 'component' keyword */
    Node *body;   /* first body node */
    struct Component *next;
} Component;

/* ============================================================ */
/* allocation tracking (everything freed after compile)          */
/* ============================================================ */

typedef struct {
    void **ptrs;
    size_t n;
    size_t cap;
    int oom;
} Allocs;

static void *allocs_add(Allocs *a, void *p)
{
    if (p == NULL) {
        a->oom = 1;
        return NULL;
    }
    if (a->n == a->cap) {
        size_t cap = a->cap == 0 ? 32 : a->cap * 2;
        void **tmp = realloc(a->ptrs, cap * sizeof(*tmp));
        if (tmp == NULL) {
            a->oom = 1;
            free(p);
            return NULL;
        }
        a->ptrs = tmp;
        a->cap = cap;
    }
    a->ptrs[a->n++] = p;
    return p;
}

static void allocs_free(Allocs *a)
{
    for (size_t i = 0; i < a->n; i++) {
        free(a->ptrs[i]);
    }
    free(a->ptrs);
    a->ptrs = NULL;
    a->n = a->cap = 0;
}

/* ============================================================ */
/* parser                                                         */
/* ============================================================ */

typedef struct {
    const char *src;
    size_t len;
    size_t pos;
    size_t line;       /* 1-based current line */
    size_t line_start; /* src offset of the current line's first char */
    CtmplError *err;
    Allocs *allocs;
    const Component *current_comp; /* enclosing component (capture) */
    /* Tag stack for HTML structure validation — reset per component
     * body, shared across if/for/fragment/once blocks (parse order
     * is linear, so tags must be balanced within one component). */
    TagFrame tag_stack[TAG_STACK_MAX];
    size_t tag_depth;
} Parser;

static char peek_at(Parser *p, size_t off)
{
    return p->pos + off < p->len ? p->src[p->pos + off] : '\0';
}

static char peek(Parser *p)
{
    return peek_at(p, 0);
}

static void advance(Parser *p)
{
    if (p->pos >= p->len) {
        return;
    }
    if (p->src[p->pos] == '\n') {
        p->line++;
        p->line_start = p->pos + 1;
    }
    p->pos++;
}

static void advance_n(Parser *p, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        advance(p);
    }
}

/* Fills the error and returns -1 (callers return it up). */
static int perr(Parser *p, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(p->err->message, sizeof(p->err->message), fmt, ap);
    va_end(ap);
    p->err->line = p->line;
    p->err->col = p->pos - p->line_start + 1;
    return -1;
}

/* Fills the error with the position at `pos` (not the cursor). */
static int perr_at(Parser *p, size_t pos, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(p->err->message, sizeof(p->err->message), fmt, ap);
    va_end(ap);
    size_t line = 1;
    size_t line_start = 0;
    for (size_t i = 0; i < pos && i < p->len; i++) {
        if (p->src[i] == '\n') {
            line++;
            line_start = i + 1;
        }
    }
    p->err->line = line;
    p->err->col = pos < p->len ? pos - line_start + 1 : 1;
    return -1;
}

static char *p_dup_raw(Parser *p, const char *start, const char *end)
{
    char *s = dup_raw(start, end);
    if (s == NULL || allocs_add(p->allocs, s) == NULL) {
        if (s != NULL) {
            free(s);
        }
        perr(p, "out of memory");
        return NULL;
    }
    return s;
}

static char *p_dup_trim(Parser *p, const char *start, const char *end)
{
    char *s = dup_trim(start, end);
    if (s == NULL || allocs_add(p->allocs, s) == NULL) {
        if (s != NULL) {
            free(s);
        }
        perr(p, "out of memory");
        return NULL;
    }
    return s;
}

static void skip_ws(Parser *p)
{
    while (p->pos < p->len && isspace((unsigned char)p->src[p->pos])) {
        advance(p);
    }
}

/* Whitespace, line comments and block comments — only used
 * BETWEEN components and #-lines, never inside markup. */
static void skip_ws_comments(Parser *p)
{
    for (;;) {
        char c = peek(p);
        if (isspace((unsigned char)c)) {
            advance(p);
            continue;
        }
        if (c == '/' && peek_at(p, 1) == '/') {
            while (p->pos < p->len && peek(p) != '\n') {
                advance(p);
            }
            continue;
        }
        if (c == '/' && peek_at(p, 1) == '*') {
            advance_n(p, 2);
            while (p->pos < p->len &&
                   !(peek(p) == '*' && peek_at(p, 1) == '/')) {
                advance(p);
            }
            if (p->pos < p->len) {
                advance_n(p, 2);
            }
            continue;
        }
        return;
    }
}

static bool is_ident_start(char c)
{
    return isalpha((unsigned char)c) || c == '_';
}

static bool is_ident_char(char c)
{
    return isalnum((unsigned char)c) || c == '_';
}

/* Reads [A-Za-z_][A-Za-z0-9_]* at the cursor (tracked copy). */
static char *read_ident(Parser *p)
{
    if (!is_ident_start(peek(p))) {
        perr(p, "expected an identifier");
        return NULL;
    }
    size_t start = p->pos;
    while (is_ident_char(peek(p))) {
        advance(p);
    }
    return p_dup_raw(p, p->src + start, p->src + p->pos);
}

/* Case-sensitive keyword match at the cursor; consumes it on match.
 * The next char must not be an identifier char ("forum" is not
 * "for", "component" needs a word boundary). */
static bool eat_keyword(Parser *p, const char *kw)
{
    size_t n = strlen(kw);
    if (p->pos + n > p->len || strncmp(p->src + p->pos, kw, n) != 0) {
        return false;
    }
    if (is_ident_char(peek_at(p, n))) {
        return false;
    }
    advance_n(p, n);
    return true;
}

/* ---- node helpers ---- */

static Node *new_node(Parser *p, NodeType type)
{
    Node *n = calloc(1, sizeof(*n));
    if (allocs_add(p->allocs, n) == NULL) {
        perr(p, "out of memory");
        return NULL;
    }
    n->type = type;
    n->line = p->line;
    return n;
}

static int append_node(Node **head, Node **tail, Node *n)
{
    if (n == NULL) {
        return -1;
    }
    if (*head == NULL) {
        *head = n;
    } else {
        (*tail)->next = n;
    }
    *tail = n;
    return 0;
}

static int append_text(Parser *p, Node **head, Node **tail, const char *start,
                       const char *end, size_t line)
{
    if (start == end) {
        return 0; /* empty slice — nothing to emit */
    }
    Node *n = new_node(p, N_TEXT);
    if (n == NULL) {
        return -1;
    }
    n->line = line;
    n->text = p_dup_raw(p, start, end);
    if (n->text == NULL) {
        return -1;
    }
    n->text_len = (size_t)(end - start);
    return append_node(head, tail, n);
}

/* ---- C-code boundary scanner (string/comment aware) ---- */

typedef enum {
    SCAN_TO_BRACE,    /* stop at '{' at depth 0 (not consumed) */
    SCAN_MATCH_BRACE, /* cursor after '{'; stop after matching '}' */
    SCAN_MATCH_PAREN, /* cursor after '('; stop after matching ')' */
} ScanMode;

/* Scans C code honoring string/char literals and comments. Braces
 * and parens share one depth counter (a '{' inside parens does not
 * terminate a TO_BRACE scan, which is what compound literals like
 * (Point){...} in conditions need). On success the start and end
 * out-params describe the expression slice; the cursor sits after
 * the terminator. */
static int scan_c(Parser *p, ScanMode mode, size_t *start, size_t *end)
{
    int depth = mode == SCAN_TO_BRACE ? 0 : 1;
    char want_close = mode == SCAN_MATCH_PAREN ? ')' : '}';
    *start = p->pos;
    for (;;) {
        if (p->pos >= p->len) {
            return perr(p,
                        mode == SCAN_TO_BRACE
                            ? "expected '{' before end of file"
                            : "unterminated expression — missing '%c'",
                        want_close);
        }
        char c = peek(p);

        if (c == '/' && peek_at(p, 1) == '/') {
            while (p->pos < p->len && peek(p) != '\n') {
                advance(p);
            }
            continue;
        }
        if (c == '/' && peek_at(p, 1) == '*') {
            advance_n(p, 2);
            while (p->pos < p->len &&
                   !(peek(p) == '*' && peek_at(p, 1) == '/')) {
                advance(p);
            }
            if (p->pos >= p->len) {
                return perr(p, "unterminated block comment");
            }
            advance_n(p, 2);
            continue;
        }

        if (c == '"' || c == '\'') {
            char quote = c;
            advance(p);
            while (p->pos < p->len && peek(p) != quote) {
                if (peek(p) == '\\') {
                    advance(p);
                }
                advance(p);
            }
            if (p->pos >= p->len) {
                return perr(p, "unterminated string literal");
            }
            advance(p);
            continue;
        }

        if (c == '{' || c == '(') {
            if (mode == SCAN_TO_BRACE && c == '{' && depth == 0) {
                *end = p->pos; /* at the '{', not consumed */
                return 0;
            }
            depth++;
        } else if (c == '}' || c == ')') {
            depth--;
            if (depth == 0 && mode != SCAN_TO_BRACE) {
                if (c != want_close) {
                    return perr(p, "unbalanced '%c' in expression", want_close);
                }
                *end = p->pos;
                advance(p);
                return 0;
            }
            if (depth < 0) {
                return perr(p, "unbalanced '%c' in expression", c);
            }
        }
        advance(p);
    }
}

/* ============================================================ */
/* recursive-descent parsing                                     */
/* ============================================================ */

static int parse_body(Parser *p, Node **head, Node **tail);

/* Interpolation contexts — decide the escaping function the
 * generated code calls. */
enum {
    CTX_TEXT, /* markup body: tpl_esc */
    CTX_ATTR, /* generic attribute value: tpl_attr */
    CTX_URL,  /* href/src/...: tpl_attr_url (needs TplUrl) */
    CTX_CSS,  /* style: tpl_attr_css (needs TplCss) */
};

static int parse_interp(Parser *p, Node **head, Node **tail, int ctx)
{
    advance(p); /* '{' */
    size_t start, end;
    if (scan_c(p, SCAN_MATCH_BRACE, &start, &end) != 0) {
        return -1;
    }
    char *expr = p_dup_trim(p, p->src + start, p->src + end);
    if (expr == NULL) {
        return -1;
    }
    Node *n = new_node(p, N_INTERP);
    if (n == NULL) {
        return -1;
    }
    n->expr = expr;
    n->ctx = ctx;
    if (strcmp(expr, "children...") == 0) {
        if (ctx != CTX_TEXT) {
            perr(p, "{ children... } is not valid in an attribute");
            return -1;
        }
        n->children = true;
    } else if (expr[0] == '\0') {
        perr(p, "empty { } interpolation");
        return -1;
    }
    return append_node(head, tail, n);
}

static bool is_builtin_callee(const char *name)
{
    return strcmp(name, "raw") == 0 || strcmp(name, "fragment") == 0 ||
           strcmp(name, "once") == 0;
}

/* Classifies an attribute for expression escaping. URL attributes
 * get TplUrl-forcing writers, style gets the CSS sanitizer, and
 * script attributes (on..., hx-on:...) REJECT expressions outright
 * — templ's injection rules (a data-* attribute plus a <script>
 * block is the CSP-friendly pattern). Reports the error and
 * returns -1. */
static int classify_attr(Parser *p, size_t name_start, size_t name_end)
{
    size_t len = name_end - name_start;
    if (len == 0) {
        return CTX_ATTR; /* spaces around '=' — treat as plain */
    }
    if ((len >= 3 && strncasecmp(p->src + name_start, "on", 2) == 0) ||
        (len >= 6 && strncasecmp(p->src + name_start, "hx-on:", 6) == 0)) {
        perr(p,
             "expressions in '%.*s' attributes are not supported — "
             "pass data via a data-* attribute and wire it up in "
             "a <script> block",
             (int)len, p->src + name_start);
        return -1;
    }
    static const char *url_attrs[] = {
        "href", "src", "action", "formaction", "poster", "cite", "background",
    };
    for (size_t i = 0; i < sizeof(url_attrs) / sizeof(url_attrs[0]); i++) {
        if (strlen(url_attrs[i]) == len &&
            strncasecmp(p->src + name_start, url_attrs[i], len) == 0) {
            return CTX_URL;
        }
    }
    if (len == 5 && strncasecmp(p->src + name_start, "style", 5) == 0) {
        return CTX_CSS;
    }
    return CTX_ATTR;
}

static int parse_call(Parser *p, Node **head, Node **tail)
{
    advance(p); /* '@' */
    size_t name_line = p->line;
    char *name = read_ident(p);
    if (name == NULL) {
        return -1;
    }
    char *args = NULL;
    if (peek(p) == '(') {
        advance(p); /* '(' */
        size_t start, end;
        if (scan_c(p, SCAN_MATCH_PAREN, &start, &end) != 0) {
            return -1;
        }
        args = p_dup_trim(p, p->src + start, p->src + end);
        if (args == NULL) {
            return -1;
        }
    }

    /* Optional child-content block: peek past whitespace for '{'
     * or the 'with (<expr>)' data binding WITHOUT keeping the
     * whitespace consumed (it belongs to the following text
     * otherwise).
     *
     * C blocks cannot capture enclosing locals (Go closures can —
     * templ needs no equivalent). A block therefore sees only
     * `out` (and out->ctx) plus the `tpl_data` pointer that
     * `with (expr)` binds at the call site. */
    size_t save_pos = p->pos;
    size_t save_line = p->line;
    size_t save_line_start = p->line_start;
    skip_ws(p);
    char *data_expr = NULL;
    Node *block = NULL;
    Node *block_tail = NULL;
    if (eat_keyword(p, "with")) {
        skip_ws(p);
        if (peek(p) != '(') {
            /* 'with' as plain text (e.g. "with great force") —
             * rewind, it belongs to the text after the call */
            p->pos = save_pos;
            p->line = save_line;
            p->line_start = save_line_start;
        } else {
            advance(p);
            size_t dstart, dend;
            if (scan_c(p, SCAN_MATCH_PAREN, &dstart, &dend) != 0) {
                return -1;
            }
            data_expr = p_dup_trim(p, p->src + dstart, p->src + dend);
            if (data_expr == NULL) {
                return -1;
            }
            skip_ws(p);
        }
    }
    if (peek(p) == '{') {
        advance(p);
        if (parse_body(p, &block, &block_tail) != 0) {
            return -1;
        }
        if (peek(p) != '}') {
            return perr(p, "expected '}' to close the child block");
        }
        advance(p);
    } else {
        p->pos = save_pos;
        p->line = save_line;
        p->line_start = save_line_start;
    }

    if (is_builtin_callee(name)) {
        /* @raw(expr): trusted HTML, exactly one argument, no block.
         * @fragment(expr) { }: fragment marker, needs a block.
         * @once(handle) { }: render-once, needs a block. None of
         * them accepts with (...). */
        if (data_expr != NULL) {
            return perr(p, "with (...) is not valid for @%s", name);
        }
        if (strcmp(name, "raw") == 0) {
            if (args == NULL || args[0] == '\0' || block != NULL) {
                return perr(p, "@raw expects exactly one argument and "
                               "no child block");
            }
        } else {
            if (args == NULL || args[0] == '\0') {
                return perr(p, "@%s expects an argument", name);
            }
            if (block == NULL) {
                return perr(p, "@%s requires a child block", name);
            }
        }
    }

    Node *n = new_node(p, N_CALL);
    if (n == NULL) {
        return -1;
    }
    n->line = name_line;
    n->callee = name;
    n->args = args;
    n->data_expr = data_expr;
    n->block = block;
    n->comp = p->current_comp;
    return append_node(head, tail, n);
}

static int parse_if(Parser *p, Node **head, Node **tail)
{
    size_t if_line = p->line;
    size_t start, end;
    if (scan_c(p, SCAN_TO_BRACE, &start, &end) != 0) {
        return -1;
    }
    char *cond = p_dup_trim(p, p->src + start, p->src + end);
    if (cond == NULL) {
        return -1;
    }
    if (cond[0] == '\0') {
        perr(p, "missing condition between 'if' and '{'");
        return -1;
    }
    advance(p); /* '{' */

    Node *n = new_node(p, N_IF);
    if (n == NULL) {
        return -1;
    }
    n->line = if_line;
    n->expr = cond;

    Node *then_tail = NULL;
    if (parse_body(p, &n->then, &then_tail) != 0) {
        return -1;
    }
    if (peek(p) != '}') {
        return perr(p, "expected '}' to close the if-branch");
    }
    advance(p);

    /* else / else if — peek past whitespace, rewind when absent */
    size_t save_pos = p->pos;
    size_t save_line = p->line;
    size_t save_line_start = p->line_start;
    skip_ws(p);
    if (eat_keyword(p, "else")) {
        skip_ws(p);
        if (eat_keyword(p, "if")) {
            /* else if — chained as a nested if node */
            Node *chain = NULL;
            Node *chain_tail = NULL;
            if (parse_if(p, &chain, &chain_tail) != 0) {
                return -1;
            }
            n->otherwise = chain;
        } else if (peek(p) == '{') {
            advance(p);
            Node *o_head = NULL;
            Node *o_tail = NULL;
            if (parse_body(p, &o_head, &o_tail) != 0) {
                return -1;
            }
            if (peek(p) != '}') {
                return perr(p, "expected '}' to close the else-branch");
            }
            advance(p);
            n->otherwise = o_head;
        } else {
            return perr(p, "expected 'if' or '{' after 'else'");
        }
    } else {
        p->pos = save_pos;
        p->line = save_line;
        p->line_start = save_line_start;
    }
    return append_node(head, tail, n);
}

static int parse_for(Parser *p, Node **head, Node **tail)
{
    size_t for_line = p->line;
    size_t start, end;
    if (scan_c(p, SCAN_TO_BRACE, &start, &end) != 0) {
        return -1;
    }
    char *head_expr = p_dup_trim(p, p->src + start, p->src + end);
    if (head_expr == NULL) {
        return -1;
    }
    if (head_expr[0] == '\0') {
        perr(p, "missing for-head between 'for' and '{'");
        return -1;
    }
    advance(p); /* '{' */

    Node *n = new_node(p, N_FOR);
    if (n == NULL) {
        return -1;
    }
    n->line = for_line;
    n->expr = head_expr;
    Node *body_tail = NULL;
    if (parse_body(p, &n->then, &body_tail) != 0) {
        return -1;
    }
    if (peek(p) != '}') {
        return perr(p, "expected '}' to close the for-branch");
    }
    advance(p);
    return append_node(head, tail, n);
}

/* Parses one tag (open/close/comment/doctype) starting at '<'.
 * Interpolations are recognized inside quoted attribute values;
 * `name?={ cond }` renders a boolean attribute. */
static int parse_element(Parser *p, Node **head, Node **tail)
{
    size_t tag_start = p->pos;
    size_t tag_line = p->line;
    advance(p); /* '<' */

    /* HTML comments: <!-- ... --> (may contain '>') */
    if (peek(p) == '!' && peek_at(p, 1) == '-' && peek_at(p, 2) == '-') {
        while (p->pos < p->len && !(peek(p) == '-' && peek_at(p, 1) == '-' &&
                                    peek_at(p, 2) == '>')) {
            advance(p);
        }
        if (p->pos >= p->len) {
            return perr(p, "unterminated <!-- comment");
        }
        advance_n(p, 3);
        return append_text(p, head, tail, p->src + tag_start, p->src + p->pos,
                           tag_line);
    }

    /* doctype: plain text up to '>' (no stack interaction) */
    if (peek(p) == '!') {
        while (p->pos < p->len && peek(p) != '>') {
            advance(p);
        }
        if (p->pos >= p->len) {
            return perr(p, "unterminated tag — missing '>'");
        }
        advance(p); /* '>' */
        return append_text(p, head, tail, p->src + tag_start, p->src + p->pos,
                           tag_line);
    }

    /* closing tag: read the name, then validate against the stack */
    if (peek(p) == '/') {
        advance(p);
        size_t name_start = p->pos;
        while (p->pos < p->len && (is_ident_char(peek(p)) || peek(p) == '-')) {
            advance(p);
        }
        size_t name_len = p->pos - name_start;
        while (p->pos < p->len && peek(p) != '>') {
            advance(p);
        }
        if (p->pos >= p->len) {
            return perr(p, "unterminated tag — missing '>'");
        }
        advance(p); /* '>' */
        if (name_len == 0) {
            return perr_at(p, tag_start, "empty closing tag name");
        }
        if (is_void_tag(p->src + name_start, name_len)) {
            return perr_at(p, tag_start,
                           "</%.*s> — void elements cannot have a closing "
                           "tag",
                           (int)name_len, p->src + name_start);
        }
        if (p->tag_depth == 0) {
            return perr_at(p, tag_start,
                           "</%.*s> closes nothing — no tag is open",
                           (int)name_len, p->src + name_start);
        }
        TagFrame *top = &p->tag_stack[p->tag_depth - 1];
        if (top->name_len != name_len ||
            strncasecmp(top->name, p->src + name_start, name_len) != 0) {
            return perr_at(p, tag_start,
                           "</%.*s> closes nothing — expected </%s> "
                           "(opened at line %zu)",
                           (int)name_len, p->src + name_start, top->name,
                           top->line);
        }
        p->tag_depth--; /* match: pop */
        return append_text(p, head, tail, p->src + tag_start, p->src + p->pos,
                           tag_line);
    }

    /* open tag: read the name for the script/style raw-text rule */
    if (!is_ident_start(peek(p))) {
        return perr(p, "expected a tag name after '<'");
    }
    size_t name_start = p->pos;
    while (p->pos < p->len && (is_ident_char(peek(p)) || peek(p) == '-')) {
        advance(p);
    }
    size_t name_len = p->pos - name_start;
    if (name_len > TAG_NAME_MAX) {
        return perr(p, "tag name too long (max %d characters)", TAG_NAME_MAX);
    }
    bool is_script =
        (name_len == 6 && strncasecmp(p->src + name_start, "script", 6) == 0);
    bool is_style =
        (name_len == 5 && strncasecmp(p->src + name_start, "style", 5) == 0);
    bool raw_text = is_script || is_style;
    bool void_tag = is_void_tag(p->src + name_start, name_len);

    /* scan the tag body: quotes switch modes, '{' inside quotes is
     * an attribute interpolation, 'name?={' a boolean attribute */
    char quote = 0;
    size_t flush_to = tag_start;     /* text flushed up to here */
    size_t attr_name_start = p->pos; /* next attribute name candidate */
    size_t attr_name_end = p->pos;   /* set when the '=' is passed */
    size_t flushed_line = tag_line;

    for (;;) {
        if (p->pos >= p->len) {
            return perr(p, "unterminated tag — missing '>'");
        }
        char c = peek(p);

        if (quote != 0) {
            if (c == '{') {
                /* flush pending text, then the attribute expression
                 * with the context derived from the attribute name */
                int ctx = classify_attr(p, attr_name_start, attr_name_end);
                if (ctx < 0) {
                    return -1;
                }
                if (append_text(p, head, tail, p->src + flush_to,
                                p->src + p->pos, flushed_line) != 0) {
                    return -1;
                }
                if (parse_interp(p, head, tail, ctx) != 0) {
                    return -1; /* still inside the quote afterwards */
                }
                flush_to = p->pos;
                continue;
            }
            if (c == quote) {
                quote = 0;
            }
            advance(p);
            continue;
        }

        if (c == '"' || c == '\'') {
            quote = c;
            advance(p);
            continue;
        }
        if (c == '=') {
            attr_name_end = p->pos; /* remember the attribute name */
            advance(p);
            continue;
        }
        if (c == '{') {
            /* templ-style attribute expression: href={ expr } — the
             * generator adds the surrounding quotes. Recognized by
             * the '=' directly before the '{'. */
            if (p->pos > tag_start && p->src[p->pos - 1] == '=' &&
                attr_name_start < p->pos - 1) {
                int ctx = classify_attr(p, attr_name_start, attr_name_end);
                if (ctx < 0) {
                    return -1;
                }
                if (append_text(p, head, tail, p->src + flush_to,
                                p->src + p->pos, flushed_line) != 0) {
                    return -1;
                }
                if (append_text(p, head, tail, "\"", "\"" + 1, p->line) != 0) {
                    return -1;
                }
                if (parse_interp(p, head, tail, ctx) != 0) {
                    return -1;
                }
                if (append_text(p, head, tail, "\"", "\"" + 1, p->line) != 0) {
                    return -1;
                }
                flush_to = p->pos;
                continue;
            }
            return perr(p, "interpolation outside a quoted attribute "
                           "value is not supported");
        }
        if (c == '?' && peek_at(p, 1) == '=') {
            /* boolean attribute: name?={ cond } */
            if (attr_name_start >= p->pos) {
                return perr(p, "missing attribute name before '?='");
            }
            if (append_text(p, head, tail, p->src + flush_to,
                            p->src + attr_name_start, flushed_line) != 0) {
                return -1;
            }
            size_t attr_line = p->line;
            size_t attr_name_len = p->pos - attr_name_start;
            advance_n(p, 2); /* "?=" */
            if (peek(p) != '{') {
                return perr(p, "expected '{' after '?=' (boolean "
                               "attributes use name?={ cond })");
            }
            Node *n = new_node(p, N_IF);
            if (n == NULL) {
                return -1;
            }
            n->line = attr_line;
            advance(p); /* '{' */
            size_t start, end;
            if (scan_c(p, SCAN_MATCH_BRACE, &start, &end) != 0) {
                return -1;
            }
            n->expr = p_dup_trim(p, p->src + start, p->src + end);
            if (n->expr == NULL) {
                return -1;
            }
            if (n->expr[0] == '\0') {
                perr(p, "missing condition in name?={ cond }");
                return -1;
            }
            /* the rendered branch is " <attrname>" */
            Node *an = new_node(p, N_TEXT);
            if (an == NULL) {
                return -1;
            }
            an->text = malloc(attr_name_len + 2);
            if (an->text == NULL || allocs_add(p->allocs, an->text) == NULL) {
                perr(p, "out of memory");
                return -1;
            }
            an->text[0] = ' ';
            memcpy(an->text + 1, p->src + attr_name_start, attr_name_len);
            an->text[1 + attr_name_len] = '\0';
            an->text_len = attr_name_len + 1;
            n->then = an;
            if (append_node(head, tail, n) != 0) {
                return -1;
            }
            flush_to = p->pos;
            attr_name_start = p->pos;
            continue;
        }
        if (c == '>') {
            advance(p);
            if (append_text(p, head, tail, p->src + flush_to, p->src + p->pos,
                            flushed_line) != 0) {
                return -1;
            }
            break; /* tag done */
        }
        if (isspace((unsigned char)c)) {
            /* whitespace outside quotes ends an attribute value */
            advance(p);
            size_t after = p->pos;
            while (after < p->len && isspace((unsigned char)p->src[after])) {
                after++;
            }
            attr_name_start = after;
            continue;
        }
        advance(p);
    }

    /* Structure validation: void tags never open a frame; a self-
     * closing slash on anything else is an error — browsers IGNORE
     * the '/', so <div/> silently becomes an unclosed <div>. */
    bool self_closing =
        p->pos >= 2 && p->src[p->pos - 2] == '/' && p->src[p->pos - 1] == '>';
    if (!void_tag) {
        if (self_closing) {
            return perr_at(p, tag_start,
                           "<%.*s/> — non-void elements need a real "
                           "closing tag (browsers ignore the '/')",
                           (int)name_len, p->src + name_start);
        }
        if (p->tag_depth == TAG_STACK_MAX) {
            return perr_at(p, tag_start,
                           "tags nested deeper than %d — likely an "
                           "unclosed tag",
                           TAG_STACK_MAX);
        }
        TagFrame *frame = &p->tag_stack[p->tag_depth++];
        memcpy(frame->name, p->src + name_start, name_len);
        frame->name[name_len] = '\0';
        frame->name_len = name_len;
        frame->pos = tag_start;
        frame->line = tag_line;
    }

    /* script/style: raw text until the matching close tag. Braces
     * pass through uninterpreted — CSS rules and JS blocks need
     * them, and raw mode never interpolates (build strings in C and
     * use @raw instead). */
    if (raw_text) {
        const char *close = is_script ? "</script" : "</style";
        size_t cl = strlen(close);
        size_t content_start = p->pos;
        size_t content_line = p->line;
        while (p->pos < p->len &&
               !(peek(p) == '<' && p->pos + cl <= p->len &&
                 strncasecmp(p->src + p->pos, close, cl) == 0)) {
            advance(p);
        }
        if (p->pos >= p->len) {
            return perr(p, "missing </%s> for the raw-text element",
                        is_script ? "script" : "style");
        }
        if (append_text(p, head, tail, p->src + content_start, p->src + p->pos,
                        content_line) != 0) {
            return -1;
        }
    }
    return 0;
}

/* Parses body nodes until the closing '}' of the current block. The
 * terminator is NOT consumed (the caller checks it). */
static int parse_body(Parser *p, Node **head, Node **tail)
{
    for (;;) {
        char c = peek(p);
        if (c == '\0') {
            return perr(p, "unterminated block — missing '}'");
        }
        if (c == '}') {
            return 0; /* caller consumes */
        }
        if (c == '<') {
            if (parse_element(p, head, tail) != 0) {
                return -1;
            }
            continue;
        }
        if (c == '{') {
            if (parse_interp(p, head, tail, CTX_TEXT) != 0) {
                return -1;
            }
            continue;
        }
        if (c == '@') {
            if (parse_call(p, head, tail) != 0) {
                return -1;
            }
            continue;
        }

        /* text run: statement keywords only count at run starts */
        size_t run_start = p->pos;
        size_t run_line = p->line;
        size_t k = p->pos;
        while (k < p->len && isspace((unsigned char)p->src[k])) {
            k++;
        }
        bool starts_if = k + 2 <= p->len && strncmp(p->src + k, "if", 2) == 0 &&
                         !is_ident_char(k + 2 < p->len ? p->src[k + 2] : '\0');
        bool starts_for = k + 3 <= p->len &&
                          strncmp(p->src + k, "for", 3) == 0 &&
                          !is_ident_char(k + 3 < p->len ? p->src[k + 3] : '\0');
        bool starts_else =
            k + 4 <= p->len && strncmp(p->src + k, "else", 4) == 0 &&
            !is_ident_char(k + 4 < p->len ? p->src[k + 4] : '\0');
        if (starts_else) {
            /* parse_if handles else AFTER an if-branch; an else at a
             * text run start here has no preceding if. Report at the
             * keyword position, not at the run start. */
            return perr_at(p, k, "unexpected 'else' — no preceding 'if'");
        }
        if (starts_if || starts_for) {
            advance_n(p, k - p->pos); /* drop the leading whitespace */
            /* starts_* guarantee the keyword matches; consume it */
            (void)eat_keyword(p, starts_if ? "if" : "for");
            if (starts_if) {
                if (parse_if(p, head, tail) != 0) {
                    return -1;
                }
            } else {
                if (parse_for(p, head, tail) != 0) {
                    return -1;
                }
            }
            continue;
        }

        /* plain text: scan until a special char */
        advance(p);
        for (;;) {
            char t = peek(p);
            if (t == '\0') {
                return perr(p, "unterminated block — missing '}'");
            }
            if (t == '<' || t == '{' || t == '@') {
                break; /* handled by the main loop next iteration */
            }
            if (t == '}') {
                /* pure whitespace before '}' is the block terminator;
                 * anything else is a stray brace */
                bool only_ws = true;
                for (size_t i = run_start; i < p->pos; i++) {
                    if (!isspace((unsigned char)p->src[i])) {
                        only_ws = false;
                        break;
                    }
                }
                if (!only_ws) {
                    return perr(p, "unexpected '}' in text — escape "
                                   "braces with { \"}\" }");
                }
                return 0; /* terminator — caller consumes */
            }
            advance(p);
        }
        if (append_text(p, head, tail, p->src + run_start, p->src + p->pos,
                        run_line) != 0) {
            return -1;
        }
    }
}

/* ============================================================ */
/* child-block capture mode                                      */
/* ============================================================ */

/* Counts commas at the top level of a C parameter list (quote and
 * bracket aware) — 0 commas = exactly one parameter. */
static size_t count_top_level_commas(const char *s)
{
    size_t count = 0;
    int depth = 0;
    char quote = 0;
    for (; *s != '\0'; s++) {
        char c = *s;
        if (quote != 0) {
            if (c == '\\') {
                s++;
            } else if (c == quote) {
                quote = 0;
            }
            continue;
        }
        if (c == '"' || c == '\'') {
            quote = c;
        } else if (c == '(' || c == '[' || c == '{') {
            depth++;
        } else if (c == ')' || c == ']' || c == '}') {
            depth--;
        } else if (c == ',' && depth == 0) {
            count++;
        }
    }
    return count;
}

/* Extracts the declared NAME of a single-parameter list, e.g.
 * "const HomePageData *p" -> "p". Plain declarators only: arrays,
 * function pointers and unnamed parameters yield false. */
static bool extract_param_name(const char *s, const char **ns, const char **ne)
{
    size_t len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1])) {
        len--;
    }
    if (len == 0 || !is_ident_char(s[len - 1])) {
        return false;
    }
    size_t e = len;
    while (e > 0 && is_ident_char(s[e - 1])) {
        e--;
    }
    if (e > 0) {
        char prev = s[e - 1];
        if (!isspace((unsigned char)prev) && prev != '*') {
            return false; /* "int arr[8]", "void (*cb)(int)" ... */
        }
    }
    *ns = s + e;
    *ne = s + len;
    return true;
}

typedef enum {
    BLOCK_UNTYPED, /* (TplOut *out, void *tpl_data) — with()/ctx */
    BLOCK_VOID0,   /* (TplOut *out) — enclosing component has no params */
    BLOCK_ONE,     /* (TplOut *out, <enclosing params>) — captured */
} BlockMode;

/* Decides how a call-with-block's lambda is generated. Without an
 * explicit "with (expr)" and with an enclosing component that has
 * zero or one plain parameter, the block CAPTURES that parameter
 * through the children data pointer — the block body can reference
 * it directly, like a closure over the parameter. */
static BlockMode block_mode(const Node *n, const char **ns, const char **ne)
{
    *ns = NULL;
    *ne = NULL;
    if (n->data_expr != NULL || n->comp == NULL) {
        return BLOCK_UNTYPED;
    }
    const char *params = n->comp->params;
    if (params[0] == '\0' || strcmp(params, "void") == 0) {
        return BLOCK_VOID0;
    }
    if (count_top_level_commas(params) == 0 &&
        extract_param_name(params, ns, ne)) {
        return BLOCK_ONE;
    }
    return BLOCK_UNTYPED;
}

/* ============================================================ */
/* code generation                                                */
/* ============================================================ */

typedef struct {
    FILE *out_c;
    const char *in_name;
    /* collected call-with-block nodes (post-order: innermost first) */
    Node **lambdas;
    size_t lambda_n;
    size_t lambda_cap;
    int failed;
} Emitter;

static void emit_line_directive(Emitter *e, size_t line)
{
    fprintf(e->out_c, "#line %zu \"%s\"\n", line, e->in_name);
}

static void emit_indent(FILE *f, size_t depth)
{
    for (size_t i = 0; i < depth * 4; i++) {
        fputc(' ', f);
    }
}

/* Appends one source char as C string content into sb. */
static void emit_c_char(SBuf *sb, char c)
{
    switch (c) {
    case '"':
        sb_puts(sb, "\\\"");
        break;
    case '\\':
        sb_puts(sb, "\\\\");
        break;
    case '\n':
        sb_puts(sb, "\\n");
        break;
    case '\t':
        sb_puts(sb, "\\t");
        break;
    case '\r':
        sb_puts(sb, "\\r");
        break;
    default:
        if ((unsigned char)c < 0x20 || (unsigned char)c == 0x7f) {
            char tmp[8];
            snprintf(tmp, sizeof(tmp), "\\%03o", (unsigned char)c);
            sb_puts(sb, tmp);
        } else {
            sb_putn(sb, &c, 1);
        }
        break;
    }
}

/* Collects call-with-block nodes in post-order (innermost lambda
 * first) and assigns + registers their generated names. */
static int collect_lambdas(Node *n, Emitter *e)
{
    for (; n != NULL; n = n->next) {
        if (n->type == N_IF || n->type == N_FOR) {
            if (n->type == N_IF && n->otherwise != NULL) {
                if (collect_lambdas(n->otherwise, e) != 0) {
                    return -1;
                }
            }
            if (collect_lambdas(n->then, e) != 0) {
                return -1;
            }
        } else if (n->type == N_CALL) {
            if (collect_lambdas(n->block, e) != 0) {
                return -1;
            }
            /* Only children-calls get a lambda; the block forms
             * (@fragment/@once) render inline in the caller. */
            if (n->block != NULL && !is_builtin_callee(n->callee)) {
                char buf[64];
                snprintf(buf, sizeof(buf), "tpl__block_%zu", e->lambda_n + 1);
                n->gen_name = strdup(buf);
                if (n->gen_name == NULL) {
                    e->failed = 1;
                    return -1;
                }
                if (e->lambda_n == e->lambda_cap) {
                    size_t cap = e->lambda_cap == 0 ? 8 : e->lambda_cap * 2;
                    Node **tmp = realloc(e->lambdas, cap * sizeof(*tmp));
                    if (tmp == NULL) {
                        e->failed = 1;
                        return -1;
                    }
                    e->lambdas = tmp;
                    e->lambda_cap = cap;
                }
                e->lambdas[e->lambda_n++] = n;
            }
        }
    }
    return 0;
}

static int emit_nodes(Node *n, Emitter *e, size_t depth);

/* Emits an if/else-if/else chain (the parse tree chains else-if as
 * nested N_IF nodes in `otherwise`). */
static int emit_if_chain(Node *n, Emitter *e, size_t depth)
{
    bool first = true;
    for (;;) {
        emit_line_directive(e, n->line);
        emit_indent(e->out_c, depth);
        if (first) {
            fprintf(e->out_c, "if (%s) {\n", n->expr);
        } else {
            fprintf(e->out_c, "} else if (%s) {\n", n->expr);
        }
        first = false;
        if (emit_nodes(n->then, e, depth + 1) != 0) {
            return -1;
        }
        Node *o = n->otherwise;
        if (o == NULL) {
            emit_indent(e->out_c, depth);
            fprintf(e->out_c, "}\n");
            return 0;
        }
        if (o->type == N_IF && o->next == NULL) {
            n = o; /* continue the chain with "} else if" */
            continue;
        }
        emit_indent(e->out_c, depth);
        fprintf(e->out_c, "} else {\n");
        if (emit_nodes(o, e, depth + 1) != 0) {
            return -1;
        }
        emit_indent(e->out_c, depth);
        fprintf(e->out_c, "}\n");
        return 0;
    }
}

/* Emits one component call (with or without a child block). */
static int emit_call(Node *n, Emitter *e, size_t depth)
{
    bool has_args = n->args != NULL && n->args[0] != '\0';
    emit_line_directive(e, n->line);
    if (strcmp(n->callee, "raw") == 0) {
        emit_indent(e->out_c, depth);
        fprintf(e->out_c, "tpl_raw(out, (%s));\n", n->args);
        return 0;
    }
    if (strcmp(n->callee, "fragment") == 0) {
        /* Fragment marker: the body ALWAYS executes, only the output
         * is filtered by the runtime (templ's semantics). */
        emit_indent(e->out_c, depth);
        fprintf(e->out_c, "{\n");
        emit_indent(e->out_c, depth + 1);
        fprintf(e->out_c, "tpl_frag_begin(out, (%s));\n", n->args);
        if (emit_nodes(n->block, e, depth + 1) != 0) {
            return -1;
        }
        emit_indent(e->out_c, depth + 1);
        fprintf(e->out_c, "tpl_frag_end(out);\n");
        emit_indent(e->out_c, depth);
        fprintf(e->out_c, "}\n");
        return 0;
    }
    if (strcmp(n->callee, "once") == 0) {
        emit_indent(e->out_c, depth);
        fprintf(e->out_c, "if (tpl_once_begin(out, &(%s))) {\n", n->args);
        if (emit_nodes(n->block, e, depth + 1) != 0) {
            return -1;
        }
        emit_indent(e->out_c, depth);
        fprintf(e->out_c, "}\n");
        return 0;
    }
    if (n->block == NULL) {
        emit_indent(e->out_c, depth);
        if (has_args) {
            fprintf(e->out_c, "tpl_%s(out, %s);\n", n->callee, n->args);
        } else {
            fprintf(e->out_c, "tpl_%s(out);\n", n->callee);
        }
        return 0;
    }

    /* child block: the lambda + the data binding (see block_mode) */
    const char *ns = NULL;
    const char *ne = NULL;
    BlockMode mode = block_mode(n, &ns, &ne);
    char fn[96]; /* gen_name or its adapter */
    char data[256];
    if (mode == BLOCK_VOID0) {
        snprintf(fn, sizeof(fn), "%s_adapter", n->gen_name);
        snprintf(data, sizeof(data), "NULL");
    } else if (mode == BLOCK_ONE) {
        snprintf(fn, sizeof(fn), "%s_adapter", n->gen_name);
        snprintf(data, sizeof(data), "(void *)(%.*s)", (int)(ne - ns), ns);
    } else {
        snprintf(fn, sizeof(fn), "%s", n->gen_name);
        snprintf(data, sizeof(data), "%s",
                 n->data_expr != NULL ? "(void *)(...)" : "NULL");
        /* full expression: */
        if (n->data_expr != NULL) {
            snprintf(data, sizeof(data), "(void *)(%s)", n->data_expr);
        }
    }
    emit_indent(e->out_c, depth);
    fprintf(e->out_c, "{\n");
    emit_indent(e->out_c, depth + 1);
    fprintf(e->out_c, "TplChildren tpl_children = {%s, %s};\n", fn, data);
    emit_indent(e->out_c, depth + 1);
    if (has_args) {
        fprintf(e->out_c, "tpl_%s(out, %s, &tpl_children);\n", n->callee,
                n->args);
    } else {
        fprintf(e->out_c, "tpl_%s(out, &tpl_children);\n", n->callee);
    }
    emit_indent(e->out_c, depth);
    fprintf(e->out_c, "}\n");
    return 0;
}

static int emit_nodes(Node *n, Emitter *e, size_t depth)
{
    while (n != NULL) {
        switch (n->type) {
        case N_TEXT: {
            /* merge consecutive text nodes into one tpl_lit */
            SBuf sb;
            sb.d = NULL;
            sb.len = 0;
            sb.cap = 0;
            sb.failed = 0;
            size_t total = 0;
            Node *t = n;
            while (t != NULL && t->type == N_TEXT) {
                for (size_t i = 0; i < t->text_len; i++) {
                    emit_c_char(&sb, t->text[i]);
                }
                total += t->text_len;
                t = t->next;
                if (total > 4000) {
                    break; /* keep literals at a sane size */
                }
            }
            if (sb.failed) {
                free(sb.d);
                e->failed = 1;
                return -1;
            }
            sb_putn(&sb, "\0", 1); /* NUL-terminate for %s */
            emit_indent(e->out_c, depth);
            fprintf(e->out_c, "tpl_lit(out, \"%s\");\n",
                    sb.d != NULL ? sb.d : "");
            free(sb.d);
            n = t;
            continue;
        }
        case N_INTERP:
            if (n->children) {
                emit_line_directive(e, n->line);
                emit_indent(e->out_c, depth);
                fprintf(e->out_c,
                        "if (children != NULL && children->fn != NULL) {\n");
                emit_indent(e->out_c, depth + 1);
                fprintf(e->out_c, "children->fn(out, children->data);\n");
                emit_indent(e->out_c, depth);
                fprintf(e->out_c, "}\n");
            } else {
                emit_line_directive(e, n->line);
                emit_indent(e->out_c, depth);
                switch (n->ctx) {
                case CTX_TEXT:
                    fprintf(e->out_c, "tpl_esc(out, (%s));\n", n->expr);
                    break;
                case CTX_ATTR:
                    fprintf(e->out_c, "tpl_attr(out, (%s));\n", n->expr);
                    break;
                case CTX_URL:
                    fprintf(e->out_c, "tpl_attr_url(out, (%s));\n", n->expr);
                    break;
                case CTX_CSS:
                    fprintf(e->out_c, "tpl_attr_css(out, (%s));\n", n->expr);
                    break;
                }
            }
            break;
        case N_CALL:
            if (emit_call(n, e, depth) != 0) {
                return -1;
            }
            break;
        case N_IF:
            if (emit_if_chain(n, e, depth) != 0) {
                return -1;
            }
            break;
        case N_FOR:
            emit_line_directive(e, n->line);
            emit_indent(e->out_c, depth);
            fprintf(e->out_c, "for (%s) {\n", n->expr);
            if (emit_nodes(n->then, e, depth + 1) != 0) {
                return -1;
            }
            emit_indent(e->out_c, depth);
            fprintf(e->out_c, "}\n");
            break;
        }
        n = n->next;
    }
    return 0;
}

/* ============================================================ */
/* top level                                                      */
/* ============================================================ */

/* Basename without directories. */
static const char *path_base(const char *path)
{
    const char *slash = strrchr(path, '/');
    const char *base = slash != NULL ? slash + 1 : path;
    const char *bslash = strrchr(base, '\\');
    return bslash != NULL ? bslash + 1 : base;
}

/* "page.thtml" -> "page" (no directories, no extension). */
static char *stem_name(const char *path, Allocs *a)
{
    const char *base = path_base(path);
    size_t n = strlen(base);
    if (n > 6 && strcmp(base + n - 6, ".thtml") == 0) {
        n -= 6;
    }
    char *s = malloc(n + 1);
    if (allocs_add(a, s) == NULL) {
        return NULL;
    }
    memcpy(s, base, n);
    s[n] = '\0';
    return s;
}

/* "page" -> "PAGE_TEMPL_H" (identifier-safe). */
static char *guard_name(const char *stem, Allocs *a)
{
    size_t n = strlen(stem);
    char *s = malloc(n + 16);
    if (allocs_add(a, s) == NULL) {
        return NULL;
    }
    if (n == 0) {
        s[0] = 'C';
        s[1] = 'T';
        s[2] = 'M';
        s[3] = 'P';
        s[4] = 'L';
        n = 4;
    } else {
        for (size_t i = 0; i < n; i++) {
            char c = stem[i];
            s[i] = isalnum((unsigned char)c) ? (char)toupper((unsigned char)c)
                                             : '_';
        }
    }
    memcpy(s + n, "_TEMPL_H", strlen("_TEMPL_H") + 1);
    return s;
}

/* Runtime symbols a component name must not collide with after
 * the tpl_ prefix is added. */
static bool name_is_reserved(const char *name)
{
    static const char *reserved[] = {
        "lit", "lit_n", "raw", "raw_n", "esc", "attr",     "int",
        "fmt", "url",   "ok",  "str",   "len", "fragment", "once",
    };
    if (strncmp(name, "tpl_", 4) == 0) {
        return true;
    }
    for (size_t i = 0; i < sizeof(reserved) / sizeof(reserved[0]); i++) {
        if (strcmp(name, reserved[i]) == 0) {
            return true;
        }
    }
    return false;
}

int ctmpl_compile(const char *src, size_t src_len, const char *in_name,
                  FILE *out_h, FILE *out_c, CtmplError *err)
{
    static const char *default_name = "input";
    if (err == NULL) {
        return -1;
    }
    err->message[0] = '\0';
    err->line = err->col = 0;
    if (src == NULL || out_h == NULL || out_c == NULL) {
        snprintf(err->message, sizeof(err->message), "invalid arguments");
        return -1;
    }
    if (in_name == NULL) {
        in_name = default_name;
    }

    Allocs allocs = {0};
    Parser p = {.src = src,
                .len = src_len,
                .pos = 0,
                .line = 1,
                .line_start = 0,
                .err = err,
                .allocs = &allocs};
    int result = -1;
    Component *comps = NULL;
    Component *comps_tail = NULL;
    char **hash_lines = NULL;
    size_t hash_count = 0;
    char **once_names = NULL;
    size_t once_count = 0;
    Emitter e = {.out_c = out_c, .in_name = in_name};

    /* ---- top level: #-lines and components ---- */
    for (;;) {
        skip_ws_comments(&p);
        if (p.pos >= p.len) {
            break;
        }
        if (peek(&p) == '#') {
            /* #-line: copied verbatim into the generated .h */
            size_t start = p.pos;
            while (p.pos < p.len && peek(&p) != '\n') {
                advance(&p);
            }
            char *line = p_dup_raw(&p, p.src + start, p.src + p.pos);
            if (line == NULL) {
                goto out;
            }
            char **tmp =
                realloc(hash_lines, (hash_count + 1) * sizeof(*hash_lines));
            if (tmp == NULL) {
                perr(&p, "out of memory");
                goto out;
            }
            hash_lines = tmp;
            hash_lines[hash_count++] = line;
            continue;
        }
        size_t decl_line = p.line;
        if (eat_keyword(&p, "once")) {
            /* once <ident>: declares a render-once handle — emitted as
             * a file-static TplOnce in the generated .c */
            skip_ws(&p);
            char *hname = read_ident(&p);
            if (hname == NULL) {
                goto out;
            }
            for (size_t i = 0; i < once_count; i++) {
                if (strcmp(once_names[i], hname) == 0) {
                    perr(&p, "once handle '%s' is already declared", hname);
                    goto out;
                }
            }
            char **tmp =
                realloc(once_names, (once_count + 1) * sizeof(*once_names));
            if (tmp == NULL) {
                perr(&p, "out of memory");
                goto out;
            }
            once_names = tmp;
            once_names[once_count++] = hname;
            continue;
        }
        if (!eat_keyword(&p, "component")) {
            perr(&p, "expected 'component', 'once' or '#<directive>'");
            goto out;
        }
        skip_ws(&p);
        char *name = read_ident(&p);
        if (name == NULL) {
            goto out;
        }
        if (name_is_reserved(name)) {
            perr(&p, "component name '%s' collides with the runtime", name);
            goto out;
        }
        skip_ws(&p);
        if (peek(&p) != '(') {
            perr(&p, "expected '(' after the component name");
            goto out;
        }
        advance(&p); /* '(' */
        size_t start, end;
        if (scan_c(&p, SCAN_MATCH_PAREN, &start, &end) != 0) {
            goto out;
        }
        char *params = p_dup_trim(&p, p.src + start, p.src + end);
        if (params == NULL) {
            goto out;
        }
        skip_ws(&p);
        if (peek(&p) != '{') {
            perr(&p, "expected '{' to open the component body");
            goto out;
        }
        advance(&p);

        /* the component must exist before its body is parsed: blocks
         * capture the enclosing component's parameter list */
        Component *c = calloc(1, sizeof(*c));
        if (allocs_add(&allocs, c) == NULL) {
            perr(&p, "out of memory");
            goto out;
        }
        c->name = name;
        c->params = params;
        c->line = decl_line;
        p.current_comp = c;
        p.tag_depth = 0; /* tag stack is per component */

        Node *body = NULL;
        Node *body_tail = NULL;
        if (parse_body(&p, &body, &body_tail) != 0) {
            goto out;
        }
        c->body = body;
        p.current_comp = NULL;
        if (p.tag_depth > 0) {
            /* unclosed tags: point at the innermost one */
            TagFrame *top = &p.tag_stack[p.tag_depth - 1];
            perr_at(&p, top->pos,
                    "unclosed <%s> (opened at line %zu) — tags must be "
                    "closed within the component",
                    top->name, top->line);
            goto out;
        }
        if (peek(&p) != '}') {
            perr(&p, "expected '}' to close the component");
            goto out;
        }
        advance(&p);

        if (comps == NULL) {
            comps = c;
        } else {
            comps_tail->next = c;
        }
        comps_tail = c;
    }

    if (comps == NULL) {
        /* positionless: there is nothing to point at */
        snprintf(p.err->message, sizeof(p.err->message), "no components found");
        p.err->line = p.err->col = 0;
        goto out;
    }

    /* ---- codegen ---- */
    char *stem = stem_name(in_name, &allocs);
    char *guard = guard_name(stem != NULL ? stem : "", &allocs);
    if (stem == NULL || guard == NULL) {
        goto out;
    }

    /* header: guard, includes, #-lines, prototypes */
    fprintf(out_h, "/* Generated by ctmpl from %s - DO NOT EDIT */\n", in_name);
    fprintf(out_h, "#ifndef %s\n#define %s\n\n", guard, guard);
    fprintf(out_h, "#include \"c_http_tpl.h\"\n");
    if (hash_count > 0) {
        fprintf(out_h, "\n");
        for (size_t i = 0; i < hash_count; i++) {
            fprintf(out_h, "%s\n", hash_lines[i]);
        }
    }
    fprintf(out_h, "\n");
    for (Component *c = comps; c != NULL; c = c->next) {
        bool no_params = c->params[0] == '\0' || strcmp(c->params, "void") == 0;
        if (no_params) {
            fprintf(out_h, "void tpl_%s(TplOut *out);\n", c->name);
        } else {
            fprintf(out_h, "void tpl_%s(TplOut *out, %s);\n", c->name,
                    c->params);
        }
    }
    fprintf(out_h, "\n#endif /* %s */\n", guard);

    /* implementation */
    fprintf(out_c, "/* Generated by ctmpl from %s - DO NOT EDIT */\n", in_name);
    fprintf(out_c, "#include \"%s_templ.h\"\n\n", stem);

    /* once handles declared with "once <name>" — file-static, the
     * fired-state lives per render in the TplOut */
    if (once_count > 0) {
        fprintf(out_c, "/* render-once handles (see @once) */\n");
        for (size_t i = 0; i < once_count; i++) {
            fprintf(out_c, "static TplOnce %s = {.name = \"%s\"};\n",
                    once_names[i], once_names[i]);
        }
        fprintf(out_c, "\n");
    }

    /* lambdas first, in the collected order (innermost before the
     * outer lambda that references it) */
    for (Component *c = comps; c != NULL; c = c->next) {
        if (collect_lambdas(c->body, &e) != 0) {
            goto out;
        }
    }
    for (size_t i = 0; i < e.lambda_n; i++) {
        Node *n = e.lambdas[i];
        const char *ns = NULL;
        const char *ne = NULL;
        BlockMode mode = block_mode(n, &ns, &ne);
        if (mode == BLOCK_VOID0) {
            fprintf(out_c, "static void %s(TplOut *out)\n{\n", n->gen_name);
        } else if (mode == BLOCK_ONE) {
            fprintf(out_c, "static void %s(TplOut *out, %s)\n{\n", n->gen_name,
                    n->comp->params);
        } else {
            fprintf(out_c, "static void %s(TplOut *out, void *tpl_data)\n{\n",
                    n->gen_name);
            fprintf(out_c, "    /* child data: 'with (...)' via tpl_data, or "
                           "out->ctx */\n");
        }
        if (emit_nodes(n->block, &e, 1) != 0) {
            goto out;
        }
        fprintf(out_c, "}\n");
        if (mode != BLOCK_UNTYPED) {
            /* adapter matching TplChildren.fn: (TplOut *, void *) —
             * the void * converts implicitly back to the captured
             * parameter type (legal C, no function-pointer UB) */
            fprintf(out_c,
                    "static void %s_adapter(TplOut *out, void *tpl_data)\n"
                    "{\n",
                    n->gen_name);
            if (mode == BLOCK_VOID0) {
                fprintf(out_c, "    (void)tpl_data;\n    %s(out);\n",
                        n->gen_name);
            } else {
                fprintf(out_c, "    %s(out, tpl_data);\n", n->gen_name);
            }
            fprintf(out_c, "}\n");
        }
        fprintf(out_c, "\n");
    }

    /* component functions */
    for (Component *c = comps; c != NULL; c = c->next) {
        bool no_params = c->params[0] == '\0' || strcmp(c->params, "void") == 0;
        if (no_params) {
            fprintf(out_c, "void tpl_%s(TplOut *out)\n{\n", c->name);
        } else {
            fprintf(out_c, "void tpl_%s(TplOut *out, %s)\n{\n", c->name,
                    c->params);
        }
        emit_line_directive(&e, c->line);
        if (c->body == NULL) {
            fprintf(out_c, "    (void)out;\n"); /* empty body */
        } else if (emit_nodes(c->body, &e, 1) != 0) {
            goto out;
        }
        fprintf(out_c, "}\n\n");
    }

    result = 0;

out:
    /* gen_name strings were strdup'd (not allocs-tracked) */
    for (size_t i = 0; i < e.lambda_n; i++) {
        free(e.lambdas[i]->gen_name);
    }
    free(e.lambdas);  /* the array; the nodes are allocs-tracked */
    free(hash_lines); /* the array; the strings are allocs-tracked */
    free(once_names); /* the array; the strings are allocs-tracked */
    allocs_free(&allocs);
    if (result != 0 && err->message[0] == '\0') {
        snprintf(err->message, sizeof(err->message), "internal error");
    }
    return result;
}