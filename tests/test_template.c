/* Unit + integration tests for the template runtime (c_http_tpl).
 *
 * Unit tests cover the writer, escapers and value helpers directly;
 * integration tests run a real server in a thread and verify the
 * response path for small bodies (fixed buffer), large bodies
 * (dyn_body) and the interaction with http_error()/gzip.
 */
#include <arpa/inet.h>
#include <limits.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "c_http.h"
#include "c_http_tpl.h"
#include "test.h"

#define TEST_PORT 18461

/* ------------------------------------------------------------------ */
/* server plumbing (same pattern as test_http.c)                       */
/* ------------------------------------------------------------------ */

static HttpServer g_srv;
static uint16_t g_port = 0;

static void *server_thread(void *arg)
{
    (void)arg;
    http_listen(&g_srv);
    return NULL;
}

static size_t raw_request(const char *data, char *out, size_t outsz)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return 0;
    }
    struct timeval tv = {.tv_sec = 5, .tv_usec = 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(g_port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    size_t total = 0;
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
        size_t len = strlen(data);
        size_t sent = 0;
        while (sent < len) {
            ssize_t s = send(fd, data + sent, len - sent, 0);
            if (s <= 0) {
                break;
            }
            sent += (size_t)s;
        }
        while (total + 1 < outsz) {
            ssize_t r = recv(fd, out + total, outsz - 1 - total, 0);
            if (r <= 0) {
                break;
            }
            total += (size_t)r;
        }
    }
    out[total] = '\0';
    close(fd);
    return total;
}

static bool wait_listening(uint16_t port)
{
    for (int i = 0; i < 200; i++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in a;
        memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET;
        a.sin_port = htons(port);
        inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
        if (connect(fd, (struct sockaddr *)&a, sizeof(a)) == 0) {
            close(fd);
            return true;
        }
        close(fd);
        nanosleep(&(struct timespec){.tv_nsec = 20000000L}, NULL);
    }
    return false;
}

/* Finds the body start in a raw response (after the blank line). */
static const char *response_body(const char *raw)
{
    const char *p = strstr(raw, "\r\n\r\n");
    return p != NULL ? p + 4 : "";
}

/* Extracts a header value ("Content-Length: 123" -> 123 via *out).
 * Case-insensitive search without strcasestr (a GNU extension). */
static bool response_header(const char *raw, const char *key, size_t *out)
{
    size_t klen = strlen(key);
    for (const char *p = raw; *p != '\0'; p++) {
        if (p > raw && p[-1] != '\n') {
            continue; /* match only at a line start */
        }
        if (strncasecmp(p, key, klen) != 0 || p[klen] != ':') {
            continue;
        }
        const char *v = p + klen + 1;
        while (*v == ' ') {
            v++;
        }
        *out = (size_t)strtoull(v, NULL, 10);
        return true;
    }
    return false;
}

/* ------------------------------------------------------------------ */
/* unit tests: writer                                                  */
/* ------------------------------------------------------------------ */

static void test_writer_basics(void)
{
    TplOut out = {0};

    CHECK(tpl_len(&out) == 0);
    CHECK(strcmp(tpl_str(&out), "") == 0);

    tpl_lit(&out, "hello");
    tpl_lit(&out, NULL); /* tolerated */
    tpl_lit(&out, "");
    CHECK(tpl_len(&out) == 5);
    CHECK(strcmp(tpl_str(&out), "hello") == 0);

    /* NUL bytes: length-aware writes must not stop at them. */
    tpl_lit_n(&out, "a\0b", 3);
    CHECK(tpl_len(&out) == 8);
    CHECK(memcmp(out.data, "helloa\0b", 8) == 0);

    /* The view is NUL-terminated at len, not inside the payload. */
    CHECK(strcmp(tpl_str(&out), "helloa") == 0);

    /* Buffer growth across doubling steps. */
    for (int i = 0; i < 1000; i++) {
        tpl_lit(&out, "0123456789"); /* 10 KB total */
    }
    CHECK(tpl_len(&out) == 8 + 10000);
    CHECK(out.data[tpl_len(&out) - 1] == '9');
    CHECK(tpl_ok(&out));

    tpl_out_free(&out);
    CHECK(out.data == NULL && out.len == 0 && out.cap == 0);
    CHECK(out.arena == NULL && !out.failed);
}

static void test_writer_failed_is_noop(void)
{
    TplOut out = {0};
    out.failed = true; /* simulate a sticky allocation failure */

    tpl_lit(&out, "x");
    tpl_esc(&out, "<y>");
    CHECK(tpl_len(&out) == 0);
    CHECK(!tpl_ok(&out));

    tpl_out_free(&out);
    CHECK(tpl_ok(&out)); /* free resets the state */
}

/* ------------------------------------------------------------------ */
/* unit tests: escaping                                                */
/* ------------------------------------------------------------------ */

static void test_esc_entities(void)
{
    TplOut out = {0};
    tpl_esc(&out, "<a href=\"x\">&amp;'</script>");
    CHECK(strcmp(tpl_str(&out),
                 "&lt;a href=&#34;x&#34;&gt;&amp;amp;&#39;&lt;/script&gt;") ==
          0);
    CHECK(tpl_len(&out) == strlen(tpl_str(&out)));
    tpl_out_free(&out);
}

static void test_esc_null_and_plain(void)
{
    TplOut out = {0};
    tpl_esc(&out, NULL); /* NULL writes nothing */
    tpl_esc(&out, "plain text, no specials");
    CHECK(strcmp(tpl_str(&out), "plain text, no specials") == 0);
    tpl_out_free(&out);
}

static void test_attr_escaping(void)
{
    TplOut out = {0};
    tpl_attr(&out, "Max & \"the\" <best> 'kid'");
    CHECK(strcmp(tpl_str(&out),
                 "Max &amp; &#34;the&#34; &lt;best&gt; &#39;kid&#39;") == 0);
    tpl_out_free(&out);
}

/* ------------------------------------------------------------------ */
/* unit tests: value helpers                                           */
/* ------------------------------------------------------------------ */

static void test_tpl_int(void)
{
    TplOut out = {0};
    CHECK(strcmp(tpl_int(&out, 0), "0") == 0);
    CHECK(strcmp(tpl_int(&out, 42), "42") == 0);
    CHECK(strcmp(tpl_int(&out, -42), "-42") == 0);
    CHECK(strcmp(tpl_int(&out, LLONG_MIN), "-9223372036854775808") == 0);
    CHECK(strcmp(tpl_int(&out, LLONG_MAX), "9223372036854775807") == 0);

    /* Arena strings survive until tpl_out_free(). */
    tpl_lit(&out, tpl_int(&out, 7));
    CHECK(strcmp(tpl_str(&out), "7") == 0);
    tpl_out_free(&out);
}

static void test_tpl_fmt(void)
{
    TplOut out = {0};
    CHECK(strcmp(tpl_fmt(&out, "%s has %d items", "max", 3),
                 "max has 3 items") == 0);
    CHECK(strcmp(tpl_fmt(&out, "%08.3f", 3.14159), "0003.142") == 0);
    CHECK(strcmp(tpl_fmt(&out, "%c%c", 'o', 'k'), "ok") == 0);
    tpl_out_free(&out);
}

static void test_tpl_url(void)
{
    TplOut out = {0};

    /* Safe URLs pass through — as the SAME pointer (no copy). */
    const char *safe[] = {
        "https://example.com/",
        "http://example.com",
        "mailto:max@x.io",
        "/relative/path",
        "#fragment",
        "?query=1",
        "./x",
        "../y",
        "",
    };
    for (size_t i = 0; i < sizeof(safe) / sizeof(safe[0]); i++) {
        CHECK(tpl_url(&out, safe[i]).s == safe[i]);
    }

    /* Scheme is case-insensitive. */
    TplUrl u = tpl_url(&out, "HTTPS://EXAMPLE.COM");
    CHECK(strcmp(u.s, "HTTPS://EXAMPLE.COM") == 0);

    /* Unsafe schemes are replaced. */
    const char *bad[] = {
        "javascript:alert(1)",  "data:text/html,<b>", "vbscript:x",
        " javascript:alert(1)", /* leading whitespace trick */
        "java\nscript:x",       /* embedded control char */
        "http://a\tx",          /* tab inside the URL */
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        CHECK_MSG(strcmp(tpl_url(&out, bad[i]).s, "about:invalid#ctmpl") == 0,
                  bad[i]);
    }

    CHECK(tpl_url(&out, NULL).s != NULL); /* NULL is handled, no crash */

    /* tpl_safe_url: the deliberate bypass — verbatim. */
    CHECK(tpl_safe_url("anything:here").s != NULL);
    CHECK(strcmp(tpl_safe_url("anything:here").s, "anything:here") == 0);
    CHECK(tpl_safe_url(NULL).s != NULL);

    /* The URL attribute writer escapes like tpl_attr. */
    tpl_attr_url(&out, tpl_url(&out, "a?q=1&x=<b>"));
    CHECK(strcmp(tpl_str(&out), "a?q=1&amp;x=&lt;b&gt;") == 0);
    tpl_out_free(&out);
}

static void test_tpl_css(void)
{
    TplOut out = {0};

    /* Safe declarations pass through as the SAME pointer. */
    const char *safe = "color: red; background: #fff; margin: 0 auto";
    CHECK(tpl_css(&out, safe).s == safe);
    CHECK(tpl_css(&out, "").s != NULL);
    CHECK(tpl_css(&out, NULL).s != NULL); /* hardening: no crash */

    /* Dangerous values are replaced per declaration. */
    TplCss r =
        tpl_css(&out, "color: red; background: url(javascript:alert(1)); "
                      "width: 10px");
    CHECK(strcmp(r.s, "color: red; background:zctmplUnsafeCSS; "
                      "width: 10px") == 0);

    /* expression() and friends. */
    r = tpl_css(&out, "width: expression(alert(1))");
    CHECK(strcmp(r.s, "width:zctmplUnsafeCSS") == 0);

    /* url() with allowed schemes and relative paths stays. */
    const char *ok_url = "background: url(/img.png); color: blue";
    CHECK(tpl_css(&out, ok_url).s == ok_url);
    const char *ok_http = "background: url(https://x.io/a.png)";
    CHECK(tpl_css(&out, ok_http).s == ok_http);

    /* data:image is allowed in url(). */
    const char *ok_data = "background: url(data:image/png;base64,AAA)";
    CHECK(tpl_css(&out, ok_data).s == ok_data);

    /* url() with a disallowed scheme is replaced. */
    r = tpl_css(&out, "background: url(vbscript:x)");
    CHECK(strcmp(r.s, "background:zctmplUnsafeCSS") == 0);

    /* Control characters and < in values. */
    r = tpl_css(&out, "color: red</style>");
    CHECK(strcmp(r.s, "color:zctmplUnsafeCSS") == 0);

    /* Invalid property names replace the whole declaration. */
    r = tpl_css(&out, "col or:red; width: 5px");
    CHECK(strcmp(r.s, "zctmplUnsafeCSS; width: 5px") == 0);

    /* Case-insensitive pattern checks. */
    r = tpl_css(&out, "width: EXPRESSION(alert(1))");
    CHECK(strcmp(r.s, "width:zctmplUnsafeCSS") == 0);

    /* tpl_css_safe: verbatim bypass; attr writer escapes. */
    CHECK(strcmp(tpl_css_safe("a: b").s, "a: b") == 0);
    tpl_attr_css(&out, tpl_css(&out, "font: \"<b>\""));
    CHECK(strcmp(tpl_str(&out), "font:zctmplUnsafeCSS") == 0);

    tpl_out_free(&out);
}

/* ------------------------------------------------------------------ */
/* unit tests: http_res_body                                           */
/* ------------------------------------------------------------------ */

static void test_res_body_fixed_buffer(void)
{
    HttpResponse res = {0};
    CHECK(http_res_body(&res, HTTP_STATUS_OK, "text/html", "<b>hi</b>",
                        strlen("<b>hi</b>")) == 0);
    CHECK(res.dyn_body == NULL);
    CHECK(res.body_len == 9);
    CHECK(strcmp(res.body, "<b>hi</b>") == 0);
    CHECK(res.status == HTTP_STATUS_OK);
    bool has_ct = false;
    for (size_t i = 0; i < res.headers.count; i++) {
        if (strcmp(res.headers.items[i].key, HTTP_HEADER_CONTENT_TYPE) == 0) {
            has_ct = strcmp(res.headers.items[i].value, "text/html") == 0;
        }
    }
    CHECK(has_ct);
    http_headers_free(&res.headers);
}

static void test_res_body_dyn(void)
{
    HttpResponse res = {0};
    size_t big_len = sizeof(res.body) * 4; /* 16 KB */
    char *big = malloc(big_len);
    CHECK(big != NULL);
    memset(big, 'x', big_len);

    CHECK(http_res_body(&res, HTTP_STATUS_OK, "text/html", big, big_len) == 0);
    CHECK(res.dyn_body != NULL);
    CHECK(res.dyn_body_len == big_len);
    CHECK(res.body_len == 0);
    CHECK(memcmp(res.dyn_body, big, big_len) == 0);

    /* Overwrite semantics: no leak, old body replaced. */
    CHECK(http_res_body(&res, HTTP_STATUS_OK, "text/plain", "small", 5) == 0);
    CHECK(res.dyn_body == NULL);
    CHECK(res.body_len == 5);

    /* Rejection cases: nothing is written. */
    CHECK(http_res_body(&res, 700, "text/html", "x", 1) == -1);
    CHECK(http_res_body(&res, HTTP_STATUS_OK, "text/html", NULL, 1) == -1);
    CHECK(http_res_body(&res, HTTP_STATUS_OK, "bad\r\ntype", "x", 1) == -1);

    free(big);
    free(res.dyn_body);
    http_headers_free(&res.headers);
}

static void test_res_html_failed_render(void)
{
    HttpResponse res = {0};
    TplOut out = {0};
    out.failed = true; /* simulate an OOM during rendering */
    CHECK(http_res_html(&res, HTTP_STATUS_OK, &out) == -1);
    CHECK(res.dyn_body == NULL && res.body_len == 0);
    tpl_out_free(&out);
    http_headers_free(&res.headers);
}

static void test_error_drops_dyn_body(void)
{
    HttpResponse res = {0};
    TplOut out = {0};
    tpl_lit(&out, "<div>rendered but then failed</div>");
    CHECK(http_res_html(&res, HTTP_STATUS_OK, &out) == 0);
    CHECK(res.dyn_body != NULL || res.body_len > 0);

    http_error(&res, HTTP_STATUS_INTERNAL_SERVER_ERROR, "boom");
    CHECK(res.error);
    CHECK(res.dyn_body == NULL); /* the error handler's body must win */
    tpl_out_free(&out);
    http_headers_free(&res.headers);
}

/* ------------------------------------------------------------------ */
/* unit tests: fragments                                              */
/* ------------------------------------------------------------------ */

/* Mirrors what ctmpl generates for a component with fragments:
 *
 *   <p>before</p> @fragment("a") { <i>A</i> @fragment("b") { <b>B</b> } }
 *   <p>after</p>
 */
static void render_frag_demo(TplOut *out)
{
    tpl_lit(out, "<p>before</p>");
    tpl_frag_begin(out, "a");
    tpl_lit(out, "<i>A</i>");
    tpl_frag_begin(out, "b");
    tpl_lit(out, "<b>B</b>");
    tpl_frag_end(out);
    tpl_lit(out, "<i>A2</i>");
    tpl_frag_end(out);
    tpl_lit(out, "<p>after</p>");
}

static void test_fragments(void)
{
    /* No selection: fragments are completely transparent. */
    TplOut out = {0};
    render_frag_demo(&out);
    CHECK(strcmp(tpl_str(&out),
                 "<p>before</p><i>A</i><b>B</b><i>A2</i><p>after</p>") == 0);
    tpl_out_free(&out);

    /* Select "a": only a's content (including nested b). */
    tpl_frag_select(&out, "a");
    render_frag_demo(&out);
    CHECK(strcmp(tpl_str(&out), "<i>A</i><b>B</b><i>A2</i>") == 0);
    tpl_out_free(&out);

    /* Select "b": only b's content — the surrounding a is discarded
     * while b renders and again after it closes. */
    tpl_frag_select(&out, "b");
    render_frag_demo(&out);
    CHECK(strcmp(tpl_str(&out), "<b>B</b>") == 0);
    tpl_out_free(&out);

    /* Unknown fragment: everything is discarded (empty output). */
    tpl_frag_select(&out, "nope");
    render_frag_demo(&out);
    CHECK(tpl_len(&out) == 0);
    CHECK(strcmp(tpl_str(&out), "") == 0);
    CHECK(tpl_ok(&out));
    tpl_out_free(&out);

    /* Selecting NULL switches back to full rendering. */
    tpl_frag_select(&out, NULL);
    render_frag_demo(&out);
    CHECK(tpl_len(&out) == strlen("<p>before</p><i>A</i><b>B</b><i>A2</i>"
                                  "<p>after</p>"));
    tpl_out_free(&out);
}

static void test_fragments_same_name(void)
{
    /* All fragments with the selected name are rendered. */
    TplOut out = {0};
    tpl_frag_select(&out, "x");
    tpl_frag_begin(&out, "y");
    tpl_lit(&out, "<y1>");
    tpl_frag_begin(&out, "x");
    tpl_lit(&out, "<x1>");
    tpl_frag_end(&out);
    tpl_lit(&out, "<y2>");
    tpl_frag_end(&out);
    tpl_frag_begin(&out, "x");
    tpl_lit(&out, "<x2>");
    tpl_frag_end(&out);
    CHECK(strcmp(tpl_str(&out), "<x1><x2>") == 0);
    tpl_out_free(&out);
}

/* ------------------------------------------------------------------ */
/* unit tests: once                                                   */
/* ------------------------------------------------------------------ */

static TplOnce once_a = {.name = "a"};
static TplOnce once_b = {.name = "b"};

static void test_once(void)
{
    TplOut out = {0};
    CHECK(tpl_once_begin(&out, &once_a));
    CHECK(!tpl_once_begin(&out, &once_a)); /* second call: skipped */
    CHECK(tpl_once_begin(&out, &once_b));  /* independent handle */
    CHECK(!tpl_once_begin(&out, &once_b));
    CHECK(tpl_once_begin(&out, &once_a) == false);

    /* Nested same handle inside the first block's body: skipped. */
    CHECK(!tpl_once_begin(&out, &once_a));

    /* A FRESH render (new TplOut) fires the handles again —
     * once state is per render, like templ's context-bound handles. */
    tpl_out_free(&out);
    CHECK(tpl_once_begin(&out, &once_a));
    CHECK(tpl_once_begin(&out, &once_b));

    /* NULL hardening. */
    CHECK(!tpl_once_begin(NULL, &once_a));
    CHECK(!tpl_once_begin(&out, NULL));
    tpl_out_free(&out);
}

static void test_res_body_empty(void)
{
    /* Empty renders (e.g. an unknown fragment) must be sendable,
     * not an error. */
    HttpResponse res = {0};
    CHECK(http_res_body(&res, HTTP_STATUS_OK, "text/html", NULL, 0) == 0);
    CHECK(res.body_len == 0);
    CHECK(res.status == HTTP_STATUS_OK);

    /* NULL is still rejected for a NONEMPTY body. */
    CHECK(http_res_body(&res, HTTP_STATUS_OK, "text/html", NULL, 1) == -1);
    http_headers_free(&res.headers);
}

/* ------------------------------------------------------------------ */
/* integration handlers                                                */
/* ------------------------------------------------------------------ */

static void h_small(const HttpRequest *req, HttpResponse *res)
{
    (void)req;
    TplOut out = {0};
    tpl_lit(&out, "<h1>");
    tpl_esc(&out, "Max & <friends>");
    tpl_lit(&out, "</h1>");
    CHECK(http_res_html(res, HTTP_STATUS_OK, &out) == 0);
    tpl_out_free(&out);
}

/* Page larger than the 4096-byte fixed buffer: exercises dyn_body
 * end-to-end (send, Content-Length, no truncation). */
static void h_big(const HttpRequest *req, HttpResponse *res)
{
    (void)req;
    TplOut out = {0};
    for (int i = 0; i < 300; i++) {
        tpl_lit(&out, "<p>row ");
        tpl_lit(&out, tpl_int(&out, i));
        tpl_lit(&out, " of the generated page</p>\n");
    }
    CHECK(tpl_len(&out) > sizeof(res->body)); /* actually exercises dyn */
    CHECK(http_res_html(res, HTTP_STATUS_OK, &out) == 0);
    tpl_out_free(&out);
}

static void h_broken(const HttpRequest *req, HttpResponse *res)
{
    (void)req;
    TplOut out = {0};
    out.failed = true; /* e.g. OOM mid-render */
    if (http_res_html(res, HTTP_STATUS_OK, &out) != 0) {
        http_error(res, HTTP_STATUS_INTERNAL_SERVER_ERROR,
                   "template render failed");
    }
    tpl_out_free(&out);
}

/* ------------------------------------------------------------------ */
/* integration tests                                                   */
/* ------------------------------------------------------------------ */

static void test_integration_responses(void)
{
    ServerArgs args = {.port = TEST_PORT,
                       .bind_addr = "127.0.0.1",
                       .server_name = "tpl-test",
                       .worker_threads = 4};
    CHECK(http_create_server(&args, &g_srv) == SERVER_OK);
    http_register_encoder(&g_srv, http_gzip_encoder);
    CHECK(http_get(&g_srv, "/small", h_small) == HTTP_ROUTE_ADD_OK);
    CHECK(http_get(&g_srv, "/big", h_big) == HTTP_ROUTE_ADD_OK);
    CHECK(http_get(&g_srv, "/broken", h_broken) == HTTP_ROUTE_ADD_OK);
    g_port = TEST_PORT;

    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, server_thread, NULL) == 0);
    CHECK(wait_listening(TEST_PORT));

    char buf[65536];

    /* Small body: escaped, text/html, fixed buffer. */
    size_t n =
        raw_request("GET /small HTTP/1.1\r\nHost: t\r\n\r\n", buf, sizeof(buf));
    CHECK(n > 0);
    CHECK(strstr(buf, "200 OK") != NULL);
    CHECK(strstr(buf, "Content-Type: text/html") != NULL);
    CHECK(strcmp(response_body(buf), "<h1>Max &amp; &lt;friends&gt;</h1>") ==
          0);
    size_t cl = 0;
    CHECK(response_header(buf, HTTP_HEADER_CONTENT_LENGTH, &cl));
    CHECK(cl == strlen("<h1>Max &amp; &lt;friends&gt;</h1>"));

    /* Large body: complete transfer through dyn_body. */
    n = raw_request("GET /big HTTP/1.1\r\nHost: t\r\n\r\n", buf, sizeof(buf));
    CHECK(n > 0);
    CHECK(response_header(buf, HTTP_HEADER_CONTENT_LENGTH, &cl));
    CHECK(cl > 4096);
    CHECK(strlen(response_body(buf)) == cl); /* nothing truncated */
    CHECK(strncmp(response_body(buf), "<p>row 0 of", 11) == 0);
    CHECK(strstr(buf, "row 299 of the generated page") != NULL);

    /* Large body + Accept-Encoding: gzip: the heap body is compressed. */
    n = raw_request("GET /big HTTP/1.1\r\nHost: t\r\n"
                    "Accept-Encoding: gzip\r\n\r\n",
                    buf, sizeof(buf));
    CHECK(n > 0);
    CHECK(strstr(buf, "Content-Encoding: gzip") != NULL);

    /* Failed render -> http_error -> 500, empty body. */
    n = raw_request("GET /broken HTTP/1.1\r\nHost: t\r\n\r\n", buf,
                    sizeof(buf));
    CHECK(n > 0);
    CHECK(strstr(buf, "500 Internal Server Error") != NULL);

    http_stop_server(&g_srv);
    pthread_join(thread, NULL);
    http_close_server(&g_srv);
}

/* ------------------------------------------------------------------ */

int main(void)
{
    test_writer_basics();
    test_writer_failed_is_noop();
    test_esc_entities();
    test_esc_null_and_plain();
    test_attr_escaping();
    test_tpl_int();
    test_tpl_fmt();
    test_tpl_url();
    test_tpl_css();
    test_res_body_fixed_buffer();
    test_res_body_dyn();
    test_res_html_failed_render();
    test_error_drops_dyn_body();
    test_fragments();
    test_fragments_same_name();
    test_once();
    test_res_body_empty();
    test_integration_responses();
    return test_report();
}