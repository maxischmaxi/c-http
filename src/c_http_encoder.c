#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <zlib.h>

#include "c_http.h"
#include "c_http_assert.h"

/* --- gzip encoder --- */

static int gzip_encode(const char *in, size_t in_len, char **out,
                       size_t *out_len)
{
    HTTP_ASSERT(in != NULL || in_len == 0);
    HTTP_ASSERT(out != NULL);
    HTTP_ASSERT(out_len != NULL);

    z_stream strm = {0};

    if (deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, MAX_WBITS + 16,
                     8, Z_DEFAULT_STRATEGY) != Z_OK) {
        return -1;
    }

    size_t bound = deflateBound(&strm, in_len);
    char *buf = malloc(bound);
    if (!buf) {
        deflateEnd(&strm);
        return -1;
    }

    strm.next_in = (Bytef *)in;
    strm.avail_in = (uInt)in_len;
    strm.next_out = (Bytef *)buf;
    strm.avail_out = (uInt)bound;

    if (deflate(&strm, Z_FINISH) != Z_STREAM_END) {
        free(buf);
        deflateEnd(&strm);
        return -1;
    }

    *out = buf;
    *out_len = strm.total_out;
    deflateEnd(&strm);
    HTTP_ASSERT(*out != NULL);
    HTTP_ASSERT(*out_len > 0);
    return 0;
}

const HttpEncoder http_gzip_encoder = {
    .name = "gzip",
    .encode = gzip_encode,
};

/* --- identity encoder (no compression) --- */

static int identity_encode(const char *in, size_t in_len, char **out,
                           size_t *out_len)
{
    HTTP_ASSERT(in != NULL || in_len == 0);
    HTTP_ASSERT(out != NULL);
    HTTP_ASSERT(out_len != NULL);

    char *buf = malloc(in_len == 0 ? 1 : in_len);
    if (!buf) {
        return -1;
    }
    memcpy(buf, in, in_len);
    *out = buf;
    *out_len = in_len;
    return 0;
}

const HttpEncoder http_identity_encoder = {
    .name = "identity",
    .encode = identity_encode,
};

/* --- encoder registration --- */

HttpEncoderAddResult http_register_encoder(HttpServer *server,
                                           HttpEncoder encoder)
{
    HTTP_ASSERT(server != NULL);
    HTTP_ASSERT(encoder.name != NULL);
    HTTP_ASSERT(encoder.encode != NULL);
    HTTP_ASSERT_MSG(server->listening == false,
                    "cannot register encoder while server is listening");
    HTTP_ASSERT(server->encoders.count <= server->encoders.capacity);

    if (server->encoders.count == server->encoders.capacity) {
        size_t new_cap =
            server->encoders.capacity == 0 ? 4 : server->encoders.capacity * 2;
        HttpEncoder *tmp =
            realloc(server->encoders.encoders, new_cap * sizeof(HttpEncoder));
        if (!tmp) {
            return HTTP_ENCODER_ADD_ERROR;
        }
        server->encoders.encoders = tmp;
        server->encoders.capacity = new_cap;
    }

    server->encoders.encoders[server->encoders.count++] = encoder;
    return HTTP_ENCODER_ADD_OK;
}

/* --- header cleanup --- */

void http_headers_free(HttpHeaders *headers)
{
    if (headers == NULL) {
        return; /* NULL is allowed — no-op */
    }
    for (size_t i = 0; i < headers->count; i++) {
        free(headers->items[i].key);
        free(headers->items[i].value);
    }
    free(headers->items);
    headers->items = NULL;
    headers->count = headers->capacity = 0;
}

/* --- content negotiation --- */

/* Parses ";q=0.5" parameters from *pp (pointing at ';'). Returns the q
 * value (default 1.0 for an unparseable/missing q) and advances *pp up
 * to the next ';' or ',' */
static double parse_q(const char **pp)
{
    const char *p = *pp;
    double q = 1.0;

    while (*p == ';') {
        p++; /* skip ';' */
        while (*p == ' ' || *p == '\t') {
            p++;
        }

        if ((p[0] == 'q' || p[0] == 'Q') && p[1] == '=') {
            char *end = NULL;
            double v = strtod(p + 2, &end);
            if (end != p + 2 && v >= 0.0) {

                q = v;
            }
            if (q > 1.0) {

                q = 1.0;
            }
        }

        while (*p && *p != ';' && *p != ',') {

            p++;
        }
    }

    *pp = p;
    return q;
}

/* RFC 9110 §12.5.6: Accept-Encoding honors q-values (q=0 = explicitly
 * forbidden) and considers all Accept-Encoding headers (not just the
 * first). "*" only matches encodings that are not explicitly listed. */
bool http_accepts_encoding(const HttpRequest *req, const char *encoding)
{
    if (req == NULL || encoding == NULL || *encoding == '\0') {
        return false;
    }

    bool specific_found = false;
    bool specific_ok = false;
    bool wildcard_found = false;
    double wildcard_q = 0.0;

    for (size_t i = 0; i < req->headers.count; i++) {
        if (strcasecmp(req->headers.items[i].key,
                       HTTP_HEADER_ACCEPT_ENCODING) != 0) {
            continue;
        }

        const char *p = req->headers.items[i].value;
        while (*p) {
            while (*p == ' ' || *p == '\t' || *p == ',') {
                p++;
            }
            if (*p == '\0') {
                break;
            }

            /* read the coding name (until ',' or ';') */
            const char *name_start = p;
            while (*p && *p != ',' && *p != ';') {
                p++;
            }
            const char *name_end = p;
            while (name_end > name_start &&
                   (name_end[-1] == ' ' || name_end[-1] == '\t')) {
                name_end--;
            }

            size_t name_len = (size_t)(name_end - name_start);
            bool wildcard = (name_len == 1 && name_start[0] == '*') != 0;
            bool match = (wildcard || (name_len == strlen(encoding) &&
                                       strncasecmp(name_start, encoding,
                                                   name_len) == 0)) != 0;

            double q = 1.0;
            if (*p == ';') {
                q = parse_q(&p);
            }

            if (wildcard) {
                wildcard_found = true;
                if (q > wildcard_q) {
                    wildcard_q = q;
                }
            } else if (match) {
                specific_found = true;
                if (q > 0.0) {
                    specific_ok = true; /* highest q wins */
                }
            }

            /* skip to the next list element */
            while (*p && *p != ',') {
                p++;
            }
            if (*p == ',') {
                p++;
            }
        }
    }

    /* Explicit mention beats the wildcard: "gzip;q=0, *" rejects gzip. */
    if (specific_found) {
        return specific_ok;
    }
    return (wildcard_found && wildcard_q > 0.0) != 0;
}

bool http_encode_body(HttpServer *server, const HttpRequest *req,
                      HttpResponse *res)
{
    HTTP_ASSERT(server != NULL);
    HTTP_ASSERT(req != NULL);
    HTTP_ASSERT(res != NULL);
    HTTP_ASSERT_MSG(res->body_len <= sizeof(res->body),
                    "body_len exceeds body buffer");
    HTTP_ASSERT(server->encoders.encoders != NULL ||
                server->encoders.count == 0);

    /* The heap body (dyn_body, template/large responses) is encoded
     * like a fixed-buffer body — encoded_body takes priority at send
     * time, so the selection stays two-level everywhere. */
    const char *src = res->dyn_body != NULL ? res->dyn_body : res->body;
    size_t src_len = res->dyn_body != NULL ? res->dyn_body_len : res->body_len;

    if (src_len == 0 || res->encoded_body != NULL) {
        return false;
    }

    /* Check whether the handler already set Content-Encoding */
    for (size_t i = 0; i < res->headers.count; i++) {
        if (strcasecmp(res->headers.items[i].key,
                       HTTP_HEADER_CONTENT_ENCODING) == 0) {
            return false;
        }
    }

    /* Try the registered encoders */
    for (size_t i = 0; i < server->encoders.count; i++) {
        if (!http_accepts_encoding(req, server->encoders.encoders[i].name)) {
            continue;
        }

        char *encoded = NULL;
        size_t encoded_len = 0;
        if (server->encoders.encoders[i].encode(src, src_len, &encoded,
                                                &encoded_len) != 0) {
            continue;
        }

        /* Skip if the encoding made the body larger */
        if (encoded_len >= src_len) {
            free(encoded);
            continue;
        }

        res->encoded_body = encoded;
        res->encoded_body_len = encoded_len;
        http_set_header(&res->headers, HTTP_HEADER_CONTENT_ENCODING,
                        server->encoders.encoders[i].name);
        return true;
    }

    return false;
}
