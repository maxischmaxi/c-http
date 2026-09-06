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
    HTTP_ASSERT(server->encoder_count <= server->encoder_capacity);

    if (server->encoder_count == server->encoder_capacity) {
        size_t new_cap =
            server->encoder_capacity == 0 ? 4 : server->encoder_capacity * 2;
        HttpEncoder *tmp =
            realloc(server->encoders, new_cap * sizeof(HttpEncoder));
        if (!tmp) {
            return HTTP_ENCODER_ADD_ERROR;
        }
        server->encoders = tmp;
        server->encoder_capacity = new_cap;
    }

    server->encoders[server->encoder_count++] = encoder;
    return HTTP_ENCODER_ADD_OK;
}

/* --- header cleanup --- */

void http_headers_free(HttpHeaders *headers)
{
    if (headers == NULL) {
        return; /* NULL ist erlaubt — no-op */
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

/* Parst ";q=0.5"-Parameter ab *pp (zeigt auf ';'). Liefert den q-Wert
 * (Default 1.0 bei unparsebarem/nicht vorhandenem q) und rückt *pp bis
 * zum nächsten ';' oder ',' vor. */
static double parse_q(const char **pp)
{
    const char *p = *pp;
    double q = 1.0;

    while (*p == ';') {
        p++; /* ';' überspringen */
        while (*p == ' ' || *p == '\t')
            p++;

        if ((p[0] == 'q' || p[0] == 'Q') && p[1] == '=') {
            char *end = NULL;
            double v = strtod(p + 2, &end);
            if (end != p + 2 && v >= 0.0)
                q = v;
            if (q > 1.0)
                q = 1.0;
        }

        while (*p && *p != ';' && *p != ',')
            p++;
    }

    *pp = p;
    return q;
}

/* RFC 9110 §12.5.6: Accept-Encoding berücksichtigt q-Werte (q=0 =
 * explizit verboten) und behandelt alle Accept-Encoding-Header (nicht
 * nur den ersten). "*" matcht nur Encodings, die nicht explizit gelistet
 * sind. */
bool http_accepts_encoding(const HttpRequest *req, const char *encoding)
{
    if (req == NULL || encoding == NULL || *encoding == '\0')
        return false;

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
            while (*p == ' ' || *p == '\t' || *p == ',')
                p++;
            if (*p == '\0')
                break;

            /* Coding-Name lesen (bis ',' oder ';') */
            const char *name_start = p;
            while (*p && *p != ',' && *p != ';')
                p++;
            const char *name_end = p;
            while (name_end > name_start &&
                   (name_end[-1] == ' ' || name_end[-1] == '\t'))
                name_end--;

            size_t name_len = (size_t)(name_end - name_start);
            bool wildcard = (name_len == 1 && name_start[0] == '*');
            bool match =
                wildcard || (name_len == strlen(encoding) &&
                             strncasecmp(name_start, encoding, name_len) == 0);

            double q = 1.0;
            if (*p == ';')
                q = parse_q(&p);

            if (wildcard) {
                wildcard_found = true;
                if (q > wildcard_q)
                    wildcard_q = q;
            } else if (match) {
                specific_found = true;
                if (q > 0.0)
                    specific_ok = true; /* höchstes q gewinnt */
            }

            /* Zum nächsten Listenelement springen */
            while (*p && *p != ',')
                p++;
            if (*p == ',')
                p++;
        }
    }

    /* Explizite Nennung schlägt Wildcard: "gzip;q=0, *" lehnt gzip ab. */
    if (specific_found)
        return specific_ok;
    return wildcard_found && wildcard_q > 0.0;
}

bool http_encode_body(HttpServer *server, const HttpRequest *req,
                      HttpResponse *res)
{
    HTTP_ASSERT(server != NULL);
    HTTP_ASSERT(req != NULL);
    HTTP_ASSERT(res != NULL);
    HTTP_ASSERT_MSG(res->body_len <= sizeof(res->body),
                    "body_len exceeds body buffer");
    HTTP_ASSERT(server->encoders != NULL || server->encoder_count == 0);

    if (res->body_len == 0 || res->encoded_body != NULL) {
        return false;
    }

    /* Prüfen ob der Handler schon Content-Encoding gesetzt hat */
    for (size_t i = 0; i < res->headers.count; i++) {
        if (strcasecmp(res->headers.items[i].key,
                       HTTP_HEADER_CONTENT_ENCODING) == 0) {
            return false;
        }
    }

    /* Registrierte Encoder durchprobieren */
    for (size_t i = 0; i < server->encoder_count; i++) {
        if (!http_accepts_encoding(req, server->encoders[i].name)) {
            continue;
        }

        char *encoded = NULL;
        size_t encoded_len = 0;
        if (server->encoders[i].encode(res->body, res->body_len, &encoded,
                                       &encoded_len) != 0) {
            continue;
        }

        /* Überspringen wenn Encoding den Body größer gemacht hat */
        if (encoded_len >= res->body_len) {
            free(encoded);
            continue;
        }

        res->encoded_body = encoded;
        res->encoded_body_len = encoded_len;
        http_set_header(&res->headers, HTTP_HEADER_CONTENT_ENCODING,
                        server->encoders[i].name);
        return true;
    }

    return false;
}
