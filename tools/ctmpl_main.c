/* ctmpl CLI: compiles a .thtml file into <stem>_templ.h/.c.
 *
 *   ctmpl page.thtml            -> page_templ.h + page_templ.c
 *   ctmpl page.thtml -o gen/    -> gen/page_templ.h + gen/page_templ.c
 *
 * Exit codes: 0 = OK, 1 = compile error, 2 = usage/IO error.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ctmpl.h"

static const char *path_base(const char *path)
{
    const char *slash = strrchr(path, '/');
    return slash != NULL ? slash + 1 : path;
}

/* Basename without directories and without the .thtml suffix. */
static char *stem_of(const char *path)
{
    const char *base = path_base(path);
    size_t n = strlen(base);
    if (n > 6 && strcmp(base + n - 6, ".thtml") == 0) {
        n -= 6;
    }
    char *s = malloc(n + 1);
    if (s == NULL) {
        return NULL;
    }
    memcpy(s, base, n);
    s[n] = '\0';
    return s;
}

static char *join_path(const char *dir, const char *file)
{
    size_t n = strlen(dir);
    while (n > 1 && dir[n - 1] == '/') {
        n--; /* strip trailing slashes (keep the root \"/\") */
    }
    char *s = malloc(n + strlen(file) + 2);
    if (s == NULL) {
        return NULL;
    }
    memcpy(s, dir, n);
    s[n] = '/';
    strcpy(s + n + 1, file);
    return s;
}

static char *read_file(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    long size = ftell(f);
    if (size < 0 || fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return NULL;
    }
    char *buf = malloc((size_t)size + 1);
    if (buf == NULL) {
        fclose(f);
        return NULL;
    }
    if (fread(buf, 1, (size_t)size, f) != (size_t)size) {
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    buf[size] = '\0';
    *len = (size_t)size;
    return buf;
}

static int usage(FILE *out)
{
    fprintf(out, "usage: ctmpl <input.thtml> [-o <outdir>]\n");
    fprintf(out, "\n");
    fprintf(out, "  Compiles a .thtml template file into C:\n");
    fprintf(out, "    <stem>_templ.h  declarations\n");
    fprintf(out, "    <stem>_templ.c  definitions (next to the input,\n");
    fprintf(out, "                    or in <outdir> when -o is given)\n");
    return 2;
}

int main(int argc, char **argv)
{
    const char *input = NULL;
    const char *outdir = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0) {
            if (i + 1 >= argc) {
                return usage(stderr);
            }
            outdir = argv[++i];
        } else if (strcmp(argv[i], "-h") == 0 ||
                   strcmp(argv[i], "--help") == 0) {
            return usage(stdout);
        } else if (argv[i][0] == '-') {
            fprintf(stderr, "ctmpl: unknown option '%s'\n", argv[i]);
            return usage(stderr);
        } else if (input == NULL) {
            input = argv[i];
        } else {
            fprintf(stderr, "ctmpl: unexpected argument '%s'\n", argv[i]);
            return usage(stderr);
        }
    }
    if (input == NULL) {
        return usage(stderr);
    }

    size_t src_len = 0;
    char *src = read_file(input, &src_len);
    if (src == NULL) {
        fprintf(stderr, "ctmpl: cannot read '%s': %s\n", input,
                strerror(errno));
        return 2;
    }
    char *stem = stem_of(input);
    if (stem == NULL) {
        fprintf(stderr, "ctmpl: out of memory\n");
        free(src);
        return 2;
    }

    char *h_path;
    char *c_path;
    if (outdir != NULL) {
        char *h_name = malloc(strlen(stem) + strlen("_templ.h") + 1);
        char *c_name = malloc(strlen(stem) + strlen("_templ.c") + 1);
        if (h_name == NULL || c_name == NULL) {
            fprintf(stderr, "ctmpl: out of memory\n");
            free(src);
            free(stem);
            free(h_name);
            free(c_name);
            return 2;
        }
        sprintf(h_name, "%s_templ.h", stem);
        sprintf(c_name, "%s_templ.c", stem);
        h_path = join_path(outdir, h_name);
        c_path = join_path(outdir, c_name);
        free(h_name);
        free(c_name);
    } else {
        /* next to the input: reuse its directory prefix (""). */
        size_t dir_len = (size_t)(path_base(input) - input);
        char *h_name = malloc(strlen(stem) + strlen("_templ.h") + 1);
        char *c_name = malloc(strlen(stem) + strlen("_templ.c") + 1);
        if (h_name == NULL || c_name == NULL) {
            fprintf(stderr, "ctmpl: out of memory\n");
            free(src);
            free(stem);
            free(h_name);
            free(c_name);
            return 2;
        }
        sprintf(h_name, "%s_templ.h", stem);
        sprintf(c_name, "%s_templ.c", stem);
        if (dir_len == 0) {
            h_path = h_name;
            c_path = c_name;
        } else {
            char *dir = malloc(dir_len + 1);
            if (dir == NULL) {
                fprintf(stderr, "ctmpl: out of memory\n");
                free(src);
                free(stem);
                free(h_name);
                free(c_name);
                return 2;
            }
            memcpy(dir, input, dir_len - 1);
            dir[dir_len - 1] = '\0';
            h_path = join_path(dir, h_name);
            c_path = join_path(dir, c_name);
            free(dir);
            free(h_name);
            free(c_name);
        }
    }
    if (h_path == NULL || c_path == NULL) {
        fprintf(stderr, "ctmpl: out of memory\n");
        free(src);
        free(stem);
        free(h_path);
        free(c_path);
        return 2;
    }

    FILE *out_h = fopen(h_path, "wb");
    FILE *out_c = fopen(c_path, "wb");
    if (out_h == NULL || out_c == NULL) {
        fprintf(stderr, "ctmpl: cannot write '%s': %s\n",
                out_h == NULL ? h_path : c_path, strerror(errno));
        if (out_h != NULL) {
            fclose(out_h);
            remove(h_path);
        }
        if (out_c != NULL) {
            fclose(out_c);
            remove(c_path);
        }
        free(src);
        free(stem);
        free(h_path);
        free(c_path);
        return 2;
    }

    CtmplError err;
    int rc = ctmpl_compile(src, src_len, input, out_h, out_c, &err);
    if (rc != 0) {
        if (err.line > 0) {
            fprintf(stderr, "%s:%zu:%zu: error: %s\n", input, err.line, err.col,
                    err.message);
        } else {
            fprintf(stderr, "%s: error: %s\n", input, err.message);
        }
        fclose(out_h);
        fclose(out_c);
        remove(h_path); /* never leave partial output behind */
        remove(c_path);
    } else {
        fclose(out_h);
        fclose(out_c);
        printf("%s -> %s, %s\n", input, h_path, c_path);
    }
    free(src);
    free(stem);
    free(h_path);
    free(c_path);
    return rc == 0 ? 0 : 1;
}