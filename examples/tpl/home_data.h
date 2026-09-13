#ifndef HOME_DATA_H
#define HOME_DATA_H

#include <stdbool.h>
#include <stddef.h>

/* View model for the home page template (examples/tpl/home.thtml).
 * templ's docs recommend passing a view model that mirrors what the
 * page displays — C needs the types somewhere the generated header
 * can include, hence this file. */

#define HOME_MAX_LINKS 8

typedef struct {
    const char *name;
    const char *url;
} HomeLink;

typedef struct {
    const char *title;
    const char *user;
    bool logged_in;
    size_t link_count;
    HomeLink links[HOME_MAX_LINKS];
} HomePageData;

#endif /* HOME_DATA_H */