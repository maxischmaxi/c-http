# c-template

A small, batteries-included starting point for C projects. Clone it, run `make`,
start writing code. No build system to configure, no editor setup to fiddle with.

[![ci](https://github.com/maxischmaxi/c-template/actions/workflows/ci.yml/badge.svg)](https://github.com/maxischmaxi/c-template/actions/workflows/ci.yml)

- **One Makefile** with debug and release builds and automatic header dependency tracking
- **Strict warnings** (`-Wall -Wextra -Wpedantic -Wshadow -Wconversion` and friends), C17 by default
- **Sanitizers on by default** in debug builds (AddressSanitizer + UndefinedBehaviorSanitizer)
- **Tests**: drop a `.c` file into `tests/`, run `make test`
- **clangd ready**: `compile_commands.json` is generated on every build, no extra tools needed
- **Formatting and linting** via `.clang-format`, `.clang-tidy` and `.editorconfig`
- **CI** on GitHub Actions: gcc and clang, debug and release, plus a format check

## Quick start

```sh
gh repo create my-app --template maxischmaxi/c-template --clone
cd my-app

make                    # debug build -> build/debug/my-app
make run ARGS="a b"     # build and run with arguments
make test               # build and run everything in tests/
make BUILD=release      # optimized build -> build/release/my-app
```

Without `gh`: clone the repo, delete `.git`, run `git init`.

The binary is named after the project directory. Set `BIN` at the top of the
`Makefile` if you want something else.

## Layout

```
.
├── Makefile
├── include/                 # public headers, added to the include path
├── src/                     # sources, picked up recursively
│   └── main.c
├── tests/                   # every tests/*.c becomes its own test binary
│   ├── test.h               # tiny CHECK() / test_report() helpers
│   └── test_example.c
├── build/                   # created by make, ignored by git
│   ├── debug/
│   └── release/
├── .clang-format
├── .clang-tidy
├── .editorconfig
└── .github/workflows/ci.yml
```

## Targets

| Target              | What it does                                              |
| ------------------- | --------------------------------------------------------- |
| `make`              | debug build (default)                                     |
| `make release`      | release build, same as `make BUILD=release`               |
| `make run`          | build and run, arguments via `ARGS="..."`                 |
| `make test`         | build and run all tests, stops at the first failing one   |
| `make format`       | format all sources with clang-format                      |
| `make format-check` | fail if anything is not formatted (used in CI)            |
| `make lint`         | run clang-tidy                                            |
| `make clean`        | remove `build/` and `compile_commands.json`               |
| `make help`         | list all targets                                          |

## Configuration

Pass variables on the command line for one-off changes, or edit the top of the
`Makefile` for permanent ones.

| Variable   | Default        | Description                                          |
| ---------- | -------------- | ---------------------------------------------------- |
| `BUILD`    | `debug`        | `debug` or `release`, output goes to `build/<BUILD>/` |
| `CC`       | `cc`           | compiler, e.g. `make CC=clang`                       |
| `STD`      | `c17`          | language standard                                    |
| `BIN`      | directory name | name of the binary                                   |
| `SANITIZE` | `1`            | `0` disables ASan/UBSan in debug builds              |
| `ARGS`     |                | arguments for `make run`                             |
| `V`        | `0`            | `1` prints the full compiler commands                |

Debug builds use `-O0 -g3` with sanitizers, release builds use `-O2 -DNDEBUG`.
Both live side by side in `build/debug/` and `build/release/`. After switching
compilers or changing flags run `make clean`.

## Adding code

New sources anywhere below `src/` and headers in `include/` are picked up
automatically. To link a library, append it to `LDLIBS` in the `Makefile`:

```make
LDLIBS += -lm
```

Every `tests/*.c` is compiled into its own binary and linked against all
objects except `main.o`, so tests can call anything in `src/`:

```c
#include "test.h"
#include "mymodule.h"

int main(void)
{
    CHECK(my_add(1, 2) == 3);
    return test_report();
}
```

`CHECK()` records failures instead of aborting, so one run shows every failing
assertion. Memory errors and undefined behaviour are caught by the sanitizers.

## Editor

`make` writes `compile_commands.json` to the project root. Any clangd based
setup (neovim, helix, vscode, ...) picks it up and gets completion, diagnostics
and go-to-definition without further configuration.

## Requirements

GNU make and gcc or clang. `clang-format` and `clang-tidy` are only needed for
`make format` and `make lint`.
