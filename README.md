# c-http

Ein kleiner Lern-Server in C: TCP-Sockets, CLI-Parsing mit [cargs](https://likle.github.io/cargs/), gebaut mit CMake.

## Bauen

Voraussetzung: C-Compiler (gcc/clang), CMake ≥ 3.16, Git.

```bash
# Clone MIT Submodulen (cargs als Vendor-Dependency)
git clone --recurse-submodules <repo-url>
cd c-http

# Falls das Repo schon ohne Submodule geklont wurde:
git submodule update --init

# Konfigurieren + Bauen (Default: Debug mit ASan/UBSan)
cmake -S . -B build
cmake --build build
```

Weitere Build-Varianten:

```bash
# Release (Optimierung, ohne Sanitizer)
cmake -S . -B build-release -DCMAKE_BUILD_TYPE=Release -DUSE_SANITIZERS=OFF
cmake --build build-release

# Debug ohne Sanitizer
cmake -S . -B build -DUSE_SANITIZERS=OFF
```

## Starten

```bash
./build/c-http                     # lauscht auf 0.0.0.0:80
./build/c-http -p 8080             # anderer Port
./build/c-http -b 127.0.0.1        # nur localhost
./build/c-http -b localhost -p 8080 # Hostnamen funktionieren auch
./build/c-http --help              # alle Optionen
```

Testen mit z.B. `nc localhost 8080` — der Server antwortet mit einem Echo.

## Tests

```bash
ctest --test-dir build
```

## Entwicklung

```bash
cmake --build build -t format       # clang-format
cmake --build build -t format-check # CI-Check
cmake --build build -t lint         # clang-tidy
```

`compile_commands.json` liegt in `build/` (für clangd / clang-tidy).

## Projektstruktur

```
src/          Quellcode des Servers
tests/        Unit-Tests (CTest)
vendor/       Git-Submodules (Fremdcode, aktuell: cargs)
```

## Abhängigkeiten

| Dependency | Zweck | Einbindung |
|---|---|---|
| [cargs](https://likle.github.io/cargs/) | CLI-Argumente | Git-Submodule in `vendor/cargs`, per `add_subdirectory` |

Neue Abhängigkeit hinzufügen:

```bash
git submodule add https://github.com/owner/lib.git vendor/lib
```

und in der `CMakeLists.txt`:

```cmake
add_subdirectory(vendor/lib EXCLUDE_FROM_ALL)
target_link_libraries(c-http PRIVATE lib)
```