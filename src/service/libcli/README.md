# Smithproxy internal libcli

Small C++17 command engine maintained as an internal Smithproxy library.
It has no dependencies on Smithproxy runtime or configuration code.

Implemented:

- hierarchical commands and unique-prefix matching;
- quoted/escaped positional arguments;
- handlers, validation and contextual command availability;
- command and argument completion with replacement ranges;
- basic generated help.

The split is intentional:

```text
Terminal transport -> Line editor -> Cli command engine -> Handler
                           |              |
                           +-- completion-+
```

The example includes a reusable terminal line editor with history, cursor
movement, immediate `?`, Tab completion and terminal redraw.
Pipelines and configuration/build modes should be composed on top instead of
being baked into parsing.

An optional `FdTransport` owns or borrows a duplex descriptor pair. It is
movable, non-copyable and replaceable with `reset()`, so a CLI session does not
need to know whether its byte stream came from TCP, a Unix socket or stdio:

```cpp
libcli2::FdTransport socket_io(libcli2::FdPair(socket_fd, socket_fd));
libcli2::FdTransport stdio(
    libcli2::FdPair::borrowed(STDIN_FILENO, STDOUT_FILENO));
```

Example:

```cpp
libcli2::Cli cli;

cli.command("show session")
    .help("Show one session")
    .argument({"id", "Session identifier"})
    .handler([](libcli2::Context& context, const libcli2::Invocation& call) {
        context.print("session: " + call.arguments.at(0));
        return 0;
    });
```

Build and run the interactive example without the rest of Smithproxy:

```sh
g++ -std=c++17 -Wall -Wextra -Werror -pedantic cli.cpp line_editor.cpp examples/example.cpp -o libcli-demo
./libcli-demo
```
