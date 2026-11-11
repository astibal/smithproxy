#include "cftar_cli.hpp"

#include "cfg_archive.hpp"
#include "cfg_archive_session.hpp"
#include "cfg_exposure.hpp"

#include <service/libcli/cli.hpp>
#include <service/libcli/line_editor.hpp>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <iostream>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

namespace sx::cfg {
namespace {

void require_resource_path(std::string_view path);

// Own one private editor hand-off. Editors still receive an ordinary file,
// but no editor path or intermediate bytes become part of the archive until
// the child exits successfully and CfgArchiveSession validates the result.
class TemporaryEditFile {
public:
    // Materialize one private text entry for an external editor process.
    TemporaryEditFile(std::string_view logical_path, std::string_view content) {
        std::string pattern = "/tmp/smithproxy-cftar-edit-XXXXXX";
        if(!::mkdtemp(pattern.data())) {
            throw CfgTarError("cannot create private edit directory");
        }
        directory_ = std::move(pattern);
        try {
            const auto slash = logical_path.find_last_of('/');
            const auto name = slash == std::string_view::npos
                ? logical_path : logical_path.substr(slash + 1);
            path_ = directory_ + "/" + std::string(name);

            const int fd = ::open(
                path_.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                0600);
            if(fd < 0) throw CfgTarError("cannot create edit file");
            std::string_view remaining = content;
            while(!remaining.empty()) {
                const auto count = ::write(fd, remaining.data(), remaining.size());
                if(count < 0 && errno == EINTR) continue;
                if(count <= 0) {
                    ::close(fd);
                    throw CfgTarError("cannot write edit file");
                }
                remaining.remove_prefix(static_cast<std::size_t>(count));
            }
            if(::close(fd) != 0) throw CfgTarError("cannot close edit file");
        }
        catch(...) {
            std::error_code ignored;
            std::filesystem::remove_all(directory_, ignored);
            throw;
        }
    }

    // Remove the editor file and its private directory on every exit path.
    ~TemporaryEditFile() {
        std::error_code ignored;
        std::filesystem::remove_all(directory_, ignored);
    }

    // Return the filesystem path passed as the editor's only argument.
    const std::string& path() const noexcept { return path_; }

private:
    std::string directory_;
    std::string path_;
};

// Offer only paths already present in the current working generation.
std::vector<libcli2::CompletionItem> archive_paths(
    const CfgArchiveSession& session, std::string_view prefix) {
    std::vector<libcli2::CompletionItem> result;
    for(const auto& [path, entry] : session.archive().entries()) {
        (void)entry;
        if(path.compare(0, prefix.size(), prefix) == 0) {
            result.push_back({path, "CFtar entry"});
        }
    }
    return result;
}

// Translate the internal change kind into the concise diff vocabulary.
std::string change_name(CfgArchiveChange::Kind kind) {
    switch(kind) {
        case CfgArchiveChange::Kind::added: return "added";
        case CfgArchiveChange::Kind::modified: return "modified";
        case CfgArchiveChange::Kind::removed: return "removed";
    }
    return "changed";
}

int launch_editor(const std::string& path) {
    // Avoid invoking a shell: the selected executable receives exactly one
    // controlled temporary path and no archive content through arguments.
    const char* editor = std::getenv("VISUAL");
    if(!editor || !*editor) editor = std::getenv("EDITOR");
    if(!editor || !*editor) editor = "vi";
    if(std::strchr(editor, ' ') || std::strchr(editor, '\t')) {
        throw CfgTarError(
            "VISUAL/EDITOR must name one executable; wrapper arguments are unsupported");
    }

    const pid_t child = ::fork();
    if(child < 0) throw CfgTarError("cannot start editor");
    if(child == 0) {
        ::execlp(editor, editor, path.c_str(), static_cast<char*>(nullptr));
        _exit(127);
    }

    int status = 0;
    while(::waitpid(child, &status, 0) < 0) {
        if(errno != EINTR) throw CfgTarError("cannot wait for editor");
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128;
}

// Keep the interactive surface intentionally small. This class only translates
// familiar commands into CfgArchiveSession operations; it never loads or
// changes Smithproxy's running configuration and owns no persistence policy.
class CfgTarShell {
public:
    // Open one validated offline archive and initialize a clean working copy.
    explicit CfgTarShell(std::string path)
        : session_(CfgArchiveSession::open(std::move(path))) {}

    // Read commands until clean quit, forced quit, or end-of-input.
    int run() {
        register_commands();
        context_.color_mode = libcli2::ColorMode::automatic;
        context_.color_capable = ::isatty(STDOUT_FILENO);
        context_.write = [](std::string_view text) { std::cout << text << '\n'; };

        std::cout << "Smithproxy CFtar offline shell\n"
                  << "Archive: " << session_.path() << "\n"
                  << "Use '?' for completion and 'help' for commands.\n\n";

        libcli2::LineEditor editor(cli_, context_);
        while(running_) {
            const auto line = editor.read_line(session_.dirty() ? "cftar*> " : "cftar> ");
            if(!line) break;
            if(*line == "help") {
                std::cout << cli_.help("", context_);
                continue;
            }
            if(line->compare(0, 5, "help ") == 0) {
                const auto help = cli_.help(line->substr(5), context_);
                std::cout << (help.empty() ? "% unknown help path\n" : help);
                continue;
            }
            const auto result = cli_.execute(*line, context_);
            if(result.status != libcli2::ExecuteStatus::ok &&
               result.status != libcli2::ExecuteStatus::empty) {
                context_.print(libcli2::Style::error, "% " + result.message);
            }
        }
        if(session_.dirty()) {
            std::cout << "Discarded unsaved working archive changes.\n";
        }
        return 0;
    }

private:
    // Convert command exceptions into ordinary libcli2 failures while keeping
    // the interactive session alive for correction or inspection.
    template<typename Callback>
    libcli2::Handler safe(Callback callback) {
        return [this, callback = std::move(callback)](
            libcli2::Context& context, const libcli2::Invocation& invocation) {
            try {
                return callback(context, invocation);
            }
            catch(const std::exception& error) {
                context.print(libcli2::Style::error, error.what());
                return -1;
            }
        };
    }

    // Build the repeated logical-path argument with archive-aware completion.
    libcli2::Argument path_argument(std::string help) {
        return {"path", std::move(help), true, false,
                [this](const libcli2::Context&, std::string_view prefix) {
                    return archive_paths(session_, prefix);
                }};
    }

    // Define the deliberately small offline command surface in one place.
    void register_commands() {
        cli_.command("inspect")
            .help("Show archive identity, hash and entry count")
            .handler(safe([this](libcli2::Context& context, const libcli2::Invocation&) {
                context.print("path: " + session_.path());
                context.print("base hash: " + session_.base_hash());
                context.print("entries: " + std::to_string(session_.archive().entries().size()));
                context.print(std::string("working state: ") +
                              (session_.dirty() ? "modified" : "clean"));
                return 0;
            }));

        cli_.command("list")
            .help("List archive entries")
            .argument({"prefix", "Optional logical path prefix", false})
            .handler(safe([this](libcli2::Context& context, const libcli2::Invocation& call) {
                const auto prefix = call.arguments.empty() ? std::string{} : call.arguments[0];
                for(const auto& [path, entry] : session_.archive().entries()) {
                    if(path.compare(0, prefix.size(), prefix) != 0) continue;
                    context.print(path + "  " + std::to_string(entry.data.size()) +
                                  (entry.executable ? "  executable" : ""));
                }
                return 0;
            }));

        cli_.command("show")
            .help("Print one text archive entry")
            .argument(path_argument("Logical archive path"))
            .handler(safe([this](libcli2::Context& context, const libcli2::Invocation& call) {
                const auto& data = session_.entry(call.arguments[0]).data;
                if(data.find('\0') != std::string::npos) {
                    throw CfgTarError("binary resource cannot be shown; use export");
                }
                context.print(data);
                return 0;
            }));

        cli_.command("validate")
            .help("Validate the complete working archive")
            .handler(safe([this](libcli2::Context& context, const libcli2::Invocation&) {
                session_.validate();
                context.print(libcli2::Style::success, "working archive is valid");
                return 0;
            }));

        cli_.command("diff")
            .help("List changes in the working archive")
            .handler(safe([this](libcli2::Context& context, const libcli2::Invocation&) {
                const auto changes = session_.changes();
                if(changes.empty()) context.print("working archive is unchanged");
                for(const auto& change : changes) {
                    context.print(change_name(change.kind) + "  " + change.path);
                }
                return 0;
            }));

        cli_.command("edit")
            .help("Edit one text entry through VISUAL or EDITOR")
            .argument(path_argument("Logical archive path"))
            .handler(safe([this](libcli2::Context& context, const libcli2::Invocation& call) {
                const auto path = call.arguments[0];
                const auto& entry = session_.entry(path);
                if(entry.data.find('\0') != std::string::npos) {
                    throw CfgTarError("binary resource cannot be edited; use import/export");
                }
                TemporaryEditFile temporary(path, entry.data);
                context.print("opening " + temporary.path());
                if(launch_editor(temporary.path()) != 0) {
                    throw CfgTarError("editor exited unsuccessfully; change discarded");
                }
                auto replacement = read_import_file(temporary.path());
                if(replacement == entry.data) {
                    context.print("entry is unchanged");
                    return 0;
                }
                session_.put(path, std::move(replacement), entry.executable);
                context.print(libcli2::Style::success, "change staged in working archive");
                return 0;
            }));

        cli_.command("resource import")
            .help("Import one file into the working archive")
            .argument({"path", "Logical resource path"})
            .argument({"file", "Local source file"})
            .argument({"mode", "Optional 'executable' mode", false})
            .handler(safe([this](libcli2::Context& context, const libcli2::Invocation& call) {
                require_resource_path(call.arguments[0]);
                const bool executable = call.arguments.size() == 3;
                if(executable && call.arguments[2] != "executable") {
                    throw CfgTarError("resource mode must be 'executable'");
                }
                session_.put(
                    call.arguments[0], read_import_file(call.arguments[1]), executable);
                context.print(libcli2::Style::success, "resource staged in working archive");
                return 0;
            }));

        cli_.command("resource export")
            .help("Export one archive entry to a new local file")
            .argument(path_argument("Logical archive path"))
            .argument({"file", "New destination file"})
            .handler(safe([this](libcli2::Context& context, const libcli2::Invocation& call) {
                require_resource_path(call.arguments[0]);
                write_export_file(call.arguments[1], session_.entry(call.arguments[0]).data);
                context.print(libcli2::Style::success, "resource exported");
                return 0;
            }));

        cli_.command("resource remove")
            .help("Remove one resource from the working archive")
            .argument(path_argument("Logical resource path"))
            .handler(safe([this](libcli2::Context& context, const libcli2::Invocation& call) {
                require_resource_path(call.arguments[0]);
                session_.remove(call.arguments[0]);
                context.print(libcli2::Style::success, "resource removed from working archive");
                return 0;
            }));

        cli_.command("save")
            .help("Validate, back up and atomically save the working archive")
            .handler(safe([this](libcli2::Context& context, const libcli2::Invocation&) {
                if(!session_.dirty()) {
                    context.print("working archive is unchanged");
                    return 0;
                }
                session_.save();
                context.print(libcli2::Style::success, "archive saved atomically");
                return 0;
            }));

        cli_.command("discard")
            .help("Discard all unsaved working archive changes")
            .handler(safe([this](libcli2::Context& context, const libcli2::Invocation&) {
                session_.discard();
                context.print("working archive reset to last saved state");
                return 0;
            }));

        cli_.command("expose")
            .help("Materialize a read-only path for this interactive session")
            .argument(path_argument("Entry or inferred directory path"))
            .handler(safe([this](libcli2::Context& context, const libcli2::Invocation& call) {
                const auto exposure = exposures_.expose(session_.archive(), call.arguments[0]);
                context.print("exposure " + std::to_string(exposure.id) + ": " +
                              exposure.filesystem_path);
                return 0;
            }));

        cli_.command("exposures")
            .help("List paths exposed by this interactive session")
            .handler(safe([this](libcli2::Context& context, const libcli2::Invocation&) {
                const auto entries = exposures_.entries();
                if(entries.empty()) context.print("no active exposures");
                for(const auto& exposure : entries) {
                    context.print(std::to_string(exposure.id) + "  " +
                                  exposure.logical_path + "  " + exposure.filesystem_path);
                }
                return 0;
            }));

        cli_.command("close exposure")
            .help("Close one interactive exposure")
            .argument({"id", "Exposure number"})
            .handler(safe([this](libcli2::Context& context, const libcli2::Invocation& call) {
                std::size_t consumed = 0;
                const auto id = std::stoull(call.arguments[0], &consumed);
                if(consumed != call.arguments[0].size() || !exposures_.close(id)) {
                    throw CfgTarError("unknown exposure id");
                }
                context.print("exposure closed");
                return 0;
            }));

        cli_.command("close exposures all")
            .help("Close every interactive exposure")
            .handler(safe([this](libcli2::Context& context, const libcli2::Invocation&) {
                exposures_.close_all();
                context.print("all exposures closed");
                return 0;
            }));

        cli_.command("quit")
            .help("Leave the shell; refuses while the working archive is dirty")
            .handler([this](libcli2::Context& context, const libcli2::Invocation&) {
                if(session_.dirty()) {
                    context.print(libcli2::Style::warning,
                                  "unsaved changes: use save, discard, or quit force");
                    return -1;
                }
                running_ = false;
                return 0;
            });
        cli_.command("quit force")
            .help("Leave the shell and discard unsaved changes")
            .handler([this](libcli2::Context&, const libcli2::Invocation&) {
                running_ = false;
                return 0;
            });
    }

    CfgArchiveSession session_;
    CfgExposureRegistry exposures_;
    libcli2::Cli cli_;
    libcli2::Context context_;
    bool running_ {true};
};

// Keep resource commands out of the format-owned archive root.
void require_resource_path(std::string_view path) {
    if(!CfgManifest::is_resource_path(path)) {
        throw CfgTarError("not a resource path: " + std::string(path));
    }
}

}  // namespace

std::string read_import_file(const std::string& path) {
    // Inspect the opened descriptor before allocating so FIFOs, devices,
    // symlinks and oversized imports cannot enter the archive model.
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if(fd < 0) throw CfgTarError("cannot open import file: " + path);

    struct stat metadata {};
    if(::fstat(fd, &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
       metadata.st_size < 0 || metadata.st_size > 64LL * 1024LL * 1024LL) {
        ::close(fd);
        throw CfgTarError("import must be a regular file up to 64 MiB: " + path);
    }

    std::string data(static_cast<std::size_t>(metadata.st_size), '\0');
    std::size_t offset = 0;
    while(offset < data.size()) {
        const auto count = ::read(fd, data.data() + offset, data.size() - offset);
        if(count < 0 && errno == EINTR) continue;
        if(count <= 0) {
            ::close(fd);
            throw CfgTarError("cannot read complete import file: " + path);
        }
        offset += static_cast<std::size_t>(count);
    }
    if(::close(fd) != 0) throw CfgTarError("cannot close import file: " + path);
    return data;
}

void write_export_file(const std::string& path, std::string_view content) {
    // O_EXCL makes export non-destructive; a failed write removes only the
    // file created by this call.
    const int fd = ::open(
        path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if(fd < 0) {
        throw CfgTarError("cannot create export file " + path + ": " + std::strerror(errno));
    }
    while(!content.empty()) {
        const auto count = ::write(fd, content.data(), content.size());
        if(count < 0 && errno == EINTR) continue;
        if(count <= 0) {
            ::close(fd);
            ::unlink(path.c_str());
            throw CfgTarError("cannot write export file: " + path);
        }
        content.remove_prefix(static_cast<std::size_t>(count));
    }
    if(::close(fd) != 0) {
        ::unlink(path.c_str());
        throw CfgTarError("cannot close export file: " + path);
    }
}

int run_cftar_interactive(const std::string& archive_path) {
    // Keep shell construction here so callers need no libcli2 implementation
    // types and one-shot commands remain independent of interactive state.
    return CfgTarShell(archive_path).run();
}

}  // namespace sx::cfg
