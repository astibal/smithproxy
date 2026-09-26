#include "libcli2_socket.hpp"

#include <algorithm>
#include <cerrno>
#include <poll.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

namespace {

bool write_all(libcli2::FdTransport& transport, std::string_view text) {
    std::size_t written = 0;
    while (written < text.size()) {
        const auto count = transport.write_some(text.data() + written, text.size() - written);
        if (count > 0) { written += static_cast<std::size_t>(count); continue; }
        return false;
    }
    return true;
}

bool read_exact(libcli2::FdTransport& transport, void* destination, std::size_t size) {
    auto* bytes = static_cast<unsigned char*>(destination);
    std::size_t received = 0;
    while (received < size) {
        const auto count = transport.read_some(bytes + received, size - received);
        if (count <= 0) return false;
        received += static_cast<std::size_t>(count);
    }
    return true;
}

std::string common_prefix(const std::vector<libcli2::CompletionItem>& items) {
    if (items.empty()) return {};
    std::string prefix = items.front().value;
    for (std::size_t i = 1; i < items.size(); ++i) {
        const auto mismatch = std::mismatch(prefix.begin(), prefix.end(), items[i].value.begin(), items[i].value.end());
        prefix.erase(static_cast<std::size_t>(mismatch.first - prefix.begin()));
    }
    return prefix;
}

class SocketEditor {
public:
    SocketEditor(libcli2::FdTransport& transport, libcli2::Cli& cli, libcli2::Context& context,
                 std::function<int(libcli2::Context&)>& regular)
        : transport_(transport), cli_(cli), context_(context), regular_(regular) {}

    bool read_line(const std::string& prompt, std::string& line, bool echo = true) {
        line.clear();
        std::size_t cursor = 0, history_index = history_.size();
        std::string saved_line;
        if (!write_all(transport_, prompt)) return false;
        while (true) {
            pollfd descriptor{transport_.input_fd(), POLLIN, 0};
            const int ready = ::poll(&descriptor, 1, 1000);
            if (ready < 0) { if (errno == EINTR) continue; return false; }
            if (ready == 0) {
                if (regular_ && regular_(context_) != 0) return false;
                if (echo) redraw(prompt, line, cursor);
                continue;
            }
            unsigned char key = 0;
            if (transport_.read_some(&key, 1) != 1) return false;
            if (key == 0xff) {
                unsigned char option[2];
                if (!read_exact(transport_, option, sizeof(option))) return false;
                continue;
            }
            if (key == '\r' || key == '\n') {
                if (key == '\r') consume_lf();
                write_all(transport_, "\r\n");
                if (echo && !line.empty() && (history_.empty() || history_.back() != line)) history_.push_back(line);
                return true;
            }
            if (!echo) {
                if (key == 127 || key == 8) { if (!line.empty()) line.pop_back(); }
                else if (key >= 32) line.push_back(static_cast<char>(key));
                continue;
            }
            if (key == 4 && line.empty()) return false;
            if (key == 1) cursor = 0;
            else if (key == 5) cursor = line.size();
            else if (key == 21) { line.erase(0, cursor); cursor = 0; }
            else if (key == 127 || key == 8) { if (cursor > 0) line.erase(--cursor, 1); }
            else if (key == '\t') complete(line, cursor);
            else if (key == '?') show_help(line, cursor);
            else if (key == 27) {
                unsigned char sequence[2];
                if (!read_exact(transport_, sequence, sizeof(sequence))) return false;
                if (sequence[0] != '[') continue;
                if (sequence[1] == 'C' && cursor < line.size()) ++cursor;
                if (sequence[1] == 'D' && cursor > 0) --cursor;
                if (sequence[1] == 'A' && !history_.empty() && history_index > 0) {
                    if (history_index == history_.size()) saved_line = line;
                    line = history_[--history_index]; cursor = line.size();
                }
                if (sequence[1] == 'B' && history_index < history_.size()) {
                    ++history_index; line = history_index == history_.size() ? saved_line : history_[history_index];
                    cursor = line.size();
                }
            } else if (key >= 32) line.insert(cursor++, 1, static_cast<char>(key));
            redraw(prompt, line, cursor);
        }
    }

private:
    void consume_lf() const {
        pollfd descriptor{transport_.input_fd(), POLLIN, 0};
        if (::poll(&descriptor, 1, 0) <= 0) return;
        unsigned char next = 0; ::recv(transport_.input_fd(), &next, 1, MSG_PEEK);
        if (next == '\n' || next == 0) transport_.read_some(&next, 1);
    }
    void redraw(const std::string& prompt, const std::string& line, std::size_t cursor) const {
        std::string output = "\r\033[2K" + prompt + line;
        if (cursor < line.size()) output += "\033[" + std::to_string(line.size() - cursor) + "D";
        write_all(transport_, output);
    }
    void show_items(const std::vector<libcli2::CompletionItem>& items) const {
        std::string output = "\r\n";
        if (items.empty()) output += "  (no matches)\r\n";
        for (const auto& item : items) {
            output += "  " + item.value;
            if (!item.description.empty()) output += "\t" + item.description;
            output += "\r\n";
        }
        write_all(transport_, output);
    }
    void complete(std::string& line, std::size_t& cursor) {
        const auto result = cli_.complete(std::string_view(line).substr(0, cursor), context_);
        if (result.items.empty()) { show_help(line, cursor); return; }
        const std::string replacement = result.items.size() == 1 ? result.items.front().value : common_prefix(result.items);
        const std::size_t old_length = cursor - result.replace_begin;
        const bool changed = replacement.size() > old_length;
        if (changed || result.items.size() == 1) {
            line.replace(result.replace_begin, old_length, replacement);
            cursor = result.replace_begin + replacement.size();
            if (result.items.size() == 1 && (cursor == line.size() || line[cursor] != ' ')) line.insert(cursor++, 1, ' ');
        }
        if (result.items.size() > 1) show_items(result.items);
    }
    void show_help(const std::string& line, std::size_t cursor) {
        const auto completion = cli_.complete(std::string_view(line).substr(0, cursor), context_);
        if (!completion.items.empty()) { show_items(completion.items); return; }
        std::string path = line.substr(0, cursor);
        while (!path.empty() && path.back() == ' ') path.pop_back();
        auto output = cli_.help(path, context_);
        if (output.empty()) { show_items({}); return; }
        std::string wire = "\r\n";
        for (char ch : output) wire += ch == '\n' ? "\r\n" : std::string(1, ch);
        write_all(transport_, wire);
    }

    libcli2::FdTransport& transport_;
    libcli2::Cli& cli_;
    libcli2::Context& context_;
    std::function<int(libcli2::Context&)>& regular_;
    std::vector<std::string> history_;
};

} // namespace

int libcli2_socket_loop(libcli2::FdTransport& transport, Libcli2SocketOptions options) {
    static constexpr char telnet_options[] = "\xff\xfb\x03\xff\xfb\x01\xff\xfd\x03\xff\xfd\x01";
    write_all(transport, std::string_view(telnet_options, sizeof(telnet_options) - 1));

    libcli2::Cli cli;
    libcli2::Context context;
    context.mode = "0";
    context.io_handle = transport.output_fd();
    context.write = [&transport](std::string_view text) {
        std::string wire;
        for (char ch : text) wire += ch == '\n' ? "\r\n" : std::string(1, ch);
        wire += "\r\n";
        write_all(transport, wire);
    };
    ConfigCli2Session config(std::move(options.config_access));
    context.user_data = &config;
    config.register_commands(cli);
    cli.command("enable")
        .help("Enter privileged mode")
        .available_if([](const libcli2::Context& value) { return value.privilege < 15 && value.mode == "0"; });
    cli.command("disable")
        .help("Leave privileged mode")
        .available_if([](const libcli2::Context& value) { return value.privilege >= 15 && value.mode == "0"; })
        .handler([](libcli2::Context& value, const libcli2::Invocation&) { value.privilege = 0; return 0; });
    cli.command("quit").help("Close this CLI session")
        .handler([](libcli2::Context&, const libcli2::Invocation&) { return 1; });
    cli.command("exit").help("Leave configuration mode or close this CLI session")
        .handler([&config](libcli2::Context& value, const libcli2::Invocation&) {
            if (!config.active()) return 1;
            config.reset(); value.mode = "0"; return 0;
        });
    if (options.register_commands) options.register_commands(cli);
    SocketEditor editor(transport, cli, context, options.regular);
    if (!options.banner.empty()) write_all(transport, options.banner + "\r\n");

    if (options.authenticate) {
        bool accepted = false;
        for (int attempt = 0; attempt < 3 && !accepted; ++attempt) {
            std::string username, password;
            if (!editor.read_line("Username: ", username) || !editor.read_line("Password: ", password, false)) return -1;
            accepted = options.authenticate(username, password) == 0;
            if (!accepted) write_all(transport, "Access denied\r\n");
        }
        if (!accepted) return -1;
        if (options.privilege_after_auth) context.privilege = 15;
    }

    std::string line;
    while (editor.read_line(options.prompt ? options.prompt(context) : "smithproxy> ", line)) {
        bool enable_request = line == "enable";
        if (!enable_request && line.find(' ') == std::string::npos) {
            const auto candidates = cli.complete(line, context);
            enable_request = candidates.items.size() == 1 && candidates.items.front().value == "enable";
        }
        if (enable_request && context.privilege < 15) {
            if (options.enable_password.empty()) context.privilege = 15;
            else {
                std::string password;
                if (!editor.read_line("Password: ", password, false)) break;
                if (password == options.enable_password) context.privilege = 15;
                else write_all(transport, "Access denied\r\n");
            }
            continue;
        }
        const auto result = cli.execute(line, context);
        if (result.handler_status == 1) break;
        if (result.status != libcli2::ExecuteStatus::ok && result.status != libcli2::ExecuteStatus::empty) {
            write_all(transport, "% " + result.message + "\r\n");
            if (!result.candidates.empty()) {
                std::string candidates = "  candidates:";
                for (const auto& candidate : result.candidates) candidates += " " + candidate;
                write_all(transport, candidates + "\r\n");
            }
        }
    }
    return 0;
}
