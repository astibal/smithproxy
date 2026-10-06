/*
    Smithproxy- transparent proxy with SSL inspection capabilities.
    Copyright (c) 2014, Ales Stibal <astib@mag0.net>, All rights reserved.

    Smithproxy is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Smithproxy is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Smithproxy.  If not, see <http://www.gnu.org/licenses/>.

    Linking Smithproxy statically or dynamically with other modules is
    making a combined work based on Smithproxy. Thus, the terms and
    conditions of the GNU General Public License cover the whole combination.

    In addition, as a special exception, the copyright holders of Smithproxy
    give you permission to combine Smithproxy with free software programs
    or libraries that are released under the GNU LGPL and with code
    included in the standard release of OpenSSL under the OpenSSL's license
    (or modified versions of such code, with unchanged license).
    You may copy and distribute such a system following the terms
    of the GNU GPL for Smithproxy and the licenses of the other code
    concerned, provided that you include the source code of that other code
    when and as the GNU GPL requires distribution of source code.

    Note that people who make modified versions of Smithproxy are not
    obligated to grant this special exception for their modified versions;
    it is their choice whether to do so. The GNU General Public License
    gives permission to release a modified version without this exception;
    this exception also makes it possible to release a modified version
    which carries forward this exception.
*/

#include <staticcontent.hpp>

#include <array>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

Loader::Result StaticContent::ConfinedLoader::load(std::string const& name) {
    constexpr std::size_t max_template_size = 1024U * 1024U;
    if(root_.empty() || name.empty() || name == "." || name == ".." ||
       name.find('/') != std::string::npos ||
       name.find('\\') != std::string::npos) {
        return {false, {}, "Unsafe template name " + name};
    }

    const int directory = ::open(root_.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC |
                                                O_NOFOLLOW);
    if(directory < 0) {
        return {false, {}, "Could not securely open template directory " + root_ +
                           ": " + std::strerror(errno)};
    }

    struct stat directory_stat {};
    if(::fstat(directory, &directory_stat) != 0 || !S_ISDIR(directory_stat.st_mode)) {
        const int saved_errno = errno;
        ::close(directory);
        return {false, {}, "Template root is not a directory: " +
                           std::string(std::strerror(saved_errno))};
    }

    const int file = ::openat(directory, name.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    const int open_errno = errno;
    ::close(directory);
    if(file < 0) {
        return {false, {}, "Could not securely open template " + name +
                           ": " + std::strerror(open_errno)};
    }

    struct stat file_stat {};
    if(::fstat(file, &file_stat) != 0 || !S_ISREG(file_stat.st_mode) ||
       file_stat.st_size < 0 ||
       static_cast<std::uintmax_t>(file_stat.st_size) > max_template_size) {
        ::close(file);
        return {false, {}, "Template is not a bounded regular file: " + name};
    }

    std::string content;
    content.reserve(static_cast<std::size_t>(file_stat.st_size));
    std::array<char, 8192> block {};
    while(true) {
        const auto count = ::read(file, block.data(), block.size());
        if(count == 0) break;
        if(count < 0) {
            const int read_errno = errno;
            ::close(file);
            return {false, {}, "Could not read template " + name +
                               ": " + std::strerror(read_errno)};
        }
        if(content.size() + static_cast<std::size_t>(count) > max_template_size) {
            ::close(file);
            return {false, {}, "Template grew beyond its size limit: " + name};
        }
        content.append(block.data(), static_cast<std::size_t>(count));
    }
    ::close(file);
    return {true, std::move(content), {}};
}

bool StaticContent::load_files(std::string& dir) {
    bool ret = true;
    
    try {
        auto lc_ = std::scoped_lock(lock);
        loader_file_.root(dir);
        std::vector<std::pair<std::string, std::unique_ptr<Template>>> loaded;

        for(const std::string name: { "test", "html_page", "html_img_warning",
                                      "tls_replacement"} ) {
            _dia("StaticContent::load_files: loading template %s", name.c_str());

            auto t_temp = std::make_unique<Template>(loader_file_);
            t_temp->load(name + ".txt");
            loaded.emplace_back(name, std::move(t_temp));
        }
        for (auto& [name, value] : loaded) {
            templates_->set(name, value.release());
        }
    }
    catch(std::exception& e) {
        _err("StaticContent::load_files: exception caught: %s", e.what());
        ret = false;
    }
    
    return ret;
}

std::string StaticContent::render_tls_replacement(
        std::string const& target, std::string const& reasons,
        std::string const& action) {
    auto t = get("tls_replacement");
    if(!t) return {};

    auto lc_ = std::scoped_lock(lock);
    t->set("target", target);
    t->set("reasons", reasons);
    t->set("action", action);
    auto result = t->render();
    t->get_properties().clear();
    return result;
}

std::shared_ptr<Template> StaticContent::get(std::string const& name) {
    auto t = templates_->get(name);
    if(!t) {
        _err("StaticContent::get: cannot load template '%s'", name.c_str());
    }

    return t;
}


std::string StaticContent::render_noargs(std::string const& name) {

    auto t = get(name);
    if(t) {
        return t->render();
    } 
    
    return {};
}

std::string StaticContent::render_server_response(std::string const& message, unsigned int code,
                                                  bool head_only) {
    auto const reason = [code]() -> std::string_view {
        switch(code) {
            case 200: return "OK";
            case 302: return "Found";
            case 400: return "Bad Request";
            case 403: return "Forbidden";
            case 404: return "Not Found";
            case 500: return "Internal Server Error";
            case 502: return "Bad Gateway";
            case 503: return "Service Unavailable";
            default: return "Unknown";
        }
    }();
    std::stringstream out;
    out << "HTTP/1.1 " << code << ' ' << reason << "\r\n";
    out << "Server: Smithproxy/1.1\r\n";
    out << "Content-Type: text/html; charset=utf-8\r\n";
    out << "Content-Length: " + std::to_string(message.length()); out << "\r\n";
    out << "Cache-Control: no-store\r\n";
    out << "Connection: close\r\n";
    
    out << "\r\n";
    if(!head_only) out << message;
    
    return out.str();
}

std::string StaticContent::render_msg_html_page(std::string const& caption, std::string const& meta, std::string const& content, const char* window_width) {

    auto t = get("html_page");
    if (!t)
        return {};

    auto lc_ = std::scoped_lock(lock);

    t->set("title", caption);
    t->set("meta", meta);
    t->set("message", content);
    t->set("window_width", window_width);
    
    std::string r = t->render();
    t->get_properties().clear();

    return r;
}
