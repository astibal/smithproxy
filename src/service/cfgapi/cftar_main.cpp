#include <service/cfgapi/cfg_pack.hpp>
#include <service/cfgapi/cfg_archive.hpp>
#include <service/cfgapi/cfg_archive_session.hpp>
#include <service/cfgapi/cftar_cli.hpp>

#include <iostream>
#include <optional>
#include <string>
#include <string_view>

namespace {

using sx::cfg::CfgPack;
using sx::cfg::CfgTar;

void usage(std::ostream& output) {
    output << "Usage:\n"
           << "  smithproxy-cftar create --config FILE --startup FILE --output FILE\n"
           << "      [--file ARCHIVE_PATH=FILE] [--executable ARCHIVE_PATH=FILE]\n"
           << "  smithproxy-cftar verify FILE\n"
           << "  smithproxy-cftar get FILE ARCHIVE_PATH\n"
           << "  smithproxy-cftar inspect FILE\n"
           << "  smithproxy-cftar list FILE [PREFIX]\n"
           << "  smithproxy-cftar resource import FILE ARCHIVE_PATH SOURCE [executable]\n"
           << "  smithproxy-cftar resource export FILE ARCHIVE_PATH DESTINATION\n"
           << "  smithproxy-cftar resource remove FILE ARCHIVE_PATH\n"
           << "  smithproxy-cftar interactive FILE\n"
           << "  smithproxy-cftar -i FILE\n";
}

// Split an explicit archive-to-filesystem mapping without interpreting either
// side. CfgTar validates the logical path and CfgPack validates the source.
CfgPack::File mapped_file(std::string_view argument, bool executable) {
    const auto separator = argument.find('=');
    if (separator == std::string_view::npos || separator == 0 || separator + 1 == argument.size()) {
        throw sx::cfg::CfgTarError("expected ARCHIVE_PATH=FILE mapping");
    }
    return {
        std::string(argument.substr(0, separator)),
        std::string(argument.substr(separator + 1)),
        executable,
    };
}

int create(int argc, char** argv) {
    // Assemble a new archive only from explicit control and resource inputs.
    CfgPack::Input input;
    std::optional<std::string> output;

    for (int index = 2; index < argc; ++index) {
        const std::string_view option = argv[index];
        if (index + 1 >= argc) {
            throw sx::cfg::CfgTarError("missing value after " + std::string(option));
        }
        const std::string value = argv[++index];

        if (option == "--config") {
            input.main_config = value;
        }
        else if (option == "--startup") {
            input.startup_config = value;
        }
        else if (option == "--output") {
            output = value;
        }
        else if (option == "--file") {
            input.files.push_back(mapped_file(value, false));
        }
        else if (option == "--executable") {
            input.files.push_back(mapped_file(value, true));
        }
        else {
            throw sx::cfg::CfgTarError("unknown create option: " + std::string(option));
        }
    }

    if (!output) {
        throw sx::cfg::CfgTarError("--output is required");
    }

    CfgPack::build(input).write_file(*output);
    std::cout << "Created " << *output << '\n';
    return 0;
}

int verify(int argc, char** argv) {
    // Preserve the original lightweight compatibility command.
    if (argc != 3) {
        throw sx::cfg::CfgTarError("verify expects exactly one archive path");
    }
    const auto archive = CfgTar::read_file(argv[2]);
    sx::cfg::CfgManifest::validate(archive);
    std::cout << argv[2] << ": valid Smithproxy CfgTar\n";
    return 0;
}

// Emit one entry only after the complete archive and manifest have passed
// validation. The caller receives no bytes from a partially trusted archive.
int get(int argc, char** argv) {
    if (argc != 4) {
        throw sx::cfg::CfgTarError("get expects an archive and one entry path");
    }
    const auto archive = CfgTar::read_file(argv[2]);
    sx::cfg::CfgManifest::validate(archive);
    const auto& data = archive.at(argv[3]).data;
    std::cout.write(data.data(), static_cast<std::streamsize>(data.size()));
    if (!std::cout) {
        throw sx::cfg::CfgTarError("cannot write archive entry");
    }
    return 0;
}

int inspect(int argc, char** argv) {
    // Report identity and inventory size without exposing stored contents.
    if(argc != 3) {
        throw sx::cfg::CfgTarError("inspect expects exactly one archive path");
    }
    const auto session = sx::cfg::CfgArchiveSession::open(argv[2]);
    std::cout << "path: " << session.path() << '\n'
              << "hash: " << session.base_hash() << '\n'
              << "entries: " << session.archive().entries().size() << '\n';
    return 0;
}

int list(int argc, char** argv) {
    // List logical paths and sizes, optionally below one namespace prefix.
    if(argc != 3 && argc != 4) {
        throw sx::cfg::CfgTarError("list expects an archive and optional prefix");
    }
    const auto session = sx::cfg::CfgArchiveSession::open(argv[2]);
    const std::string_view prefix = argc == 4 ? argv[3] : "";
    for(const auto& [path, entry] : session.archive().entries()) {
        if(path.compare(0, prefix.size(), prefix) != 0) continue;
        std::cout << path << "\t" << entry.data.size();
        if(entry.executable) std::cout << "\texecutable";
        std::cout << '\n';
    }
    return 0;
}

void require_resource_path(std::string_view path) {
    if(!sx::cfg::CfgManifest::is_resource_path(path)) {
        throw sx::cfg::CfgTarError("not a resource path: " + std::string(path));
    }
}

// One-shot resource commands deliberately use the same session as the shell.
// Each successful mutation validates the complete working archive and save()
// performs the same lock, stale-hash check, recovery write and atomic publish.
int resource(int argc, char** argv) {
    if(argc < 3) throw sx::cfg::CfgTarError("resource operation is required");
    const std::string_view operation = argv[2];

    if(operation == "import") {
        if(argc != 6 && argc != 7) {
            throw sx::cfg::CfgTarError(
                "resource import expects FILE ARCHIVE_PATH SOURCE [executable]");
        }
        const bool executable = argc == 7;
        if(executable && std::string_view(argv[6]) != "executable") {
            throw sx::cfg::CfgTarError("resource mode must be 'executable'");
        }
        require_resource_path(argv[4]);
        auto session = sx::cfg::CfgArchiveSession::open(argv[3]);
        session.put(argv[4], sx::cfg::read_import_file(argv[5]), executable);
        session.save();
        std::cout << "Imported " << argv[4] << " into " << argv[3] << '\n';
        return 0;
    }
    if(operation == "export") {
        if(argc != 6) {
            throw sx::cfg::CfgTarError(
                "resource export expects FILE ARCHIVE_PATH DESTINATION");
        }
        require_resource_path(argv[4]);
        const auto session = sx::cfg::CfgArchiveSession::open(argv[3]);
        sx::cfg::write_export_file(argv[5], session.entry(argv[4]).data);
        std::cout << "Exported " << argv[4] << " to " << argv[5] << '\n';
        return 0;
    }
    if(operation == "remove") {
        if(argc != 5) {
            throw sx::cfg::CfgTarError("resource remove expects FILE ARCHIVE_PATH");
        }
        require_resource_path(argv[4]);
        auto session = sx::cfg::CfgArchiveSession::open(argv[3]);
        session.remove(argv[4]);
        session.save();
        std::cout << "Removed " << argv[4] << " from " << argv[3] << '\n';
        return 0;
    }
    throw sx::cfg::CfgTarError("unknown resource operation: " + std::string(operation));
}

} // namespace

int main(int argc, char** argv) {
    // Dispatch a deliberately flat one-shot interface; the richer workflow is
    // isolated behind "interactive" and still operates on the same session.
    try {
        if(argc == 2 &&
           (std::string_view(argv[1]) == "--help" ||
            std::string_view(argv[1]) == "-h")) {
            usage(std::cout);
            return 0;
        }
        if (argc >= 2 && std::string_view(argv[1]) == "create") {
            return create(argc, argv);
        }
        if (argc >= 2 && std::string_view(argv[1]) == "verify") {
            return verify(argc, argv);
        }
        if (argc >= 2 && std::string_view(argv[1]) == "get") {
            return get(argc, argv);
        }
        if(argc >= 2 && std::string_view(argv[1]) == "inspect") {
            return inspect(argc, argv);
        }
        if(argc >= 2 && std::string_view(argv[1]) == "list") {
            return list(argc, argv);
        }
        if(argc >= 2 && std::string_view(argv[1]) == "resource") {
            return resource(argc, argv);
        }
        if(argc == 3 &&
           (std::string_view(argv[1]) == "interactive" ||
            std::string_view(argv[1]) == "-i")) {
            return sx::cfg::run_cftar_interactive(argv[2]);
        }
        usage(std::cerr);
        return 2;
    }
    catch (const std::exception& error) {
        std::cerr << "smithproxy-cftar: " << error.what() << '\n';
        return 1;
    }
}
