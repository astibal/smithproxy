#include <service/cfgapi/cfg_pack.hpp>
#include <service/cfgapi/cfg_source.hpp>

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
           << "  smithproxy-cftar get FILE ARCHIVE_PATH\n";
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

} // namespace

int main(int argc, char** argv) {
    try {
        if (argc >= 2 && std::string_view(argv[1]) == "create") {
            return create(argc, argv);
        }
        if (argc >= 2 && std::string_view(argv[1]) == "verify") {
            return verify(argc, argv);
        }
        if (argc >= 2 && std::string_view(argv[1]) == "get") {
            return get(argc, argv);
        }
        usage(std::cerr);
        return 2;
    }
    catch (const std::exception& error) {
        std::cerr << "smithproxy-cftar: " << error.what() << '\n';
        return 1;
    }
}
