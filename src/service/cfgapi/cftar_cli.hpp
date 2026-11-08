#pragma once

#include <iosfwd>
#include <string>
#include <string_view>

namespace sx::cfg {

// Run the small libcli2 shell over one offline archive. The shell is only a
// presentation layer: all mutation, validation and persistence stay in
// CfgArchiveSession so one-shot commands can use the same behavior.
int run_cftar_interactive(const std::string& archive_path);

// Read one regular, non-symlink file with the CFtar per-entry size limit.
std::string read_import_file(const std::string& path);
// Create one private export without following links or replacing a file.
void write_export_file(const std::string& path, std::string_view content);

}  // namespace sx::cfg
