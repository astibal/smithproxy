#include <cli/clistate.hpp>
#include <cli/cligen.hpp>

std::string CliState::template_callback_key (std::string const& section, cli_def* cli) {

    std::string template_key = section;

    if(CliState::get().has_callback(section)) {

        // it is possible object is already in callback db (set up by previous cmd generation),
        // but we still need to look for .[x] template!
        _debug(cli, "object %s has callbacks set ", template_key.c_str());

        if (CliState::get().has_callback(section + ".[x]")) {
            _debug(cli, "object %s has callbacks set, but prefer .[x] template", template_key.c_str());
            template_key = section + ".[x]";
        }
    }
    else if (CliState::get().has_callback(section + ".[x]")) {

        _debug(cli, "object %s has no callbacks set, but .[x] found", template_key.c_str());
        template_key = section + ".[x]";
    }
    else {
        _debug(cli, "object %s has callbacks set, no template set", template_key.c_str());
        // otherwise there is no template and template_cb will be the same as section_cb
        template_key = section;
    }

    return template_key;
}