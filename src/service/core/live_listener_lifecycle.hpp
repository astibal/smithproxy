#pragma once

namespace smithproxy::live {

enum class Listener { tproxy, redirect, socks, http_connect };
enum class Workers { tproxy, socks, http_connect };

template <class Enabled, class Stop, class Create, class Launch>
bool apply_listener(bool previous_enabled, Enabled&& enabled, Stop&& stop,
                    Create&& create, Launch&& launch) {
    const bool current_enabled = enabled();
    if (current_enabled == previous_enabled) return true;

    stop();
    if (!current_enabled) return true;
    if (!create()) {
        stop();  // discard a partially created listener group
        return false;
    }
    launch();
    return true;
}

template <class Restart>
bool apply_workers(Workers workers, Restart&& restart) {
    if (workers == Workers::tproxy) {
        // REDIRECT shares the transparent TCP/TLS/UDP worker settings.
        return restart(Listener::tproxy) && restart(Listener::redirect);
    }
    return restart(workers == Workers::socks ? Listener::socks
                                              : Listener::http_connect);
}

}  // namespace smithproxy::live
