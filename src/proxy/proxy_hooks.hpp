#pragma once

#include <cstdint>
#include <string_view>
#include <nlohmann/json.hpp>
#include <vars.hpp>

class MitmProxy;
class baseHostCX;
class buffer;

namespace sx::proxy {

// Executes proxy hooks and applies their decisions synchronously where required.
// The proxy owns lifetime and call ordering; asynchronous replies retain only
// shared webhook control, never a reference to the proxy itself.
class ProxyHooks {
public:
    // Hooks without additional inputs still use the same explicit call shape.
    struct StartDetailsArgs {};
    struct StartArgs {};
    struct StopArgs {};

    struct ReadinessArgs {
        unsigned char side = 0;
        baseHostCX* cx = nullptr;
        const char* event = nullptr;
        std::uint64_t attempt = 0;
    };

    // Borrowed inputs, valid throughout the synchronous call. The caller must
    // supply cx and both buffers; no ownership is transferred to the hook.
    struct ContentArgs {
        baseHostCX* cx = nullptr;
        socle::side_t side = socle::side_t::LEFT;
        buffer* data = nullptr;
        std::string_view payload_layer;
        bool regular_webhook = false;
        bool sift = false;
        buffer* reverse_output = nullptr;
    };

    static nlohmann::json start_details(const MitmProxy& proxy, const StartDetailsArgs& args);
    static bool start(MitmProxy& proxy, const StartArgs& args);
    static void stop(const MitmProxy& proxy, const StopArgs& args);
    static void readiness(const MitmProxy& proxy, const ReadinessArgs& args);
    static bool content(MitmProxy& proxy, const ContentArgs& args);
};

} // namespace sx::proxy
