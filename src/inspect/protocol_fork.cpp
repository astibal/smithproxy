#include <inspect/protocol_adapter.hpp>

namespace sx::engine {

std::unique_ptr<EngineCtx> EngineCtx::protocol_fork() const {
    auto adapter = protocol_adapter(*this);

    if (!adapter) {
        throw std::logic_error("Protocol fork requires an initialized protocol adapter");
    }

    return adapter->fork(*this);
}
} // namespace sx::engine
