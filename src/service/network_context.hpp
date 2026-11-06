#pragma once

#include <array>
#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <set>
#include <thread>
#include <vector>

namespace sx::net {

struct InterfaceInfo {
    std::uint32_t index = 0;
    std::string name;
    std::uint32_t flags = 0;
    std::string role{};
};

struct InterfaceAddress {
    std::uint32_t interface_index = 0;
    std::string interface_name;
    int family = 0;
    std::array<std::uint8_t, 16> address{};
    std::uint8_t address_size = 0;
    std::uint8_t prefix_length = 0;
    std::uint8_t scope = 0;
    std::uint32_t flags = 0;

    [[nodiscard]] std::string text() const;
};


struct InterfaceSnapshot {
    std::uint64_t generation = 0;
    bool valid = false;
    bool roles_valid = false;
    std::vector<InterfaceInfo> interfaces;
    std::vector<InterfaceAddress> addresses;

    void assign_automatic_roles(const std::set<std::uint32_t>& uplinks);
    [[nodiscard]] std::optional<std::string> interface_role(std::uint32_t index) const;
    [[nodiscard]] std::optional<std::string> interface_name(std::uint32_t index) const;
    [[nodiscard]] bool contains_address(int family, const void* address,
                                        std::size_t address_size) const noexcept;
};

struct NetworkCtxStats {
    bool running = false;
    std::uint64_t synchronization_attempts = 0;
    std::uint64_t synchronization_successes = 0;
    std::uint64_t errors = 0;
    std::uint64_t event_datagrams = 0;
    std::uint64_t changed_event_datagrams = 0;
};

namespace detail {

struct NetlinkBatchResult {
    bool ok = true;
    bool changed = false;
    bool done = false;
    bool dump_interrupted = false;
    int error_code = 0;
    std::string error;
};

// Mutable writer-side state. Readers only receive immutable snapshots made
// from this table, so applying a netlink batch never exposes partial updates.
class InterfaceTable {
public:
    void clear();
    [[nodiscard]] NetlinkBatchResult apply_netlink_datagram(
        const void* data, std::size_t size, std::uint32_t expected_sequence = 0);
    [[nodiscard]] std::shared_ptr<const InterfaceSnapshot> snapshot(
        std::uint64_t generation, bool valid) const;

private:
    struct AddressKey {
        std::uint32_t interface_index = 0;
        int family = 0;
        std::array<std::uint8_t, 16> address{};

        bool operator<(const AddressKey& other) const noexcept;
    };

    struct AddressRecord {
        InterfaceAddress value;
        std::string label;
    };

    std::map<std::uint32_t, InterfaceInfo> interfaces_;
    std::map<AddressKey, AddressRecord> addresses_;
};

} // namespace detail

class NetworkCtx {
public:
    NetworkCtx(const NetworkCtx&) = delete;
    NetworkCtx& operator=(const NetworkCtx&) = delete;

    static NetworkCtx& instance();

    // Starts one reader thread and waits until its first dump succeeds or
    // fails. A failed initial attempt is retried in the background.
    [[nodiscard]] bool start();
    void stop() noexcept;

    // Numeric destinations only. A failed lookup is unknown, never interface 0.
    [[nodiscard]] std::optional<std::uint32_t> route_lookup(const std::string& destination) const;

    [[nodiscard]] bool running() const noexcept;
    [[nodiscard]] std::shared_ptr<const InterfaceSnapshot> snapshot() const noexcept;
    [[nodiscard]] NetworkCtxStats stats() const noexcept;
    [[nodiscard]] std::string last_error() const;

private:
    NetworkCtx();
    ~NetworkCtx();

    void run() noexcept;
    void publish(bool valid);
    void publish_invalid(const std::string& error);
    void signal_initial_result(bool success);
    [[nodiscard]] bool stop_requested() const noexcept;

    mutable std::mutex lifecycle_mutex_;
    mutable std::mutex error_mutex_;
    std::condition_variable initial_condition_;
    std::thread worker_;
    int stop_fd_ = -1;
    bool initial_complete_ = false;
    bool initial_success_ = false;
    std::atomic<bool> stop_requested_{false};
    std::atomic<bool> running_{false};
    std::atomic<std::uint64_t> synchronization_attempts_{0};
    std::atomic<std::uint64_t> synchronization_successes_{0};
    std::atomic<std::uint64_t> errors_{0};
    std::atomic<std::uint64_t> event_datagrams_{0};
    std::atomic<std::uint64_t> changed_event_datagrams_{0};
    std::shared_ptr<const InterfaceSnapshot> snapshot_;
    std::string last_error_;
    std::uint64_t generation_ = 0;
    detail::InterfaceTable table_;
};

} // namespace sx::net
