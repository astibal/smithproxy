#include <service/comm.hpp>

#include <algorithm>
#include <array>
#include <cerrno>
#include <climits>
#include <cstring>
#include <poll.h>
#include <unordered_set>
#include <unistd.h>
#include <fcntl.h>

namespace {

constexpr std::array<std::byte, 2> magic{std::byte{'S'}, std::byte{'C'}};
constexpr std::uint8_t version = 1;
constexpr std::size_t header_size = 12;
constexpr std::size_t max_payload = 64U * 1024U;

void put_u32(std::byte* destination, std::uint32_t value) {
    destination[0] = std::byte{static_cast<std::uint8_t>(value >> 24U)};
    destination[1] = std::byte{static_cast<std::uint8_t>(value >> 16U)};
    destination[2] = std::byte{static_cast<std::uint8_t>(value >> 8U)};
    destination[3] = std::byte{static_cast<std::uint8_t>(value)};
}

std::uint32_t get_u32(const std::byte* source) {
    return (std::to_integer<std::uint32_t>(source[0]) << 24U)
        | (std::to_integer<std::uint32_t>(source[1]) << 16U)
        | (std::to_integer<std::uint32_t>(source[2]) << 8U)
        | std::to_integer<std::uint32_t>(source[3]);
}

std::vector<std::byte> frame(std::uint8_t opcode, int status, const std::string& payload) {
    std::vector<std::byte> result(header_size + payload.size());
    result[0] = magic[0]; result[1] = magic[1];
    result[2] = std::byte{version}; result[3] = std::byte{opcode};
    put_u32(result.data() + 4, static_cast<std::uint32_t>(status));
    put_u32(result.data() + 8, static_cast<std::uint32_t>(payload.size()));
    if(!payload.empty()) std::memcpy(result.data() + header_size, payload.data(), payload.size());
    return result;
}

bool valid_frame(const socle::privsep::Message& message) {
    if(message.data.size() < header_size || message.data[0] != magic[0]
       || message.data[1] != magic[1] || message.data[2] != std::byte{version}) return false;
    const auto size = get_u32(message.data.data() + 8);
    return size <= max_payload && message.data.size() == header_size + size;
}

std::string payload(const socle::privsep::Message& message) {
    return {reinterpret_cast<const char*>(message.data.data() + header_size),
            get_u32(message.data.data() + 8)};
}

} // namespace

namespace sx::comm {

Reply error_reply(int error) { return {error == 0 ? EIO : error, {}, -1}; }

Client::Client(int fd, std::chrono::milliseconds timeout): channel_(fd), timeout_(timeout) {}

int Client::set_nonblocking() {
    const int flags = ::fcntl(channel_.fd(), F_GETFL);
    return flags < 0 ? -1 : ::fcntl(channel_.fd(), F_SETFL, flags | O_NONBLOCK);
}

int Client::wait_readable() const {
    pollfd descriptor{channel_.fd(), POLLIN, 0};
    const int timeout = static_cast<int>(std::min<std::int64_t>(timeout_.count(), INT_MAX));
    int result;
    do { result = ::poll(&descriptor, 1, timeout); } while(result < 0 && errno == EINTR);
    if(result == 0) { errno = ETIMEDOUT; return -1; }
    if(result < 0) return -1;
    if((descriptor.revents & POLLIN) == 0) { errno = ECONNRESET; return -1; }
    return 0;
}

void Client::break_channel() noexcept { broken_ = true; channel_.close(); }

int Client::request(std::uint8_t opcode, const std::string& request_payload, int passed_fd,
                    Reply& response) {
    std::lock_guard lock(mutex_);
    if(broken_) { errno = ECONNRESET; return -1; }
    const auto wire_request = frame(opcode, 0, request_payload);
    socle::privsep::Message wire_response;
    if(channel_.send(wire_request, passed_fd) != 0 || wait_readable() != 0
       || channel_.receive(wire_response) <= 0 || !valid_frame(wire_response)
       || (wire_response.data[3] != std::byte{opcode}
           && wire_response.data[3] != std::byte{0})) {
        if(wire_response.fd >= 0) ::close(wire_response.fd);
        const int saved = errno == 0 ? EPROTO : errno;
        break_channel(); errno = saved; return -1;
    }
    const int status = static_cast<int>(get_u32(wire_response.data.data() + 4));
    if(status != 0) { if(wire_response.fd >= 0) ::close(wire_response.fd); errno = status; return -1; }
    response = {0, payload(wire_response), wire_response.fd};
    wire_response.fd = -1;
    return 0;
}

int Client::notify(std::uint8_t opcode, const std::string& value, int passed_fd) {
    std::lock_guard lock(mutex_);
    if(broken_) { errno = ECONNRESET; return -1; }
    return channel_.send(frame(opcode, 0, value), passed_fd);
}

Server::Server(int fd): channel_(fd) {}
Server::~Server() { shutdown_operations(); }

int Server::register_operation(std::uint8_t opcode, std::shared_ptr<Operation> operation) {
    if(running_) { errno = EBUSY; return -1; }
    if(opcode == 0 || !operation) { errno = EINVAL; return -1; }
    if(!operations_.emplace(opcode, std::move(operation)).second) { errno = EEXIST; return -1; }
    return 0;
}

int Server::respond(std::uint8_t opcode, Reply reply) {
    const int result = channel_.send(frame(opcode, reply.status, reply.payload), reply.fd);
    const int saved = errno;
    if(reply.fd >= 0) ::close(reply.fd);
    errno = saved;
    return result;
}

int Server::dispatch(socle::privsep::Message& wire) {
    if(!valid_frame(wire)) return respond(0, error_reply(EPROTO));
    const auto opcode = std::to_integer<std::uint8_t>(wire.data[3]);
    const auto found = operations_.find(opcode);
    if(found == operations_.end()) return respond(opcode, error_reply(EOPNOTSUPP));
    Request request{opcode, payload(wire), wire.fd};
    try {
        auto reply = found->second->execute(request);
        return found->second->one_way() ? 0 : respond(opcode, std::move(reply));
    } catch(...) {
        return found->second->one_way() ? 0 : respond(opcode, error_reply(EIO));
    }
}

int Server::serve_once() {
    running_ = true;
    socle::privsep::Message request;
    const int received = channel_.receive(request);
    if(received <= 0) return received;
    const int result = dispatch(request);
    if(request.fd >= 0) ::close(request.fd);
    return result == 0 ? 1 : -1;
}

int Server::run() {
    for(;;) {
        const int result = serve_once();
        if(result <= 0) { shutdown_operations(); return result; }
    }
}

void Server::shutdown_operations() noexcept {
    if(shutdown_complete_) return;
    std::unordered_set<Operation*> invoked;
    for(auto& [opcode, operation]: operations_) {
        (void)opcode;
        if(operation && invoked.insert(operation.get()).second) operation->shutdown();
    }
    shutdown_complete_ = true;
}

} // namespace sx::comm
