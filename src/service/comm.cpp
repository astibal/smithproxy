#include <service/comm.hpp>
#include <service/comm_frame.hpp>

#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstring>
#include <poll.h>
#include <unordered_set>
#include <unistd.h>
#include <fcntl.h>

namespace {

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
    const auto wire_request = wire::encode(opcode, 0, request_payload);
    socle::privsep::Message wire_response;
    if(channel_.send(wire_request, passed_fd) != 0) {
        if(errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS) return -1;
        const int saved = errno == 0 ? EIO : errno;
        break_channel(); errno = saved; return -1;
    }
    wire::Header response_header;
    std::string response_payload;
    if(wait_readable() != 0 || channel_.receive(wire_response) <= 0
       || !wire::decode(wire_response.data, response_header, response_payload)
       || (response_header.opcode != opcode && response_header.opcode != 0)) {
        if(wire_response.fd >= 0) ::close(wire_response.fd);
        const int saved = errno == 0 ? EPROTO : errno;
        break_channel(); errno = saved; return -1;
    }
    const int status = response_header.status;
    if(status != 0) { if(wire_response.fd >= 0) ::close(wire_response.fd); errno = status; return -1; }
    response = {0, std::move(response_payload), wire_response.fd};
    wire_response.fd = -1;
    return 0;
}

int Client::notify(std::uint8_t opcode, const std::string& value, int passed_fd) {
    std::lock_guard lock(mutex_);
    if(broken_) { errno = ECONNRESET; return -1; }
    return channel_.send(wire::encode(opcode, 0, value), passed_fd);
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
    const int result = channel_.send(wire::encode(opcode, reply.status, reply.payload), reply.fd);
    const int saved = errno;
    if(reply.fd >= 0) ::close(reply.fd);
    errno = saved;
    return result;
}

int Server::dispatch(socle::privsep::Message& wire) {
    sx::comm::wire::Header header;
    std::string request_payload;
    if(!sx::comm::wire::decode(wire.data, header, request_payload))
        return respond(0, error_reply(EPROTO));
    const auto opcode = header.opcode;
    const auto found = operations_.find(opcode);
    if(found == operations_.end()) return respond(opcode, error_reply(EOPNOTSUPP));
    Request request{opcode, std::move(request_payload), wire.fd};
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
    // SOCK_SEQPACKET discarded the complete offending datagram. A malformed
    // or ancillary-truncated packet must not let a client terminate the broker.
    if(received < 0 && (errno == EMSGSIZE || errno == EPROTO)) return 1;
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

int Server::run_until(const std::function<bool()>& stop,
                      std::chrono::milliseconds poll_interval) {
    if(!stop || poll_interval.count() < 1) { errno = EINVAL; return -1; }
    while(!stop()) {
        pollfd descriptor{channel_.fd(), POLLIN, 0};
        const int timeout = static_cast<int>(
            std::min<std::int64_t>(poll_interval.count(), INT_MAX));
        int ready;
        do { ready = ::poll(&descriptor, 1, timeout); } while(ready < 0 && errno == EINTR);
        if(ready < 0) return -1;
        if(ready == 0) continue;
        if((descriptor.revents & (POLLIN | POLLHUP | POLLERR)) == 0) {
            errno = EIO;
            return -1;
        }
        const int result = serve_once();
        if(result <= 0) { shutdown_operations(); return result; }
    }
    shutdown_operations();
    return 0;
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
