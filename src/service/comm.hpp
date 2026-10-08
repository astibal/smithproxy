#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

#include <privileged_socket.hpp>

namespace sx::comm {

struct Request {
    std::uint8_t opcode = 0;
    std::string payload;
    int fd = -1;
};

struct Reply {
    int status = 0;
    std::string payload;
    int fd = -1;
};

class Operation {
public:
    virtual ~Operation() = default;
    virtual Reply execute(const Request& request) = 0;
    virtual bool one_way() const noexcept { return false; }
    virtual void shutdown() noexcept {}
};

class Client {
public:
    explicit Client(int fd, std::chrono::milliseconds timeout = std::chrono::seconds(90));

    int request(std::uint8_t opcode, const std::string& payload, int passed_fd,
                Reply& response);
    // A one-way operation. EAGAIN/ENOBUFS is reported to the caller and never
    // turns the channel into a blocking dataplane dependency.
    int notify(std::uint8_t opcode, const std::string& payload, int passed_fd = -1);
    int set_nonblocking();

private:
    int wait_readable() const;
    void break_channel() noexcept;

    socle::privsep::SeqPacketChannel channel_;
    std::chrono::milliseconds timeout_;
    std::mutex mutex_;
    bool broken_ = false;
};

class Server {
public:
    explicit Server(int fd);
    virtual ~Server();

    int run();
    int serve_once();
    int register_operation(std::uint8_t opcode, std::shared_ptr<Operation> operation);

private:
    int dispatch(socle::privsep::Message& request);
    int respond(std::uint8_t opcode, Reply reply);
    void shutdown_operations() noexcept;

    socle::privsep::SeqPacketChannel channel_;
    std::unordered_map<std::uint8_t, std::shared_ptr<Operation>> operations_;
    bool running_ = false;
    bool shutdown_complete_ = false;
};

Reply error_reply(int error);

} // namespace sx::comm
