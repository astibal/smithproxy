/*
 * StreamHandler adapter for the libssh MITM transport.
 */

#ifndef SMITHPROXY_SSHSTREAM_HPP
#define SMITHPROXY_SSHSTREAM_HPP

#include <memory>
#include <string>

#include <proxy/streamhandler.hpp>
#include <proxy/ssh/sshmitm.hpp>

namespace sx::ssh {

class stream_handler final : public sx::StreamHandler {
public:
    explicit stream_handler(transport_options options);
    ~stream_handler() override;

    bool attach(MitmProxy& proxy) override;
    result drive() override;
    void shutdown() noexcept override;

    [[nodiscard]] bool committed() const noexcept override { return committed_; }
    [[nodiscard]] std::string_view session_protocol() const noexcept override { return "ssh"; }
    [[nodiscard]] std::uint64_t bytes_up() const noexcept override;
    [[nodiscard]] std::uint64_t bytes_down() const noexcept override;
    [[nodiscard]] std::string state() const override;
    [[nodiscard]] std::string error() const override;

private:
    transport_options options_;
    std::unique_ptr<mitm_transport> transport_;
    bool committed_ = false;
    std::string final_state_ = "detached";
    std::string final_error_;
    std::uint64_t final_bytes_up_ = 0;
    std::uint64_t final_bytes_down_ = 0;
};

} // namespace sx::ssh

#endif
