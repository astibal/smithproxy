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
    [[nodiscard]] std::string state() const override;
    [[nodiscard]] std::string error() const override;

private:
    transport_options options_;
    std::unique_ptr<mitm_transport> transport_;
    bool committed_ = false;
    std::string final_state_ = "detached";
    std::string final_error_;
};

} // namespace sx::ssh

#endif
