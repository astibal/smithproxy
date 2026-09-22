#ifndef SMITHPROXY_MFFLOWCOM_HPP
#define SMITHPROXY_MFFLOWCOM_HPP

#include <basecom.hpp>

#include <atomic>
#include <deque>
#include <memory>

#include "proxy/multiflow/multiflow.hpp"

namespace sx::multiflow {

/** A baseCom compatibility facade for one logical multiflow byte stream. */
class MFFlowCom final : public baseCom {
public:
    MFFlowCom(std::shared_ptr<connection> owner, flow_handle flow);
    ~MFFlowCom() override;

    baseCom* replicate() override;

    int connect(const char*, const char*) override;
    int accept(int, sockaddr*, socklen_t*) override;
    int bind(unsigned short) override;
    int bind(const char*) override;

    ssize_t read(int token, void* destination, size_t size, int flags) override;
    ssize_t peek(int token, void* destination, size_t size, int flags) override;
    ssize_t write(int token, const void* source, size_t size, int flags) override;

    void shutdown(int token) override;
    void close(int token) override;
    void cleanup() override;

    bool is_connected(int token) override;
    bool com_status() override;
    bool readable(int token) override;
    bool writable(int token) override;
    bool in_readset(int token) override;
    bool in_writeset(int token) override;
    int translate_socket(int token) const override;
    int poll() override;

    flow_handle flow() const { return flow_; }
    int token() const { return token_; }

    std::string shortname() const override { return "mf"; }
    std::string to_string(int verbosity) const override;

    TYPENAME_OVERRIDE("MFFlowCom")

private:
    ssize_t map_result(io_result result);
    std::shared_ptr<connection> lock_connection() const;
    static int next_token();

    std::weak_ptr<connection> connection_;
    flow_handle flow_;
    int token_ = 0;
    std::deque<unsigned char> peek_buffer_;
    bool cleaned_up_ = false;
};

} // namespace sx::multiflow

#endif // SMITHPROXY_MFFLOWCOM_HPP
