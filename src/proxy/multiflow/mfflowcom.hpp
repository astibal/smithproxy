#ifndef SMITHPROXY_MFFLOWCOM_HPP
#define SMITHPROXY_MFFLOWCOM_HPP

#include <basecom.hpp>

#include <atomic>
#include <deque>
#include <memory>

#include "proxy/multiflow/multiflow.hpp"

namespace sx::multiflow {

/**
 * Exposes one logical multiflow stream through Smithproxy's baseCom API.
 *
 * There is deliberately no operating-system file descriptor per instance.
 * MFProxy schedules the stream through its owning multiplexed connection, while
 * legacy consumers can keep using familiar baseCom read/write/status methods.
 * The connection is weakly referenced so a flow facade cannot prolong the
 * lifetime of its physical transport.
 */
class MFFlowCom final : public baseCom {
public:
    /** Bind the facade to one flow owned by the shared physical connection. */
    MFFlowCom(std::shared_ptr<connection> owner, flow_handle flow);
    ~MFFlowCom() override;

    /** Create an unbound facade as required by the baseCom factory contract. */
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
    /** Idempotently send FIN for this facade's flow without closing siblings. */
    void cleanup() override;

    bool is_connected(int token) override;
    bool com_status() override;
    bool readable(int token) override;
    bool writable(int token) override;
    bool in_readset(int token) override;
    bool in_writeset(int token) override;
    int translate_socket(int token) const override;
    int poll() override;

    flow_handle flow() const { return flow_; } ///< Underlying logical-flow handle.
    int token() const { return token_; }        ///< Synthetic baseCom socket token.
    /**
     * Keep a peer FIN from looking like a full socket close to legacy proxies.
     * The multiflow owner then propagates each half-close independently.
     */
    void defer_read_eof(bool enabled) { defer_read_eof_ = enabled; }

    std::string shortname() const override { return "mf"; }
    std::string to_string(int verbosity) const override;

    TYPENAME_OVERRIDE("MFFlowCom")

private:
    /** Translate transport-neutral results to baseCom/errno conventions. */
    ssize_t map_result(io_result result);
    /** Lock the non-owning connection reference for one operation. */
    std::shared_ptr<connection> lock_connection() const;
    /** Allocate negative tokens which cannot collide with real descriptors. */
    static int next_token();

    std::weak_ptr<connection> connection_;      ///< Non-owning physical transport.
    flow_handle flow_;                          ///< Stream selected on that transport.
    int token_ = 0;                             ///< Synthetic identity for baseCom.
    std::deque<unsigned char> peek_buffer_;     ///< Bytes retained by peek().
    bool cleaned_up_ = false;                   ///< Guards duplicate FIN transmission.
    bool defer_read_eof_ = false;               ///< Let the owner handle stream half-close.
    bool peer_eof_ = false;                     ///< Suppress repeated reads after peer FIN.
};

} // namespace sx::multiflow

#endif // SMITHPROXY_MFFLOWCOM_HPP
