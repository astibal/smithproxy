#include "proxy/multiflow/mfflowcom.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <vector>

#include <stringformat.hpp>

namespace sx::multiflow {

MFFlowCom::MFFlowCom(std::shared_ptr<connection> owner, flow_handle flow)
    : connection_(std::move(owner)), flow_(flow), token_(next_token()) {
    l4_proto(SOCK_STREAM);
    socket(token_);
}

MFFlowCom::~MFFlowCom() {
    cleanup();
}

baseCom* MFFlowCom::replicate() {
    return new MFFlowCom(connection_.lock(), {});
}

int MFFlowCom::connect(const char*, const char*) {
    errno = EOPNOTSUPP;
    return -1;
}

int MFFlowCom::accept(int, sockaddr*, socklen_t*) {
    errno = EOPNOTSUPP;
    return -1;
}

int MFFlowCom::bind(unsigned short) {
    errno = EOPNOTSUPP;
    return -1;
}

int MFFlowCom::bind(const char*) {
    errno = EOPNOTSUPP;
    return -1;
}

ssize_t MFFlowCom::read(int, void* destination, size_t size, int) {
    if (size == 0) return 0;

    if (!peek_buffer_.empty()) {
        auto const copied = std::min(size, peek_buffer_.size());
        auto* output = static_cast<unsigned char*>(destination);
        for (std::size_t i = 0; i < copied; ++i) {
            output[i] = peek_buffer_.front();
            peek_buffer_.pop_front();
        }
        return static_cast<ssize_t>(copied);
    }

    auto connection = lock_connection();
    if (!connection) {
        errno = ENOTCONN;
        return -1;
    }
    auto const result = connection->read(flow_, destination, size);
    if (defer_read_eof_ && result.size == 0 && result.status == io_status::eof) {
        // A QUIC FIN closes only the peer's sending half. Returning zero here
        // makes the stream-oriented MitmProxy tear down both halves before an
        // HTTP/3 response can arrive. The multiflow owner consumes the emitted
        // peer_fin event and forwards FIN after buffered bytes have drained.
        peer_eof_ = true;
        errno = EAGAIN;
        return -1;
    }
    return map_result(result);
}

ssize_t MFFlowCom::peek(int, void* destination, size_t size, int) {
    if (size == 0) return 0;
    auto connection = lock_connection();
    if (!connection) {
        errno = ENOTCONN;
        return -1;
    }

    io_result fill_result { 0, io_status::ok };
    if (peek_buffer_.size() < size) {
        std::vector<unsigned char> temporary(size - peek_buffer_.size());
        fill_result = connection->read(flow_, temporary.data(), temporary.size());
        if (fill_result.status == io_status::ok) {
            peek_buffer_.insert(peek_buffer_.end(), temporary.begin(),
                                temporary.begin() + static_cast<std::ptrdiff_t>(fill_result.size));
        }
    }

    auto const copied = std::min(size, peek_buffer_.size());
    if (copied != 0) {
        auto* output = static_cast<unsigned char*>(destination);
        std::copy_n(peek_buffer_.begin(), copied, output);
        return static_cast<ssize_t>(copied);
    }
    if (defer_read_eof_ && fill_result.size == 0
        && fill_result.status == io_status::eof) {
        peer_eof_ = true;
        errno = EAGAIN;
        return -1;
    }
    return map_result(fill_result);
}

ssize_t MFFlowCom::write(int, const void* source, size_t size, int) {
    auto connection = lock_connection();
    if (!connection) {
        errno = ENOTCONN;
        return -1;
    }
    auto const result = connection->write(flow_, source, size);
    if (result.status == io_status::would_block && result.size == 0) {
        // baseHostCX keeps bytes in its output buffer when write returns zero.
        errno = EAGAIN;
        return 0;
    }
    return map_result(result);
}

void MFFlowCom::shutdown(int) {
    cleanup();
}

void MFFlowCom::close(int) {
    cleanup();
}

void MFFlowCom::cleanup() {
    if (cleaned_up_) return;
    cleaned_up_ = true;
    if (auto connection = lock_connection(); connection && connection->contains(flow_)) {
        connection->finish(flow_);
    }
}

bool MFFlowCom::is_connected(int) {
    auto connection = lock_connection();
    return connection && connection->contains(flow_);
}

bool MFFlowCom::com_status() {
    return is_connected(token_);
}

bool MFFlowCom::readable(int) {
    auto connection = lock_connection();
    return !peek_buffer_.empty()
        || (!peer_eof_ && connection && connection->readable(flow_));
}

bool MFFlowCom::writable(int) {
    auto connection = lock_connection();
    return connection && connection->writable(flow_);
}

bool MFFlowCom::in_readset(int token) {
    return readable(token);
}

bool MFFlowCom::in_writeset(int token) {
    return writable(token);
}

int MFFlowCom::translate_socket(int) const {
    // Logical flows are scheduled by BaseMFProxy, never registered in epoll.
    return -1;
}

int MFFlowCom::poll() {
    return 0;
}

std::string MFFlowCom::to_string(int) const {
    return string_format("MFFlowCom[%llu:%llu]",
                         static_cast<unsigned long long>(flow_.id),
                         static_cast<unsigned long long>(flow_.generation));
}

ssize_t MFFlowCom::map_result(io_result result) {
    // A transport may report partial progress together with would_block.
    // baseHostCX must consume that prefix and retain only the unsent suffix.
    if (result.size != 0) return static_cast<ssize_t>(result.size);

    switch (result.status) {
        case io_status::ok:
            return static_cast<ssize_t>(result.size);
        case io_status::would_block:
            errno = EAGAIN;
            return -1;
        case io_status::eof:
            return 0;
        case io_status::reset:
            errno = ECONNRESET;
            error(ERROR_READ);
            return -1;
        case io_status::connection_closed:
            errno = ENOTCONN;
            error(ERROR_SOCKET);
            return -1;
        case io_status::invalid_handle:
            errno = EBADF;
            error(ERROR_SOCKET);
            return -1;
    }
    errno = EIO;
    return -1;
}

std::shared_ptr<connection> MFFlowCom::lock_connection() const {
    return connection_.lock();
}

int MFFlowCom::next_token() {
    static std::atomic<int> next { -2 };
    return next.fetch_sub(1);
}

} // namespace sx::multiflow
