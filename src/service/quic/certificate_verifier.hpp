#include "proxy/quic/error_stats.hpp"
#include "proxy/quic/log.hpp"
#pragma once

#include "proxy/proxymaker_connect.hpp"
#include "service/tpool.hpp"

#include <sslcom.hpp>
#include <vars.hpp>
#include <atomic>

namespace sx::quic {

// Apply the same certificate policy as TCP/TLS without creating another
// transport. SSL owns the live verifier; revocation workers own independent
// snapshots, so closing a QUIC session never leaves a worker using its SSL.
class certificate_verifier final : public SSLCom {
public:
    // Translate the session's policy snapshot into the shared SSLCom checks.
    // QUIC admits explicit exceptions, but does not serve a replacement page.
    explicit certificate_verifier(proxymaker::QuicTlsPolicy policy) : policy_(policy) {
        opt.cert.allow_self_signed = policy.allow_self_signed;
        opt.cert.allow_unknown_issuer = policy.allow_untrusted_issuers;
        opt.cert.allow_self_signed_chain = policy.allow_untrusted_issuers;
        opt.cert.allow_not_valid = policy.allow_invalid_certs;
        opt.cert.failed_check_replacement = false;

        opt.ct_enable = policy.ct_enable;
        opt.ocsp.stapling_enabled = policy.ocsp_stapling;
        opt.ocsp.stapling_mode = policy.ocsp_stapling_mode;
        opt.ocsp.mode = policy.ocsp_mode;
    }

    // Snapshot chains own their references; SSLCom releases the other retained
    // certificates and the snapshot's memory-only SSL object.
    ~certificate_verifier() override = default;

    // Supply the retained chain to SSLCom's OCSP/CRL helpers. Borrowed by callers.
    STACK_OF(X509)* verified_peer_chain() const override { return chain_.value; }

    // Keep certificate selection consistent with the policy used for admission.
    proxymaker::QuicTlsPolicy const& policy() const { return policy_; }

    // After progress starts, distinguish ordinary trust from a policy exception.
    // An allowed invalid origin must not produce a normally trusted MITM identity.
    bool trusted() const { return !exception_; }

    // Read the worker's published result: 0 pending, 1 accepted, -1 rejected.
    int verdict() const { return result_->load(std::memory_order_acquire); }

    // Look up the verifier attached before the upstream handshake; may be null
    // for connections that intentionally bypass verification in the testbed.
    static certificate_verifier* get(SSL* ssl) {
        if (!ssl || index() < 0) return nullptr;
        return static_cast<certificate_verifier*>(SSL_get_ex_data(ssl, index()));
    }

    // Attach ownership and verification callbacks before the first ClientHello.
    // False aborts connection setup; once attached, SSL also owns failure cleanup.
    static bool install(SSL* ssl, proxymaker::QuicTlsPolicy const& policy) {
        if (!ssl) {
            ++stats.errors.verifier_install_missing_ssl;
            return false;
        }
        auto verifier = std::make_unique<certificate_verifier>(policy);
        if (index() < 0 || SSL_set_ex_data(ssl, index(), verifier.get()) != 1) {
            ++stats.errors.verifier_install_attachment_failed;
            return false;
        }

        auto* value = verifier.release();
        value->owner_ = ssl;
        if (SSL_set_ex_data(ssl, SSLCom::extdata_index(), value) != 1) {
            ++stats.errors.verifier_install_callback_state_failed;
            return false;
        }
        SSL_set_verify(ssl, SSL_VERIFY_PEER, verify_chain);

        // OpenSSL 3.5's SSL_new_from_listener() exposes its inner TLS object
        // to verification callbacks, unlike SSL_new(). Bind the borrowed
        // SSLCom state when TLS first reports a message, before chain checks.
        // The outer QUIC SSL remains the sole owner of this verifier.
        if (SSL_get0_listener(ssl)) {
            SSL_set_msg_callback_arg(ssl, value);
            SSL_set_msg_callback(ssl, bind_callback_state);
        }

        if (policy.ocsp_stapling || policy.ocsp_mode > 0) {
            if (SSL_set_tlsext_status_type(ssl, TLSEXT_STATUSTYPE_ocsp) != 1) {
                ++stats.errors.verifier_install_stapling_failed;
                return false;
            }
        }
        if (policy.ct_enable) {
            if (SSL_enable_ct(ssl, SSL_CT_VALIDATION_STRICT) != 1
                || SSL_set_ct_validation_callback(ssl, SSLCom::ct_verify_callback, value) != 1) {
                ++stats.errors.verifier_install_ct_failed;
                return false;
            }
        }
        return true;
    }

    // Advance admission without blocking the event loop. Chain/CT checks have
    // already run during TLS; revocation is submitted once and polled thereafter.
    // Returns 0 while pending, 1 on acceptance, or -1 on any failure.
    int progress(SSL* ssl) {
        if (!ssl) {
            ++stats.errors.verifier_progress_missing_ssl;
            return finish(-1);
        }
        if (started_) {
            return verdict();
        }
        if (!SSL_is_init_finished(ssl)) {
            return 0;
        }

        started_ = true;
        logging::verify().deb("verifier=%p B handshake complete verify-result=%ld",
                              static_cast<void*>(this), SSL_get_verify_result(ssl));
        if (SSL_get0_listener(ssl)) {
            // The handshake has bound its TLS callback state. Do not retain
            // a per-frame observer in the application's steady-state path.
            SSL_set_msg_callback(ssl, nullptr);
            SSL_set_msg_callback_arg(ssl, nullptr);
        }
        if (callback_binding_failed_) {
            ++stats.errors.verifier_progress_callback_binding_failed;
            return finish(-1);
        }
        exception_ = SSL_get_verify_result(ssl) != X509_V_OK;
        if (!is_verify_status_opt_allowed()) {
            ++stats.errors.verifier_progress_policy_rejected;
            return finish(-1);
        }
        if (!opt.ocsp.stapling_enabled && opt.ocsp.mode == 0) {
            return finish(1);
        }

        auto snapshot = make_revocation_snapshot(ssl);
        if (!snapshot || !enqueue_revocation(std::move(snapshot))) {
            ++stats.errors.verifier_progress_revocation_setup_failed;
            return finish(-1);
        }
        return 0;
    }

private:
    // Preserve TLS policy semantics and expose its per-chain-step decision.
    static int verify_chain(int trusted, X509_STORE_CTX* context) {
        int const accepted = SSLCom::ssl_client_vrfy_callback(trusted, context);
        try {
            if (context) {
                logging::verify().deb("chain=%p depth=%d error=%d trusted=%d accepted=%d",
                                      static_cast<void*>(context), X509_STORE_CTX_get_error_depth(context),
                                      X509_STORE_CTX_get_error(context), trusted, accepted);
            }
        } catch (...) {
            ++stats.errors.logging_verify_exception;
        }
        return accepted;
    }

    // Attach only the non-owning SSLCom slot on the inner TLS object. Its
    // lifetime is nested inside owner_; duplicating our owning slot would
    // double-delete the verifier. Failure keeps admission closed.
    static void bind_callback_state(int, int, int, const void*, std::size_t,
                                    SSL* callback_ssl, void* argument) {
        auto* verifier = static_cast<certificate_verifier*>(argument);
        if (!verifier || !callback_ssl) {
            ++stats.errors.verifier_callback_missing_context;
            if (verifier) verifier->callback_binding_failed_ = true;
            return;
        }
        if (callback_ssl != verifier->owner_
            && SSL_set_ex_data(callback_ssl, SSLCom::extdata_index(), verifier) != 1)
            verifier->callback_binding_failed_ = true;
    }

    SSL* owner_ = nullptr;
    bool callback_binding_failed_ = false;

    // Share immutable X509 material with a snapshot using a separate reference.
    // A missing issuer is preserved as missing for SSLCom to evaluate later.
    static bool retain_certificate(X509* source, X509*& target) {
        if (!source) {
            return true;
        }
        if (X509_up_ref(source) != 1) {
            ++stats.errors.verifier_certificate_ref_failed;
            return false;
        }
        target = source;
        return true;
    }

    // Copy the peer's staple into the snapshot SSL. Absence is not an error here:
    // the shared revocation policy decides whether a missing response is allowed.
    static bool copy_staple(SSL* source, SSL* target) {
        const unsigned char* staple = nullptr;
        auto const size = SSL_get_tlsext_status_ocsp_resp(source, &staple);
        if (size <= 0) {
            return true;
        }

        auto* copy = static_cast<unsigned char*>(OPENSSL_memdup(staple, size));
        if (!copy) {
            ++stats.errors.verifier_staple_allocation_failed;
            return false;
        }
        if (SSL_set_tlsext_status_ocsp_resp(target, copy, size) != 1) {
            OPENSSL_free(copy);
            ++stats.errors.verifier_staple_install_failed;
            return false;
        }
        // SSL owns the response buffer after successful installation.
        return true;
    }

    // Retain everything the worker needs while still on the event-loop thread.
    // The dummy SSL holds the staple for SSLCom's existing callback API; it has
    // no socket and never connects. Null means snapshot creation failed.
    std::unique_ptr<certificate_verifier> make_revocation_snapshot(SSL* ssl) {
        auto snapshot = std::make_unique<certificate_verifier>(policy_);
        snapshot->verify_reset(static_cast<verify_status_t>(verify_get()));
        snapshot->sslcom_ssl = SSL_new(factory()->default_tls_client_cx());
        if (!snapshot->sslcom_ssl) {
            ++stats.errors.verifier_snapshot_ssl_failed;
            return nullptr;
        }
        if (SSL_set_ex_data(snapshot->sslcom_ssl, SSLCom::extdata_index(), snapshot.get()) != 1) {
            ++stats.errors.verifier_snapshot_binding_failed;
            return nullptr;
        }

        if (!retain_certificate(sslcom_target_cert, snapshot->sslcom_target_cert)
            || !retain_certificate(sslcom_target_issuer, snapshot->sslcom_target_issuer)
            || !retain_certificate(sslcom_target_issuer_issuer, snapshot->sslcom_target_issuer_issuer)) {
            ++stats.errors.verifier_snapshot_certificate_ref_failed;
            return nullptr;
        }
        if (auto* chain = SSL_get0_verified_chain(ssl)) {
            snapshot->chain_.value = X509_chain_up_ref(chain);
            if (!snapshot->chain_.value) {
                ++stats.errors.verifier_snapshot_chain_failed;
                return nullptr;
            }
        }
        if (!copy_staple(ssl, snapshot->sslcom_ssl)) {
            ++stats.errors.verifier_snapshot_staple_failed;
            return nullptr;
        }
        return snapshot;
    }

    // The task owns certificate material, but only weakly references its result.
    // Session teardown can therefore discard admission without waiting for I/O.
    struct revocation_task final : sx::tp::PoolTask {
        std::unique_ptr<certificate_verifier> snapshot;
        std::weak_ptr<std::atomic_int> result;

        // Take the prepared snapshot and the pending-work slot reserved by enqueue.
        revocation_task(std::unique_ptr<certificate_verifier> value,
                        std::shared_ptr<std::atomic_int> const& output)
            : snapshot(std::move(value)), result(output) {}

        // Release the slot on completion, cancellation, or queue rejection alike.
        ~revocation_task() override { --pending_; }

        // Run shared TLS revocation checks on the snapshot only. Publish failure
        // on exceptions; skip work if the session disappeared before execution.
        void execute(std::atomic_bool const& stop) override {
            if (stop || result.expired()) {
                return;
            }

            logging::ocsp().deb("snapshot=%p revocation checks started", static_cast<void*>(snapshot.get()));
            int verdict = -1;
            try {
                bool const accepted = SSLCom::status_resp_callback(snapshot->sslcom_ssl, nullptr) == 1
                    && snapshot->is_verify_status_opt_allowed();
                verdict = accepted ? 1 : -1;
            } catch (...) {
                ++stats.errors.certificate_verifier_execute_exception;
                logging::ocsp().err("snapshot=%p revocation checks raised an exception",
                                    static_cast<void*>(snapshot.get()));
                // A worker failure must never turn into certificate acceptance.
                verdict = -1;
            }
            if (verdict > 0) logging::ocsp().dia("snapshot=%p revocation accepted", static_cast<void*>(snapshot.get()));
            else logging::ocsp().war("snapshot=%p revocation rejected", static_cast<void*>(snapshot.get()));
            if (auto output = result.lock()) {
                output->store(verdict, std::memory_order_release);
            }
        }

        // Identify this work in pool diagnostics without retaining session data.
        std::string info_short() const override { return "QUIC certificate revocation"; }

        // The short description contains all diagnostic context owned by the task.
        std::string info_long() const override { return info_short(); }
    };

    // Bound retained certificate material even if revocation responders stall.
    // True means the existing pool accepted ownership; false rejects admission.
    bool enqueue_revocation(std::unique_ptr<certificate_verifier> snapshot) {
        socle::raw::unique<bool> reserved {false, [](bool& held) { if (held) --pending_; }};
        if (pending_.fetch_add(1) >= max_pending_revocations) {
            --pending_;
            ++stats.errors.verifier_revocation_capacity_exhausted;
            logging::ocsp().war("revocation capacity exhausted: limit=%u", max_pending_revocations);
            return false;
        }
        // Until a task exists, this guard owns the reserved pending slot.
        // Allocation or queue exceptions must not permanently consume capacity.
        reserved.value = true;
        try {
            auto task = std::make_unique<revocation_task>(std::move(snapshot), result_);
            reserved.release(); // The task destructor now releases the slot.
            if (sx::tp::ThreadPool::instance::get().enqueue(std::move(task)) > 0) return true;
            ++stats.errors.verifier_revocation_queue_rejected;
            return false;
        } catch (...) {
            ++stats.errors.verifier_revocation_enqueue_exception;
            return false;
        }
    }

    // Allocate the SSL-owned attachment slot once, including its destruction hook.
    static int index() {
        static int const value = SSL_get_ex_new_index(0, nullptr, nullptr, nullptr,
            [](void*, void* pointer, CRYPTO_EX_DATA*, int, long, void*) {
                delete static_cast<certificate_verifier*>(pointer);
            });
        return value;
    }

    // Store an immediate event-loop decision in the same result used by workers.
    int finish(int verdict) {
        if (verdict < 0) logging::verify().war("verifier=%p certificate policy rejected", static_cast<void*>(this));
        else logging::verify().dia("verifier=%p certificate accepted policy-exception=%d",
                                   static_cast<void*>(this), exception_);
        result_->store(verdict);
        return verdict;
    }

    proxymaker::QuicTlsPolicy policy_;
    socle::raw::var<STACK_OF(X509)*> chain_ {nullptr,
        [](auto*& value) { sk_X509_pop_free(value, X509_free); }};
    bool started_ = false;
    bool exception_ = false;
    std::shared_ptr<std::atomic_int> result_ = std::make_shared<std::atomic_int>(0);

    static constexpr unsigned max_pending_revocations = 64;
    static inline std::atomic_uint pending_ {0};
};

} // namespace sx::quic
