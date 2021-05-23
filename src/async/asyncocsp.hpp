//
// Created by astib on 18.12.19.
//

#ifndef ASYNCOCSP_HPP
#define ASYNCOCSP_HPP

#include <openssl/x509.h>

#include <async/asyncsocket.hpp>



#define ASYNC_OCSP_DEBUG

class Tracer {
public:

#ifdef ASYNC_OCSP_DEBUG
    std::vector<std::pair<time_t,std::string>> trace;

    void log(std::string const& s) {
        trace.emplace_back(std::make_pair(::time(nullptr), s));
    }
#else
    void log(std::string const& s) {}
#endif
};



namespace inet::ocsp {

    class AsyncOCSP : public AsyncSocket<int>, public socle::sobject {
    public:

        AsyncOCSP (X509 *cert, X509 *issuer, baseHostCX *cx, callback_t cb) :
                AsyncSocket(cx, std::move(cb)),
                socle::sobject(),
                query_(cert, issuer, oid()) {
            log_tracer_("c-tor");
        };

        bool ask_destroy () override {
            untap();
            return true;
        }

        #ifdef ASYNC_OCSP_DEBUG
        Tracer tracer;
        #endif

        std::string to_string (int verbosity = iINF) const override {
            std::stringstream ss;

            ss << "AsyncOcsp [" << socket() << "] socket state: " << query().io().state_str();
            ss << " OCSP state: " << state_str();

            #ifdef ASYNC_OCSP_DEBUG
            time_t now = time(nullptr);

            std::string prev_msg;
            int prev_counter = 0;
            for(auto const& e: tracer.trace) {

                if(prev_msg != e.second) {
                    ss << std::endl << "[" <<  string_format("0x%lx", oid()) << "] " << std::dec << e.first - now << "s - " << e.second;

                    if(prev_counter > 1) {
                        ss << ", repeated " << prev_counter  << " times";
                    }

                    prev_counter = 0;
                } else {
                    prev_counter++;
                }
                prev_msg = e.second;
            }
            #endif
            return ss.str();
        }

        void log_tracer_(const char* location) {
            std::stringstream ss;
            ss << location << ": state:" << query_.state_str() << " yield: " << query_.yield_str();
            tracer.log(ss.str());

        }

        task_state_t update () override {


            if (query_.run()) {

                // reflect state to monitor socket
                if (query_.state() < inet::ocsp::OcspQuery::ST_REQ_SENT) {
                    owner()->com()->set_write_monitor(socket());
                } else {
                    owner()->com()->set_monitor(socket());
                }

                log_tracer_("update");
                return task_state_t::RUNNING;
            }

            result_ = query_.yield();
            result_state_ = query_.state();

            log_tracer_("update");
            return task_state_t::FINISHED;
        }

        int &yield () override {
            log_tracer_("yield");
            return result_;
        }

        static const char* yield_str(int y) { return inet::ocsp::OcspQuery::yield_str(y); }

        virtual void tap () {
            log_tracer_("tap");
            AsyncSocket::tap(query_.io().socket());
            query_.io().com_ = owner()->com();
        }

        inet::ocsp::OcspQuery const& query() const { return query_; }
    private:
        inet::ocsp::OcspQuery query_;
        int result_ = -100;
        int result_state_ = -100;


    DECLARE_C_NAME("AsyncOCSP")
    };
}
#endif //ASYNCOCSP_HPP
