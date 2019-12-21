//
// Created by astib on 18.12.19.
//

#ifndef ASYNCOCSP_HPP
#define ASYNCOCSP_HPP

#include <openssl/x509.h>

#include <async/asyncsocket.hpp>


namespace inet {

    namespace ocsp {

        class AsyncOCSP : public AsyncSocket<int> {
        public:

            AsyncOCSP (X509 *cert, X509 *issuer, baseHostCX *cx, callback_t cb) :
                    AsyncSocket(cx, cb),
                    query_(cert, issuer) {
            };

            task_state_t update () override {

                if (query_.run()) {

                    // reflect state to monitor socket
                    if (query_.state() < inet::ocsp::OcspQuery::ST_REQ_SENT) {
                        owner()->com()->set_write_monitor(socket());
                    } else {
                        owner()->com()->set_monitor(socket());
                    }

                    return task_state_t::RUNNING;
                }

                result_ = query_.yield();
                result_state_ = query_.state();

                return task_state_t::FINISHED;
            }

            int &yield () override {
                return result_;
            }

            virtual void tap () {
                AsyncSocket::tap(query_.io().socket());
                query_.io().com_ = owner()->com();
            }

        private:
            inet::ocsp::OcspQuery query_;
            int result_ = -100;
            int result_state_ = -100;
        };
    }
}
#endif //ASYNCOCSP_HPP
