/*
    Smithproxy- transparent proxy with SSL inspection capabilities.
    Copyright (c) 2014, Ales Stibal <astib@mag0.net>, All rights reserved.

    Smithproxy is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Smithproxy is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Smithproxy.  If not, see <http://www.gnu.org/licenses/>.

    Linking Smithproxy statically or dynamically with other modules is
    making a combined work based on Smithproxy. Thus, the terms and
    conditions of the GNU General Public License cover the whole combination.

    In addition, as a special exception, the copyright holders of Smithproxy
    give you permission to combine Smithproxy with free software programs
    or libraries that are released under the GNU LGPL and with code
    included in the standard release of OpenSSL under the OpenSSL's license
    (or modified versions of such code, with unchanged license).
    You may copy and distribute such a system following the terms
    of the GNU GPL for Smithproxy and the licenses of the other code
    concerned, provided that you include the source code of that other code
    when and as the GNU GPL requires distribution of source code.

    Note that people who make modified versions of Smithproxy are not
    obligated to grant this special exception for their modified versions;
    it is their choice whether to do so. The GNU General Public License
    gives permission to release a modified version without this exception;
    this exception also makes it possible to release a modified version
    which carries forward this exception.
*/

#ifndef ASYNCSOCKET_HPP
#define ASYNCSOCKET_HPP

#include <functional>
#include <hostcx.hpp>

template <class R>
class IAsyncTask {
public:
    using task_state_t = enum class state { INIT, RUNNING, FINISHED, TIMEOUT, ERROR };
    task_state_t state_ = task_state_t::INIT;

    inline void state(task_state_t n) { state_ = n; };
    inline task_state_t state() const { return state_; };

    virtual R& yield() = 0;
    virtual task_state_t update() = 0;
    bool finished() {
        return update() >= IAsyncTask::FINISHED;
    }

};

template <class R>
class AsyncSocket : public IAsyncTask<R>, public epoll_handler {
public:
    using task_state_t = typename IAsyncTask<R>::task_state_t;
    using callback_t = std::function<void(R&)>;

    explicit AsyncSocket(baseHostCX* owner, callback_t callback = nullptr) : owner_(owner), callback_(callback) {}
    ~AsyncSocket () override {
        untap();
    }

    void tap(int fd) {

        socket_.set(fd, this, owner_->com(), true);
        socket_.opening();
        owner_->com()->unset_monitor(owner_->socket());

        this->state(task_state_t::RUNNING);

        if(pause_owner_) {
            owner_->io_disabled(true);
        }
        if(pause_peer_) {
            if(owner_->peer())
                owner_->peer()->io_disabled(true);
        }
    }

    void untap() {
        socket_.closing();
        owner_->com()->set_write_monitor(owner_->socket()); // monitor all events on socket

        if(pause_owner_) {
            owner_->io_disabled(false);
        }
        if(pause_peer_) {
            if(owner_->peer()) {
                owner_->peer()->io_disabled(false);

                // this usually triggers proxies and it's harmless
                owner_->peer()->com()->set_write_monitor(owner_->peer()->socket());
            }
        }

        this->state(task_state_t::INIT);
    }
    virtual typename IAsyncTask<R>::state update() = 0;
    virtual R& yield() = 0;

    void handle_event (baseCom *com) override {

        if(com->in_idleset(socket_.socket_)) {
            this->state(task_state_t::TIMEOUT);
        }
            // add more termination expressions
        else {
            this->state(update());
        }


        if(IAsyncTask<R>::state() >= task_state_t::FINISHED) {
            if(callback_)
                callback_(yield());
            untap();
        }
    }

    void io_pausing(bool owner, bool peer = false) {
        pause_owner_ = owner;
        pause_peer_ = peer;
    }


    inline int socket() const { return socket_.socket_; }
    inline baseHostCX* owner() const { return owner_; }
private:
    baseHostCX* owner_;
    callback_t callback_;

    bool pause_owner_ = false;
    bool pause_peer_ = false;

    socket_state socket_;
};



#endif //ASYNCSOCKET_HPP
