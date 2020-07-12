#include <unistd.h>
#include <sys/fcntl.h>

#include <proxy/fdq.hpp>

#define USE_SOCKETPAIR


FdQueue::FdQueue() : log("acceptor.fdqueue") {
#ifdef USE_SOCKETPAIR
    if(0 == ::socketpair(AF_UNIX, SOCK_STREAM|SOCK_NONBLOCK, 0, hint_pair_)) {
        _inf("acceptor: using socketpair");
        sq_type_ = sq_type_t::SQ_SOCKETPAIR;
    }
    else if( 0 == pipe2(hint_pair_, O_DIRECT | O_NONBLOCK)) {
        _inf("acceptor: using pipe2");
        sq_type_ = sq_type_t::SQ_PIPE;
    }

#else
    if(version_check(get_kernel_version(),"3.4")) {
        _deb("Acceptor: kernel supports O_DIRECT");
        if ( 0 != pipe2(hint_pair_,O_DIRECT|O_NONBLOCK)) {
            _err("ThreadAcceptor::new_raw: hint pipe not created, error[%d], %s", errno, string_error().c_str());
        }
    } else {
        _war("Acceptor: kernel doesn't support O_DIRECT");
        if (0 != pipe2(hint_pair_,O_NONBLOCK)) {
            _err("ThreadAcceptor::new_raw: hint pipe not created, error[%d], %s", errno, string_error().c_str());
        }
    }
#endif
}

FdQueue::~FdQueue() {
    ::close(hint_pair_[0]);
    ::close(hint_pair_[1]);
}


const char* FdQueue::sq_type_str() const {
    switch (sq_type_) {
        case sq_type_t::SQ_PIPE:
            return "pipe";
        case sq_type_t::SQ_SOCKETPAIR:
            return "socketpair";
    }
    return "unknown";
}

int FdQueue::push(int s) {
    std::lock_guard<std::mutex> lck(sq_lock_);
    sq_.push_front(s);
    int wr = ::write(hint_pair_[1], "A", 1);
    if( wr <= 0) {
        _err("FdQueue::push: failed to write hint byte - error[%d]: %s", wr, string_error().c_str());
    }

    return sq_.size();
};

int FdQueue::pop() {

    int red = 0;
    char dummy_buffer[1];

    int returned_socket = 0;

    {
        std::lock_guard<std::mutex> lck(sq_lock_);

        if (sq_.empty()) {
            return 0;
        }

        returned_socket = sq_.back();
        sq_.pop_back();



        red = ::read(hint_pair_[0], dummy_buffer, 1);
    }

    if(red > 0) {
        _dia("FdQueue::pop: clearing sq__hint %c", dummy_buffer[0]);
    } else {
        _dia("FdQueue::pop_for_worker: hint not read, read returned %d", red);
    }
    return returned_socket;
}

