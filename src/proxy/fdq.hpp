/*
    Socle - Socket Library Ecosystem
    Copyright (c) 2014, Ales Stibal <astib@mag0.net>, All rights reserved.

    This library  is free  software;  you can redistribute  it and/or
    modify  it  under   the  terms of the  GNU Lesser  General Public
    License  as published by  the   Free Software Foundation;  either
    version 3.0 of the License, or (at your option) any later version.
    This library is  distributed  in the hope that  it will be useful,
    but WITHOUT ANY WARRANTY;  without  even  the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

    See the GNU Lesser General Public License for more details.

    You  should have received a copy of the GNU Lesser General Public
    License along with this library.
*/

#include <tuple>

#include <log/logan.hpp>
#include <mpstd.hpp>

class FdQueue {

public:
    FdQueue();
    virtual ~FdQueue();

    enum  class sq_type_t { SQ_PIPE = 0, SQ_SOCKETPAIR = 1 } sq_type_;
    sq_type_t sq_type() const { return sq_type_; }
    const char* sq_type_str() const;


    // pipe created to be monitored by Workers with poll. If pipe is filled with *some* data
    // there is something in the queue to pick-up.

    int push(int s);
    int pop();
    template <typename UnaryPredicate>
    std::optional<int> pop_if(UnaryPredicate);

    inline std::pair<int,int> hint_pair() const { return std::make_pair(hint_pair_[0], hint_pair_[1]); }
    std::mutex& get_lock() const { return sq_lock_; }
protected:
    mutable std::mutex sq_lock_;
    mp::deque<int> sq_;
    int hint_pair_[2] = {-1, -1};

    logan_lite log;

    friend struct FdQueueHandler;
};


template <typename UnaryPredicate>
std::optional<int> FdQueue::pop_if(UnaryPredicate check_true) {

    auto l_ = std::scoped_lock(sq_lock_);

    if(sq_.empty())
        return {};

    uint32_t val = sq_.back();
    if(check_true(val)) {
        sq_.pop_back();
        return val;
    }

    return {};
}


// proxy and wrapper class for FdQueue
class FdQueueError : public std::runtime_error {
public:
    explicit FdQueueError(const char* what) : std::runtime_error(what) {};
};

struct FdQueueHandler {
    explicit FdQueueHandler(std::shared_ptr<FdQueue> fdq) : fdqueue(std::move(fdq)) {}

    [[nodiscard]] int pop() const {
        if(fdqueue)
            return fdqueue->pop();

        throw FdQueueError("handler: no fdqueue");
    }

    int push(int s) const {
        if(fdqueue)
            return fdqueue->push(s);

        throw FdQueueError("handler: no fdqueue");
    }

    [[nodiscard]] FdQueue::sq_type_t sq_type() const {
        if(fdqueue)
            return fdqueue->sq_type();

        throw FdQueueError("handler: no fdqueue");
    }

    [[nodiscard]] const char* sq_type_str() const {
        if(fdqueue)
            return fdqueue->sq_type_str();

        throw FdQueueError("handler: no fdqueue");
    }

    template <typename UnaryPredicate>
    [[nodiscard]] std::optional<int> pop_if(UnaryPredicate check_true) {
        if(fdqueue)
            return fdqueue->pop_if(check_true);

        throw FdQueueError("handler: no fdqueue");
    }

    [[nodiscard]] std::pair<int,int> hint_pair() const {
        if(fdqueue)
            return fdqueue->hint_pair();

        throw FdQueueError("handler: no fdqueue");
    }

private:
    std::shared_ptr<FdQueue> fdqueue;
};