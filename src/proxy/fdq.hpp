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

    int push(int);
    int pop();

    inline std::pair<int,int> hint_pair() const { return std::make_pair(hint_pair_[0], hint_pair_[1]); }
private:
    mutable std::mutex sq_lock_;
    mp::deque<int> sq_;
    int hint_pair_[2] = {-1, -1};

    logan_lite log;
};

// proxy and wrapper class for FdQueue
class FdQueueError : public std::runtime_error {
public:
    explicit FdQueueError(const char* what) : std::runtime_error(what) {};
};

struct FdQueueHandler {
    explicit FdQueueHandler(std::shared_ptr<FdQueue> fdq) : fdqueue(std::move(fdq)) {}

    std::shared_ptr<FdQueue> fdqueue;
    [[nodiscard]] int pop() const {
        if(fdqueue)
            return fdqueue->pop();

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

};