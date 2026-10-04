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

#include <display.hpp>
#include <smithlog.hpp>
#include <unistd.h>

#include <optional>

using namespace socle;

QueueLogger::QueueLogger(): LogMux(), lockable() {
}

size_t QueueLogger::write_log(loglevel l, std::string& sss) {

    auto lc_ = std::scoped_lock(*this);


    if(debug_queue) {
        logs_.push(log_entry(l, string_format("[logger=%p qsize=%zu]",
                                             static_cast<void*>(this), logs_.size()) + sss));
    } else {
        logs_.push(log_entry(l, sss));
    }


    // set warning condition
    if(warned  == 0 && logs_.size() >= max_len - max_len/10 ) {
        auto msg = string_format("logger queue filling up: %zu/%u", logs_.size(), max_len);
        LogMux::write_log(log::level::ERR, msg);
        warned++;
    }


    // clear warning condition
    if(warned){
        if(logs_.size() < max_len/10) {
            warned = 0;
        }
        else
        if(warned > 50) {

            // warn each 50 messages
            warned = 0;
        }
    }

    if(logs_.size() >= max_len) {
        logs_.pop();
    }

    // process on my mark!

    return 0;
}

size_t QueueLogger::write_disk(loglevel l, std::string& sss) {
    auto lc_ = std::scoped_lock(*this);

    return LogMux::write_log(l,sss);
}


void QueueLogger::run_queue(std::shared_ptr<QueueLogger> log_src) {

    if(log_src == nullptr) {
        return;
    }

    while (!log_src->sig_terminate.load(std::memory_order_acquire)) {
        std::optional<log_entry> entry;
        std::size_t queued = 0;
        {
            auto lock = std::scoped_lock(*log_src);
            if (!log_src->logs_.empty()) {
                entry = std::move(log_src->logs_.front());
                log_src->logs_.pop();
                queued = log_src->logs_.size();
            }
        }

        if (entry) {
            auto& [level, message] = *entry;
            if(log_src->debug_queue) {
                message = string_format("logsrc=%p [%zu]| ",
                                        static_cast<void*>(log_src.get()), queued) + message;
            }
            // write_disk takes the logger lock itself. Never call it while the
            // queue lock above is held: lockable uses a non-recursive mutex.
            log_src->write_disk(level, message);
        } else {
            usleep(1000); // wait 1ms if there is nothing to read
        }
    }
}

std::thread *create_log_writer () {
    auto* writer_thread = new std::thread([]() {
        auto log_ptr = Log::get();
        auto q_logger = std::dynamic_pointer_cast<QueueLogger>(log_ptr);
        
        if(q_logger) {
            QueueLogger::run_queue(q_logger);
        }
    } );
       
    return writer_thread;
}
