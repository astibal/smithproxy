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

QueueLogger::QueueLogger(): logger(), lockable() {
}

int QueueLogger::write_log(loglevel l, std::string& sss) {

    locked_guard<QueueLogger> ll(this);


    if(debug_queue) {
        logs_.push(log_entry(l, string_format("[logger=0x%x qsize=%d]", this, logs_.size()) + sss));
    } else {
        logs_.push(log_entry(l, sss));
    }


    // set warning condition
    if(warned  == 0 && logs_.size() >= max_len - max_len/10 ) {
        auto msg = string_format("logger queue filling up: %d/%d", logs_.size(), max_len);
        logger::write_log(ERR, msg);
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

int QueueLogger::write_disk(loglevel l, std::string& sss) {
    locked_guard<QueueLogger> ll(this);

    return logger::write_log(l,sss);
}


void QueueLogger::run_queue(std::shared_ptr<QueueLogger> log_src) {

    if(log_src == nullptr) {
        return;
    }
    
    while (!log_src->sig_terminate) {

        if(! log_src->logs_.empty()) {

            auto lock = locked_guard(log_src.get());

            log_entry e = log_src->logs_.front(); log_src->logs_.pop();

            //copy elements and unlock before write_log.
            loglevel l = e.first;
            std::string msg = e.second;


            if(log_src->debug_queue) {
                auto ss = string_format("logsrc=0x%x [%d]| ", log_src.get(), log_src->logs_.size());
                msg = ss + msg;
            }
            log_src->write_disk(l, msg);
            
        } else {
            usleep(1000); // wait 10ms if there is nothing to read
        }
    }
}

std::thread *create_log_writer () {
    std::thread * writer_thread = new std::thread([]() { 
        auto log_ptr = LogOutput::get();
        auto q_logger = std::dynamic_pointer_cast<QueueLogger>(log_ptr);
        
        if(q_logger) {
            QueueLogger::run_queue(q_logger);
        }
    } );
       
    return writer_thread;
}
