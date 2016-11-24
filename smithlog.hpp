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
    
*/

#ifndef __SMITHLOG_HPP__
#define __SMITHLOG_HPP__

#include <queue>
#include <mutex>

#include <string>
#include <utility>
#include <lockable.hpp>
#include <logger.hpp>

typedef std::pair<int,std::string> log_entry;

class QueueLogger : public logger, public lockable {
public:
    QueueLogger();
    virtual ~QueueLogger() {};
    virtual int write_log(unsigned int l, std::string& sss);
    virtual int write_disk(unsigned int l, std::string& sss);
    
    static void run_queue(QueueLogger* logger_src);
    
    unsigned int max_len = 1000;
    bool sig_terminate = false;
protected:

    std::queue<log_entry> logs_;
    std::thread*  log_writter;
};


std::thread* create_log_writer(logger* log_ptr);

#endif