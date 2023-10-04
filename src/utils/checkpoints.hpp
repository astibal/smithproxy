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

#pragma once

#ifndef CHECKPOINTS_HPP
#define CHECKPOINTS_HPP

#include <iostream>
#include <chrono>
#include <array>

template <typename T, std::size_t N>
class MS_checkpoint {
public:
    struct Custom_Data {
        long long delta;
        T data;
    };

private:
    std::chrono::time_point<std::chrono::steady_clock> start_time;
    bool is_first_update = true;
    std::array<Custom_Data, N> elapsed_times;
    std::size_t update_count = 0;

public:
    void click(T data) {
        auto now = std::chrono::steady_clock::now();

        if (is_first_update) {
            start_time = now;
            is_first_update = false;
            elapsed_times[0] = { 0, data };
            update_count++;
            return;  // elapsed time is 0 for the first update
        }

        if (update_count < N) {
            elapsed_times[update_count] = { std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time).count(), data };
            update_count++;
        }
        // further updates above N are ignored
    }

    const std::array<Custom_Data, N>& get_checkpoints() const {
        return elapsed_times;
    }
    std::size_t count() const {
        return update_count;
    }
};

#endif