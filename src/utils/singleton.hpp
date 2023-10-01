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

#ifndef SINGLETON_HPP
#define SINGLETON_HPP

#include <iostream>
#include <memory>
#include <mutex>
#include <tuple>
#include <utility>


template <typename T, typename... Args>
class Singleton {
public:
    explicit Singleton(Args... args) : params(std::make_tuple(args...)) {}

    T& get() {
        return std::apply([](auto&&... args) -> T& {
            return Instance::get(std::forward<Args>(args)...);
        }, params);
    }

    void set_params(Args... args) {
        Instance::reset();
        params = std::make_tuple(args...);
    }

private:
    // Nested Singleton class with variadic constructor parameters
    class Instance {
    public:
        template <typename... InnerArgs>
        static T& get(InnerArgs&&... args) {
            auto _lc = std::lock_guard(mutex);
            if (!instance) {
                instance = std::make_unique<T>(std::forward<InnerArgs>(args)...);
            }
            return *instance;
        }

        static void reset() {
            auto _lc = std::lock_guard(mutex);
            instance.reset();
        }

        Instance(const Instance&) = delete;
        Instance& operator=(const Instance&) = delete;

    private:
        Instance() = default;
        ~Instance() = default;

        static inline std::unique_ptr<T> instance = nullptr;
        static inline std::mutex mutex;
    };

    std::tuple<Args...> params;
};

#endif