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


#ifndef NODE_HPP
#define NODE_HPP

#include <unordered_map>
#include <string>
#include <memory>

#include <deque>

#include <ext/json/json.hpp>

namespace sx {

    struct Node_Data {
        virtual std::string to_string() const = 0;
        virtual nlohmann::json to_json() const = 0;
        virtual bool empty() const { return false; };
        virtual ~Node_Data() = default;
    };

    template<typename K>
    struct Node {
        std::string label = ".";
        std::shared_ptr<Node_Data> data;
        std::unordered_map<K,std::weak_ptr<Node>> elements;
        std::deque<std::pair<K,std::weak_ptr<Node>>> elements_queue;

        static inline size_t max_elements = 1000;
        static inline size_t cleanup_divisor = 10;  // max_elements/cleanup_divisor = amount of elements triggering cleanup
                                                    // 10 is arbitrary number made up by wild guess - maybe other is better
        static inline std::deque<std::shared_ptr<Node>> queue {};

        explicit Node() = default;
        explicit Node(std::shared_ptr<Node_Data> const& d) : data(d) {};

        Node(Node const&) = delete;
        Node& operator=(Node&) = delete;
        virtual ~Node() = default;

        auto& operator[](const char* k) {
            return elements[k];
        }

        template < typename Y, typename ... Args >
        std::shared_ptr<Node<K>> at(std::string const& key, Args ... args) {
            if(auto it = elements.find(key); it != elements.end()) {
                if(auto to_ret = it->second.lock(); to_ret)
                    return to_ret;

                elements.erase(it);
            }

            auto y = std::make_shared<Y>(args...);
            return replace(key, y);
        }

        void apply_quota() {
            if(max_elements > 0) {
                if(queue.size() > max_elements) {
                    queue.pop_front();
                }

                // clean-up own elements if there is too many entries
                // Too many means relative to maximum entries.
                // 10
                if(elements_queue.size() > max_elements/cleanup_divisor)
                    while(true) {
                        if(auto const& [ key, last ] = elements_queue.front(); last.use_count() == 0) {
                            elements.erase(key);
                            elements_queue.pop_front();
                            continue;
                        }
                        break;
                    }
            }
        }

        template<typename Y>
        std::shared_ptr<Node<K>> replace(std::string const& key, std::shared_ptr<Y> n) {
            auto x = std::dynamic_pointer_cast<Node_Data>(n);
            if(x) {

                apply_quota();

                auto nel = std::make_shared<Node<K>>(x);
                queue.push_back(nel);
                elements[key] = nel;
                elements_queue.emplace_back(key, nel);

                return nel;
            }

            return nullptr;
        }

        std::shared_ptr<Node<K>> operator[](std::string_view str) {
            return elements[str];
        }

        virtual nlohmann::json to_json() const  {
            nlohmann::json ret;

            if(elements.empty() and data and not data->empty()) return data->to_json();

            if(data and not data->empty()) {
                    ret[label] = data->to_json();
            }
            for(auto const& [ key, elem ] : elements) {

                auto entry = elem.lock();
                if(entry)
                    ret[key] = entry->to_json();
            }
            return ret;
        }

        virtual std::string to_string() const {
            std::stringstream ret;
            ret << "{ ";

            if(data) {
                ret << "{ " << data->to_string() << " } ";
            }

            ret << ": [";
            for(auto const& [ key,elem ] : elements) {

                auto entry = elem.lock();
                if(entry)
                    ret << "\"" << key << "\": {" << entry->to_string() << "} ";
            }
            ret << "]";

            return ret.str();
        }
    };

}

#endif // NODE_HPP