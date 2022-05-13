#ifndef KB_HPP
#define KB_HPP

#include <unordered_map>

#include <string>
#include <memory>
#include <mutex>

#include <ext/json/json.hpp>

namespace sx {

    struct Node_Data {
        virtual std::string to_string() const = 0;
        virtual nlohmann::json to_json() const = 0;
        virtual ~Node_Data() = default;
    };

    template<typename K>
    struct Node {
        std::string label = ".";
        std::shared_ptr<Node_Data> data;
        std::unordered_map<K,std::shared_ptr<Node>> elements;

        explicit Node() = default;
        explicit Node(std::shared_ptr<Node_Data> const& d) : data(d) {};

        Node(Node const&) = delete;
        Node& operator=(Node&) = delete;
        virtual ~Node() = default;

        auto& operator[](const char* k) {
            return elements[k];
        }

        template < typename Y, typename ... Args >
        std::shared_ptr<Node<K>> insert(std::string const& key, Args ... args) {
            auto y = std::make_shared<Y>(args...);
            return insert(key, y);
        }

        template<typename Y>
        std::shared_ptr<Node<K>> insert(std::string const& key, std::shared_ptr<Y> n) {
            auto x = std::dynamic_pointer_cast<Node_Data>(n);
            if(x) {
                auto nel = std::make_shared<Node<K>>(x);
                elements[key] = nel;

                return nel;
            }

            return nullptr;
        }

        std::shared_ptr<Node<K>> operator[](std::string_view str) {
            return elements[str];
        }

        virtual nlohmann::json to_json() const  {
            nlohmann::json ret;

            if(elements.empty()) return data->to_json();

            if(data) {
                ret[label] = data->to_json();
            }
            for(auto const& [ key,elem] : elements) {

                ret[key] = elem->to_json();
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
            for(auto const& [ key,elem] : elements) {

                ret << "\"" << key << "\": {" << elem->to_string() << "} ";
            }
            ret << "]";

            return ret.str();
        }
    };

}

#endif // KB_HPP