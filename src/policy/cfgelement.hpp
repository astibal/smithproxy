//
// Created by astib on 15.12.20.
//

#ifndef SMITHPROXY_CFGELEMENT_HPP
#define SMITHPROXY_CFGELEMENT_HPP

#include <display.hpp>
#include <log/logger.hpp>

#include <sobject.hpp>
#include <policy/profiles.hpp>
#include <ranges.hpp>


class CfgElement {
    std::string name_;

    using dependency_vec_t = std::vector<std::weak_ptr<CfgElement>>;
    dependency_vec_t usage_references_;

public:
    virtual ~CfgElement() = default;

    std::string element_name() const { return name_; }
    std::string& element_name() { return name_; }

    dependency_vec_t& usage_vec() noexcept { return usage_references_; };
    dependency_vec_t const& usage_vec() const noexcept  { return usage_references_; };
    bool has_usage() const { return ! usage_references_.empty(); }
    void usage_add(std::weak_ptr<CfgElement> a);

    inline std::vector<std::string> usage_strvec() const;
};


inline std::vector<std::string> CfgElement::usage_strvec() const {
    std::vector<std::string> depnames;

    for(auto const& dep: usage_vec()) {
        auto dep_ptr = dep.lock();

        // if the dependency is still valid
        if(dep_ptr) {

            auto depstr = dep_ptr->element_name();

            if(dep_ptr->has_usage()) {
                depstr += ":";

                auto vec_of_deps = dep_ptr->usage_strvec();
                std::for_each(vec_of_deps.begin(), vec_of_deps.end(), [&](auto e) { depstr+= e; } );
            }

            depnames.push_back(depstr);
        }
    }

    return depnames;
}

inline void CfgElement::usage_add (std::weak_ptr<CfgElement> a) { usage_vec().emplace_back(a); }


template <typename val_type>
struct CfgSingle : public CfgElement {
    CfgSingle(val_type const& v) { value_ = v; }
    CfgSingle(std::string const& name, val_type const& v) { element_name() = name; value_ = v; }
    val_type value_;

//    explicit operator val_type() const { return value_; }
    val_type& value() { return value_; }
    val_type value() const { return value_; }
};



typedef CfgSingle<uint8_t> CfgUint8;
typedef CfgSingle<uint16_t> CfgUint16;
typedef CfgSingle<uint32_t> CfgUint32;
typedef CfgSingle<range> CfgRange;
typedef CfgSingle<std::string> CfgString;


#endif //SMITHPROXY_CFGELEMENT_HPP
