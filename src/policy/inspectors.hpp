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

//
/// \file  inspector.hpp
/// \brief Inspection modules called/updated usually MitmHostCX::inspect()
/// \sa MitmHostCX::inspect
//


#ifndef INSPECTORS_HPP_
#define INSPECTORS_HPP_

#include <basecom.hpp>
#include <tcpcom.hpp>
#include <inspect/dns.hpp>
#include <signature.hpp>
#include <apphostcx.hpp>
#include <regex>

#include <sobject.hpp>
#include <lockable.hpp>

//
/// \brief Abstract class intended to be parent for all inspector modules.
///        Serves as an interface.
///
//
class Inspector : public socle::sobject, public lockable {
public:
    explicit Inspector() = default;
    virtual ~Inspector() = default;
    //! called always when there are new data in the flow. \see class Flow.
    virtual void update(AppHostCX* cx) = 0;
    //! called before inserting to inspector list. 
    //! \return false if you don't want insert inspector to the list (and save some CPU cycles).
    virtual bool l4_prefilter(AppHostCX* cx) = 0;
    
    //! called before each update to indicate if update() should be called.
    virtual bool interested(AppHostCX*) const = 0;
    
    //! indicate if inspection is complete. Completed inspectors are not updated.
    inline bool completed() const   { return completed_; }
    //! indicate if inspection started already.
    inline bool in_progress() const { return in_progress_; }
    //! indicate if inspector was able to parse and process the payload.
    inline bool result() const { return result_; }

    typedef enum { OK=0, BLOCK, CACHED } inspect_verdict;
    inspect_verdict verdict_ = OK;
    inspect_verdict verdict() const { return verdict_; };
    void verdict(inspect_verdict v) { verdict_ = v; }
    virtual void apply_verdict(AppHostCX* cx) {};
    virtual std::shared_ptr<buffer> verdict_response() = 0;
private:
    logan_lite log {"com.app"};

protected:
    bool completed_ = false;
    void completed(bool b) { completed_ = b; }
    bool in_progress_ = false;
    void in_progress(bool b) { in_progress_ = b; }
    bool result_ = false;
    void result(bool b) { result_ = b; }
    
    //! internal stage counter. It could be used 
    int stage = 0;
    
    
    bool ask_destroy() override { return false; };
    std::string to_string(int verbosity) const override {
        return string_format("%s: in-progress: %d stage: %d completed: %d result: %d",
                             c_type(),in_progress(), stage, completed(),result());
    };
    
                                                
    static std::string remove_redundant_dots(std::string);
    static std::vector<std::string> split(std::string, unsigned char delimiter);
    static std::pair<std::string,std::string> split_fqdn_subdomain(std::string& fqdn);

public:
    TYPENAME_OVERRIDE("Inspector")
};

#endif //INSPECTORS_HPP_