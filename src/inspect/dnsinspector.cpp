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

#include <inspect/dnsinspector.hpp>


bool DNS_Inspector::dns_prefilter(AppHostCX *cx) {
    auto port = cx->com()->nonlocal_dst_port();
    return port == 53;
}

bool DNS_Inspector::interested(AppHostCX* cx) const {
    return DNS_Inspector::dns_prefilter(cx);
}

void DNS_Inspector::update(AppHostCX* cx) {

    // not entirely sure why we lock whole datagramcom, if we operate on flow and write to DNS cache
    //std::lock_guard<std::recursive_mutex> l(DatagramCom::lock);


    duplexFlow& f = cx->flow();
    _dia("DNS_Inspector::update[%s]: stage %d start (flow size %d, last flow entry data length %d)",cx->c_name(),stage, f.flow().size(),f.flow().back().second->size());

    /* INIT */

    if(!in_progress()) {
        baseCom* com = cx->com();
        auto* tcp_com = dynamic_cast<TCPCom*>(com);
        if(tcp_com)
            is_tcp = true;

        in_progress(true);
    }


    std::pair<char,buffer*> cur_pos = cx->flow().flow().back();

    std::shared_ptr<DNS_Packet> ptr;
    buffer *xbuf = cur_pos.second;
    buffer shallow_xbuf = xbuf->view(0, xbuf->size());

    int mem_pos = 0;
    unsigned int red = 0;

    if(is_tcp) {
        unsigned short data_size = ntohs(shallow_xbuf.get_at<unsigned short>(0));
        if(shallow_xbuf.size() < data_size) {
            _dia("DNS_Inspector::update[%s]: not enough DNS data in TCP stream: expected %d, but having %d. Waiting to more.", cx->c_name(), data_size, shallow_xbuf.size());
            return;
        }
        red += 2;
    }

    int mem_len = shallow_xbuf.size();
    switch(cur_pos.first)  {
        case 'r':
            stage = 0;
            for(unsigned int it = 0; red < shallow_xbuf.size() && it < 10; it++) {

                ptr = std::make_shared<DNS_Request>();

                buffer cur_buf = shallow_xbuf.view(red, shallow_xbuf.size() - red);
                int cur_red = ptr->load(&cur_buf);

                // because of non-standard return value from above load(), we need to adjust red bytes manually
                if(cur_red == 0) { cur_red = cur_buf.size(); }

                _dia("DNS_Inspector::update[%s]: red  %d, load returned %d", cx->c_name(), red, cur_red);
                _deb("DNS_Inspector::update[%s]: flow: %s", cx->c_name(), cx->flow().hr().c_str());

                // on success write to requests_
                if(cur_red >= 0) {
                    red += cur_red;

                    if(requests_[ptr->id()] != nullptr) {
                        _not("DNS_Inspector::update[%s]: detected re-sent request",cx->c_name());
                        requests_.erase(ptr->id());
                    }

                    _dia("DNS_Inspector::update[%s]: adding key 0x%x red=%d, buffer_size=%d, ptr=0x%x", cx->c_name(), ptr->id(), red, cur_buf.size(), ptr.get());
                    requests_[ptr->id()] = std::dynamic_pointer_cast<DNS_Request>(ptr);

                    _deb("DNS_Inspector::update[%s]: this 0x%x, requests size %d",cx->c_name(),this, requests_.size());

                    cx->idle_delay(30);

                } else {
                    _err("DNS BUG CAUGHT: iteration: %d, buffer:\n%s",it, hex_dump(cur_buf).c_str());

                    // keep for troubleshooting if needed
                    // _cons(string_format("DNS BUG: read buffer 0x%x size: %d, red = %d", shallow_xbuf.data(), shallow_xbuf.size(), red).c_str());
                    // _cons(string_format("DNS BUG: iteration: %d, buffer:\n%s",it, hex_dump(cur_buf).c_str()).c_str());

                    goto fail;
                }

            }
            _dia("DNS_Inspector::update[%s]: finishing reading from buffers: red=%d, buffer_size=%d",cx->c_name(),red, shallow_xbuf.size());


            if(opt_cached_responses && ( ptr->question_type_0() == A || ptr->question_type_0() == AAAA ) ) {
                std::scoped_lock<std::recursive_mutex> l_(DNS::get_dns_lock());

                auto cached_entry = DNS::get_dns_cache().get(ptr->question_str_0());
                if(cached_entry != nullptr) {
                    _dia("DNS answer for %s is already in the cache",cached_entry->question_str_0().c_str());


                    if(cached_entry->cached_packet != nullptr) {

                        // do TTL check
                        _dia("cached entry TTL check");

                        time_t now = time(nullptr);
                        bool ttl_check = true;

                        for(auto idx: cached_entry->answer_ttl_idx) {
                            uint32_t ttl = ntohl(cached_entry->cached_packet->get_at<uint32_t>(idx));
                            _deb("cached response ttl byte index %d value %d",idx,ttl);
                            if(now > static_cast<time_t>(ttl) + cached_entry->loaded_at) {
                                _deb("  %ds -- expired", now - (ttl + cached_entry->loaded_at));
                                ttl_check = false;
                            } else {
                                _deb("  %ds left to expiry", (ttl + cached_entry->loaded_at) - now);
                            }
                        }

                        if(ttl_check) {
                            verdict(CACHED);
                            // this  will copy packet to our cached response
                            if(! cached_response)
                                cached_response =  std::make_shared<buffer>();

                            cached_response->clear();
                            cached_response->append(cached_entry->cached_packet->data(),cached_entry->cached_packet->size());
                            cached_response_id = ptr->id();
                            cached_response_ttl_idx = cached_entry->answer_ttl_idx;
                            cached_response_decrement = now - cached_entry->loaded_at;

                            _dia("cached entry TTL check: OK");
                            _deb("cached response prepared: size=%d, setting overwrite id=%d",cached_response->size(),cached_response_id);
                        } else {
                            _dia("cached entry TTL check: failed");
                        }

                    }
                } else {
                    _dia("DNS answer for %s is not in cache - reverting to non-cached result",ptr->question_str_0().c_str());
                    verdict(OK);
                    if(cached_response) {
                        _dia("DNS answer for %s is not in cache - resetting previous response",ptr->question_str_0().c_str());
                        cached_response.reset();
                    }

                }
            }

            break;
        case 'w':
            stage = 1;
            for(unsigned int it = 0; red < shallow_xbuf.size() && it < 10; it++) {
                if(ptr) {
                    _err("DNS_Inspector::update[%s]: deleting response ptr from previous loop:%d", cx->c_name(), it-1);
                }
                ptr = std::make_shared<DNS_Response>();
                auto ptr_response = std::dynamic_pointer_cast<DNS_Response>(ptr);

                buffer cur_buf = shallow_xbuf.view(red, shallow_xbuf.size() - red);
                int cur_red = ptr->load(&cur_buf);


                if(cur_red >= 0) {
                    if(opt_cached_responses) {


                        if(ptr_response) {
                            delete ptr_response->cached_packet;

                            ptr_response->cached_packet = new buffer();
                            if (cur_red == 0) {
                                ptr_response->cached_packet->append(cur_buf.data(), cur_buf.size());
                            } else {
                                ptr_response->cached_packet->append(cur_buf.data(), cur_red);
                            }

                            _deb("caching response packet: size=%d", ptr_response->cached_packet->size());
                        }
                    }

                    mem_pos += cur_red;
                    red = cur_red;

                    _dia("DNS_Inspector::update[%s]: loaded new response (at %d size %d out of %d)", cx->c_name(), red, mem_pos, mem_len);
                    if (!validate_response(ptr_response)) {
                        // invalid, delete

                        cx->writebuf()->clear();
                        cx->error(true);
                        _war("DNS inspection: cannot find corresponding DNS request id 0x%x: dropping connection.", ptr->id());
                    }
                    else {
                        // DNS response is valid
                        responses_ ++;

                        _dia("DNS_Inspector::update[%s]: valid response",cx->c_name());

                        if(store(ptr_response)) {
                            stored_ = true;
                            // DNS response is interesting (A record present) - we stored it , ptr is VALID
                            _dia("DNS_Inspector::update[%s]: contains interesting info, stored", cx->c_name());

                        } else {
                            _dia("DNS_Inspector::update[%s]: no interesting info there, deleted", cx->c_name());
                        }

                        if(is_tcp)
                            cx->idle_delay(30);
                        else
                            cx->idle_delay(10);
                    }
                } else {
                    red = 0;
                }

                // on failure or last data exit loop
                if(red <= 0) break;
            }
            break;
    }

    fail:

    _dia("DNS_Inspector::update[%s]: stage %d end (flow size %d)", cx->c_name(), stage, f.flow().size());
}




bool DNS_Inspector::store(std::shared_ptr<DNS_Response> ptr) {
    bool is_a_record = true;

    std::string ip = ptr->answer_str();
    if(! ip.empty()) {
        _not("DNS inspection: %s is at%s",ptr->question_str_0().c_str(),ip.c_str()); //ip is already prepended with " "
    }
    else {
        _dia("DNS inspection: non-A response for %s",ptr->question_str_0().c_str());
        is_a_record = false;
    }
    _dia("DNS response: %s",ptr->str().c_str());


    if(is_a_record) {
        std::string question = ptr->question_str_0();

        {
            std::scoped_lock<std::recursive_mutex> l_(DNS::get_dns_lock());
            DNS::get_dns_cache().set(question, ptr);
        }
        _dia("DNS_Inspector::update: %s added to cache (%d elements of max %d)", ptr->question_str_0().c_str(),
             DNS::get_dns_cache().cache().size(), DNS::get_dns_cache().max_size());


        std::pair<std::string,std::string> dom_pair = split_fqdn_subdomain(question);
        _deb("topdomain = %s, subdomain = %s",dom_pair.first.c_str(), dom_pair.second.c_str());

        if( (! dom_pair.first.empty()) && (! dom_pair.second.empty()) ) {

            std::scoped_lock<std::recursive_mutex> ll_(DNS::get_domain_lock());

            auto subdom_cache = DNS::get_domain_cache().get(dom_pair.first);
            if(subdom_cache) {

                _dia("Top domain cache entry found for domain %s",dom_pair.first.c_str());
                if(subdom_cache->get(dom_pair.second) != nullptr) {
                    _dia("Sub domain cache entry found for subdomain %s",dom_pair.second.c_str());
                }


                if(*log.level() >= DEB) {
                    for( auto const& [subdom_str, subdom_exp ]: subdom_cache->cache()) {
                        _deb("Sub domain cache list: entry %s, expiring in %d", subdom_str.c_str(), subdom_exp->ptr()->expired_at() - ::time(nullptr));
                    }
                }

                subdom_cache->set(dom_pair.second,new expiring_int(1,28000));
            }

            else {
                _dia("Top domain cache entry NOT found for domain %s",dom_pair.first.c_str());
                auto new_subdom_cache = DNS::make_domain_entry(dom_pair.first);
                new_subdom_cache -> set(dom_pair.second, new expiring_int(1, DNS::sub_ttl));

                DNS::get_domain_cache().set(dom_pair.first, new_subdom_cache);
            }
        }
    }

    return is_a_record;
}

bool DNS_Inspector::validate_response(std::shared_ptr<DNS_Response> ptr) {

    unsigned int id = ptr->id();
    auto req = find_request(id);
    if(req) {
        _dia("DNS_Inspector::validate_response: request 0x%x found",id);
        return true;

    } else {
        _dia("DNS_Inspector::validate_response: request 0x%x not found",id);
        _err("validating DNS response for %s failed.",ptr->str().c_str());
        return false;
    }
}

std::string DNS_Inspector::to_string(int verbosity) const {
    std::string r = Inspector::to_string(verbosity)+"\n  ";

    r += string_format("tcp: %d requests: %d valid responses: %d stored: %d",is_tcp,requests_.size(),responses_,stored_);

    return r;
}

void Inspector::apply_verdict(AppHostCX* cx) {
}

void DNS_Inspector::apply_verdict(AppHostCX* cx) {
    _deb("DNS_Inspector::apply_verdict called");

    //TODO: dirty, make more generic
    if(cached_response != nullptr) {
        _deb("DNS_Inspector::apply_verdict: mangling response id=%d",cached_response_id);
        *((uint16_t*)cached_response->data()) = htons(cached_response_id);

        for(auto i: cached_response_ttl_idx) {
            uint32_t orig_ttl = ntohl(cached_response->get_at<uint32_t>(i));
            uint32_t new_ttl = orig_ttl - cached_response_decrement;
            _deb("DNS_Inspector::apply_verdict: mangling original ttl %d to %d at index %d",orig_ttl,new_ttl,i);

            uint8_t* ptr = cached_response->data();
            auto* ptr_ttl  = reinterpret_cast<uint32_t*>(&ptr[i]);
            *ptr_ttl = htonl(new_ttl);

        }

        if(! is_tcp) {
            _deb("udp encapsulation");
            int w = cx->io_write(cached_response->data(), cached_response->size(), MSG_NOSIGNAL);

            _dia("DNS_Inspector::apply_verdict: %d bytes written of cached response size %d", w, cached_response->size());
        } else {
            _deb("tcp encapsulation");
            // uint16_t* ptr = (uint16_t*)cached_response->data();
            uint16_t len = htons(cached_response->size());
            buffer b;
            b.append(&len,sizeof(uint16_t));
            b.append(cached_response->data(),cached_response->size());
            int w = cx->io_write(b.data(), b.size(), MSG_NOSIGNAL);

            _dia("DNS_Inspector::apply_verdict: %d bytes written of cached response size %d",w,b.size());
        }

    } else {
        // what to do now?
        _err("cannot send cached response, original reply not found.");
    }
}