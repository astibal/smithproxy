#!/usr/bin/env python

"""
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
    along with Smithproxy.  If not, see <http://www.gnu.org/licenses/>.  """


# curl -v "http://api.mywot.com/0.4/public_link_json2?hosts=root.cz/&callback=process&key=57a92fd16754f60359c4d7fb6dd8b5ea7a26039e"


import httplib
import json
import sys

class WotResult:
    def __init__(self,json_string):
        self.json_string = json_string
        self.result = None

    def process(self):
        try:
            self.result = None
            self.result = json.loads(self.json_string)
        except ValueError, e:
            print str(e)
            print ":"
            print self.json_string
            pass
        
        return self.result


    
    def site(self):
        k = None
        try:
            k = self.result.keys()[0]
        except IndexError:
            pass
        except KeyError:
            pass

        return k
    
    def get_component(self,comp):
        try:
            k = self.result.keys()[0]
            return self.result[k][comp]
                
        except IndexError:
            pass
        except KeyError:
            pass
        
        if comp == "categories":
            return {}
        
        return [0,0]

    def child_safety(self):
        return self.get_component("4")
    
    def child_safety_str(self):
        r = self.child_safety()
        
        
        rating = WotResult.rating_str(r[0])
        confidence = WotResult.confidence_str(r[1])
        
        return [rating,confidence]
    
    @staticmethod
    def rating_str(rating):
        if rating >= 80:
            return "excellent"

        elif rating >= 60:
            return "good"
        
        elif rating >= 40:
            return "unsatisfactory"
        
        elif rating >= 20:
            return "poor"
        
        elif rating >= 0:
            return "very poor"
        
        return "unknown"

    @staticmethod
    def confidence_str(rating):
        if rating >= 50:
            return "excellent"

        elif rating >= 25:
            return "good"
        
        elif rating >= 10:
            return "acceptable"
        
        elif rating >= 0:
            return "unacceptable"
        
        return "unknown"

    @staticmethod
    def category_to_list(str_cat):
        cat = int(str_cat)
        
        group = "unknown"
        category = "unknown"
        category_name = "unknown"
        
        if cat >= 500:
            group = "positive"
            if 501 == cat:
                category = "good site"

        elif cat >= 300:
            group = "neutral"
            if 304 == cat:
                category = "other"
            elif 303 == cat:
                category = "opinions, religion, politics"
            elif 302 == cat:
                category = "alternative or controvestial medicine"
            elif 301 == cat:
                category = "online tracking"
                
        elif cat >= 200:
            group = "questionable"
            if 207 == cat:
                cat = "ads/pop-ups"
            elif 206 == cat:
                category = "potentially unwanted programs"
            elif 205 == cat:
                category = "spam"
            elif 204 == cat:
                category = "hate, discrimination"
            elif 203 == cat:
                category = "suspicious"
            elif 202 == cat:
                category = "privacy risks"
            elif 201 == cat:
                category = "misleading claims or unethical"
                
        elif cat >= 100:
            group = "negative"
            if 105 == cat:
                category = "potentially illegal"
            elif 104 == cat:
                category = "scam"
            elif 103 == cat:
                category = "phishing"
            elif 102 == cat:
                category = "poor customer experience"
            elif 101 == cat:
                category = "malware or viruses"
            
        return [group,category]

    def categories(self):
        d = self.get_component("categories")
        return d
    
    def categories_str(self):
        d = self.categories()
        r = {}
        for k in d.keys():
            q = WotResult.category_to_list(k)
            r[q[0]+":"+q[1]] = WotResult.confidence_str(d[k])
                                             
        return r

    def trust(self):
        return self.get_component("0")
    
    def trust_str(self):
        r = self.trust()
        rating = WotResult.rating_str(r[0])
        confidence = WotResult.confidence_str(r[1])
        
        return [rating,confidence]

class Wot:
    servername_ = "api.mywot.com"
    api_ = "0.4"
    def __init__(self, key):
        self.key = key
        self.req_id = 0
        
    def rate(self,url):
        #get_str = "/"+self.api_+"/public_link_json2?hosts="+url+"/&callback="+str(self.req_id)+"&key="+self.key
        get_str = "/"+self.api_+"/public_link_json2?hosts="+url+"/"+"&key="+self.key
        
        req = httplib.HTTPConnection(self.servername_)
        req.request("GET",get_str)
        
        response = req.getresponse()
        data = response.read()
        
        return data
        

if __name__ == "__main__":

    if len(sys.argv) > 1:
        w = Wot("57a92fd16754f60359c4d7fb6dd8b5ea7a26039e")        
        w_r = WotResult(w.rate(sys.argv[1]))
        d = w_r.process()

        #print str(d)
        print ":"
        for chs in  [ w_r.child_safety(), w_r.child_safety_str() ]:
            print "Child safety: '" + str(chs[0]) + "', confidence: '" + str(chs[1]) + "'"

        print 
        print

        for t in  [ w_r.trust(), w_r.trust_str() ]:
            print "Trust: '" + str(t[0]) + "', confidence: '" + str(t[1]) + "'"
        
        print 
        print
        
        for c in [w_r.categories(), w_r.categories_str() ]:
            for k in c.keys():
                print "Category: '" + str(k) + "', confidence: '" + str(c[k]) + "'"
        
    else:
        print "Usage:\n%s <website>" % (sys.argv[0],)
        
        
        