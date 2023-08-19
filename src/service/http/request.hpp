#include <iostream>
#include <string>
#include <curl/curl.h>
#include <optional>

namespace sx::http {

    class Request {
    private:
        CURL *curl;
        struct curl_slist *headers;
        std::string responseData;

        static size_t _write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
            ((std::string *) userp)->append((char *) contents, size * nmemb);
            return size * nmemb;
        }

    public:
        enum IPVersion {
            DEFAULT,
            IPV4_ONLY,
            IPV6_ONLY
        };

        // this is not good idea, but good to have for testing
        void disable_tls_verify() {
            if(curl)
                curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        }

        Request(IPVersion
        ip_version = DEFAULT,
        const std::string &dns_servers = "",
        const std::string &ca_path = ""
        ) {
            curl_global_init(CURL_GLOBAL_DEFAULT);
            curl = curl_easy_init();

            if (!curl) {
                throw std::runtime_error("Failed to initialize CURL.");
            }

            headers = nullptr;
            headers = curl_slist_append(headers, "Content-Type: application/json");

            // Set up common options
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, _write_callback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseData);
            curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "");

            // IP version handling
            switch (ip_version) {
                case IPV4_ONLY:
                    curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
                    break;
                case IPV6_ONLY:
                    curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V6);
                    break;
                default:
                    break;
            }

            // Set DNS servers if provided
            if (!dns_servers.empty()) {
                curl_easy_setopt(curl, CURLOPT_DNS_SERVERS, dns_servers.c_str());
            }

            // Set CA path if provided
            if (!ca_path.empty()) {
                curl_easy_setopt(curl, CURLOPT_CAPATH, ca_path.c_str());
            }
        }

        ~Request() {
            if (headers) {
                curl_slist_free_all(headers);
            }

            if (curl) {
                curl_easy_cleanup(curl);
            }

            curl_global_cleanup();
        }

        using Reply = std::optional<std::pair<long, std::string>>;

        Reply emit(std::string const& url, std::string const& payload) {
            CURLcode res;

            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_POST, 1L);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload.c_str());

            responseData.clear();
            res = curl_easy_perform(curl);

            if (res != CURLE_OK) {
                return std::nullopt;
            }

            long responseCode;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &responseCode);

            return std::make_pair(responseCode, responseData);
        }
    };
}
