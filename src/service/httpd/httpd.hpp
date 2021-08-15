#include <ext/lmhpp/include/lmhttpd.hpp>


std::thread* create_httpd_thread(unsigned short port);

class HttpService_Status_Ping : public lmh::DynamicController {
public:
    bool validPath(const char* path, const char* method) override {
        const std::string this_path = "/api/status/ping";
        const std::string this_meth = "GET";

        return (this_path == path and this_meth == method);
    }

    void createResponse(struct MHD_Connection * connection,
            const char * url, const char * method, const char * upload_data,
            size_t * upload_data_size, std::stringstream& response) override {

        response << "<html><head><title>smithproxy http service</title></head><body>OK</body></html>";
    }

};