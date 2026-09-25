#include "smith_cli2_test.hpp"

#include <inspect/dns.hpp>
#include <inspect/dnsinspector.hpp>
#include <log/logger.hpp>
#include <policy/addrobj.hpp>
#include <service/cfgapi/cfgapi.hpp>
#include <service/http/async_request.hpp>
#include <utils/str.hpp>

#include <socle.hpp>

#include <openssl/rand.h>

#include <memory>
#include <mutex>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

namespace {

bool exec_mode(const libcli2::Context& context) { return context.mode == "0"; }

unsigned short random_id() {
    unsigned short result = 0;
    RAND_bytes(reinterpret_cast<unsigned char*>(&result), sizeof(result));
    return result;
}

std::shared_ptr<DNS_Response> send_dns_request(libcli2::Context& context, const std::string& hostname,
                                               DNS_Record_Type type, const AddressInfo& nameserver) {
    buffer request(1024);
    const int generated = DNSFactory::get().generate_dns_request(random_id(), request, hostname, type);
    context.print("DNS generated request:\n" + hex_dump(request) + ", " + std::to_string(generated) + "B");

    const int fd = ::socket(nameserver.family, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0 || ::connect(fd, reinterpret_cast<const sockaddr*>(nameserver.as_ss()), sizeof(sockaddr_storage)) != 0) {
        if (fd >= 0) ::close(fd);
        context.print("cannot connect socket");
        return {};
    }
    if (::send(fd, request.data(), request.size(), 0) < 0) {
        ::close(fd);
        context.print("cannot send DNS request");
        return {};
    }
    epoll poller;
    poller.init();
    poller.add(fd, EPOLLIN);
    if (poller.wait(4000) < 1) {
        ::close(fd);
        context.print("timeout, or an error occurred.");
        return {};
    }
    buffer reply(1500);
    const auto length = ::recv(fd, reply.data(), reply.capacity(), 0);
    ::close(fd);
    if (length <= 0) {
        context.print("recv() returned " + std::to_string(length));
        return {};
    }
    reply.size(length);
    auto response = std::make_shared<DNS_Response>();
    const auto parsed = response->load(&reply);
    context.print("received " + std::to_string(length) + " bytes\n" + hex_dump(reply));
    context.print("DNS response:\n" + response->str());
    return parsed == 0 ? response : std::shared_ptr<DNS_Response>{};
}

libcli2::Command& hostname_command(libcli2::Cli& cli, std::string_view path, std::string_view help) {
    return cli.command(path).reset_definition().help(std::string(help)).available_if(exec_mode)
        .argument({"hostname", "DNS hostname", true, false});
}

}  // namespace

void register_smithproxy_cli2_test(libcli2::Cli& cli) {
    hostname_command(cli, "test dns genrequest", "Generate a DNS request")
        .handler([](libcli2::Context& context, const libcli2::Invocation& invocation) {
            buffer request(1024);
            const int generated = DNSFactory::get().generate_dns_request(random_id(), request,
                                                                          invocation.arguments.front(), A);
            context.print("DNS generated request:\n" + hex_dump(request) + ", " + std::to_string(generated) + "B");
            return 0;
        });

    hostname_command(cli, "test dns sendrequest", "Send a DNS request to the configured resolver")
        .handler([](libcli2::Context& context, const libcli2::Invocation& invocation) {
            const auto response = send_dns_request(context, invocation.arguments.front(), A,
                                                    DNS_Setup::choose_dns_server(0));
            if (response && DNS_Inspector::store(response)) context.print("Entry successfully stored in cache.");
            return response ? 0 : -1;
        });

    cli.command("test dns refreshallfqdns")
        .reset_definition()
        .help("Refresh all configured FQDN address objects")
        .available_if(exec_mode)
        .handler([](libcli2::Context& context, const libcli2::Invocation&) {
            std::vector<std::string> names;
            {
                const auto lock = std::scoped_lock(CfgFactory::lock());
                for (const auto& [name, address] : CfgFactory::get()->db_address) {
                    if (const auto fqdn = std::dynamic_pointer_cast<FqdnAddress>(address)) names.push_back(fqdn->fqdn());
                }
            }
            const auto& nameserver = DNS_Setup::choose_dns_server(0);
            for (const auto& name : names) {
                for (const auto type : {A, AAAA}) {
                    const auto response = send_dns_request(context, name, type, nameserver);
                    if (response && DNS_Inspector::store(response)) context.print("Entry successfully stored in cache.");
                }
            }
            return 0;
        });

    cli.command("test webhook")
        .reset_definition()
        .help("Send a simple JSON message to a webhook URL")
        .available_if(exec_mode)
        .argument({"url", "Webhook URL", true, false})
        .handler([](libcli2::Context& context, const libcli2::Invocation& invocation) {
            const int fd = context.io_handle;
            sx::http::AsyncRequest::emit_url(invocation.arguments.front(), R"({"key": "value"})", [fd](auto reply) {
                if (Log::get()->target_profiles().find(static_cast<std::uint64_t>(fd)) == Log::get()->target_profiles().end()) return;
                const long code = reply ? reply->response.first : -1;
                const std::string message = reply ? reply->response.second : "request failed";
                const std::string output = "Response: " + std::to_string(code) + ":" + message + "\r\n";
                ::write(fd, output.data(), output.size());
            });
            return 0;
        });
}
