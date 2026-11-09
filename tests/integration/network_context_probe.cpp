#include <service/network_context.hpp>
#include <cstdlib>
#include <iostream>
#include <chrono>
#include <thread>

int main(int argc, char** argv) {
    if(argc != 3) return 2;
    const unsigned index = std::stoul(argv[1]);
    const std::string expected = argv[2];
    auto& context = sx::net::NetworkCtx::instance();
    if(!context.start()) return 3;
    auto snapshot = context.snapshot();
    if(!snapshot->roles_valid || !snapshot->all_interfaces_have_roles() ||
       snapshot->interface_role(index) != expected) return 4;
    if(context.route_lookup("192.0.2.2") != index) return 5;
    if(context.route_lookup("not-an-IP")) return 6;
    if(context.route_lookup("203.0.113.1")) return 7; // blackhole route
    sx::net::InterfaceRoleRule rule;
    rule.if_name = "proxy0"; rule.role = "Office";
    const auto before_roles = context.snapshot();
    context.set_role_rules({rule});
    const auto after_roles = context.snapshot();
    if(after_roles->route_generation != before_roles->route_generation ||
       after_roles->role_generation <= before_roles->role_generation) return 14;
    context.set_role_rules({rule});
    if(context.snapshot()->role_generation != after_roles->role_generation ||
       context.snapshot()->role_changed_at != after_roles->role_changed_at) return 15;
    if(after_roles->route_changed_at != before_roles->route_changed_at) return 17;
    if(after_roles->role_changed_at == std::chrono::system_clock::time_point{}) return 18;
    if(context.snapshot()->interface_role(index) != "Office") return 8;
    context.set_role_rules({});
    if(context.snapshot()->interface_role(index) != expected) return 9;
    if(expected == "Inside") {
        auto wait_role = [&](const std::string& role) {
            for(int attempt = 0; attempt < 200; ++attempt) {
                if(context.snapshot()->interface_role(index) == role) return true;
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }
            return false;
        };
        const auto old_route_generation = context.snapshot()->route_generation;
        if(std::system("ip route add default via 192.0.2.2") != 0) return 10;
        if(!wait_role("Outside")) return 11;
        if(context.snapshot()->route_generation <= old_route_generation) return 16;
        if(std::system("ip route del default") != 0) return 12;
        if(!wait_role("Inside")) return 13;
    }
    context.stop();
    std::cout << "NetworkCtx route, " << expected << ", custom role and reset PASS\n";
}
