#include <service/network_context.hpp>

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <linux/if_addr.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

namespace {

class NetlinkMessage {
public:
    template<class Payload>
    NetlinkMessage(std::uint16_t type, const Payload& payload, std::uint32_t sequence = 0) {
        data_.resize(NLMSG_SPACE(sizeof(Payload)), 0);
        auto* header = this->header();
        header->nlmsg_len = NLMSG_LENGTH(sizeof(Payload));
        header->nlmsg_type = type;
        header->nlmsg_seq = sequence;
        std::memcpy(NLMSG_DATA(header), &payload, sizeof(payload));
    }

    NetlinkMessage& attribute(std::uint16_t type, const void* value, std::size_t size) {
        const auto old_length = static_cast<std::size_t>(header()->nlmsg_len);
        const auto offset = static_cast<std::size_t>(NLMSG_ALIGN(old_length));
        const auto attribute_length = static_cast<std::size_t>(RTA_LENGTH(size));
        const auto message_length = offset + attribute_length;
        data_.resize(NLMSG_ALIGN(message_length), 0);

        auto* attribute = reinterpret_cast<rtattr*>(data_.data() + offset);
        attribute->rta_type = type;
        attribute->rta_len = static_cast<std::uint16_t>(attribute_length);
        if(size != 0) std::memcpy(RTA_DATA(attribute), value, size);
        header()->nlmsg_len = static_cast<std::uint32_t>(data_.size());
        return *this;
    }

    NetlinkMessage& string_attribute(std::uint16_t type, const std::string& value) {
        return attribute(type, value.c_str(), value.size() + 1);
    }

    nlmsghdr* header() { return reinterpret_cast<nlmsghdr*>(data_.data()); }
    const void* data() const { return data_.data(); }
    std::size_t size() const { return data_.size(); }

private:
    std::vector<std::uint8_t> data_;
};

NetlinkMessage link_message(std::uint16_t type, int index, const std::string& name,
                            unsigned int flags = 0) {
    ifinfomsg payload{};
    payload.ifi_index = index;
    payload.ifi_flags = flags;
    NetlinkMessage message(type, payload);
    if(!name.empty()) message.string_attribute(IFLA_IFNAME, name);
    return message;
}

NetlinkMessage ipv4_message(std::uint16_t type, unsigned int index,
                            const char* local, const char* peer = nullptr) {
    ifaddrmsg payload{};
    payload.ifa_family = AF_INET;
    payload.ifa_prefixlen = 24;
    payload.ifa_scope = RT_SCOPE_UNIVERSE;
    payload.ifa_index = index;
    NetlinkMessage message(type, payload);

    in_addr local_address{};
    EXPECT_EQ(::inet_pton(AF_INET, local, &local_address), 1);
    if(peer != nullptr) {
        in_addr peer_address{};
        EXPECT_EQ(::inet_pton(AF_INET, peer, &peer_address), 1);
        message.attribute(IFA_ADDRESS, &peer_address, sizeof(peer_address));
    }
    message.attribute(IFA_LOCAL, &local_address, sizeof(local_address));
    return message;
}

TEST(InterfaceTable, PublishesLinksAndLocalAddresses) {
    sx::net::detail::InterfaceTable table;

    auto link = link_message(RTM_NEWLINK, 7, "eth-test", IFF_UP | IFF_RUNNING);
    auto result = table.apply_netlink_datagram(link.data(), link.size());
    ASSERT_TRUE(result.ok) << result.error;
    EXPECT_TRUE(result.changed);

    auto address = ipv4_message(RTM_NEWADDR, 7, "192.0.2.8", "192.0.2.1");
    const std::uint32_t extended_flags = IFA_F_PERMANENT | IFA_F_NOPREFIXROUTE;
    address.attribute(IFA_FLAGS, &extended_flags, sizeof(extended_flags));
    address.string_attribute(IFA_LABEL, "ignored-label");
    result = table.apply_netlink_datagram(address.data(), address.size());
    ASSERT_TRUE(result.ok) << result.error;
    EXPECT_TRUE(result.changed);

    const auto snapshot = table.snapshot(3, true);
    ASSERT_TRUE(snapshot->valid);
    EXPECT_EQ(snapshot->generation, 3U);
    ASSERT_EQ(snapshot->interfaces.size(), 1U);
    EXPECT_EQ(snapshot->interfaces.front().index, 7U);
    EXPECT_EQ(snapshot->interfaces.front().name, "eth-test");
    ASSERT_EQ(snapshot->addresses.size(), 1U);
    EXPECT_EQ(snapshot->addresses.front().interface_index, 7U);
    EXPECT_EQ(snapshot->addresses.front().interface_name, "eth-test");
    EXPECT_EQ(snapshot->addresses.front().text(), "192.0.2.8");
    EXPECT_EQ(snapshot->addresses.front().flags, extended_flags);

    in_addr binary{};
    ASSERT_EQ(::inet_pton(AF_INET, "192.0.2.8", &binary), 1);
    EXPECT_TRUE(snapshot->contains_address(AF_INET, &binary, sizeof(binary)));
    EXPECT_EQ(snapshot->interface_name(7), std::optional<std::string>("eth-test"));
}

TEST(InterfaceTable, LinkRenameUpdatesAddressView) {
    sx::net::detail::InterfaceTable table;
    auto link = link_message(RTM_NEWLINK, 9, "old-name");
    ASSERT_TRUE(table.apply_netlink_datagram(link.data(), link.size()).ok);
    auto address = ipv4_message(RTM_NEWADDR, 9, "198.51.100.4");
    ASSERT_TRUE(table.apply_netlink_datagram(address.data(), address.size()).ok);

    auto rename = link_message(RTM_NEWLINK, 9, "new-name");
    const auto update = table.apply_netlink_datagram(rename.data(), rename.size());
    ASSERT_TRUE(update.ok) << update.error;
    EXPECT_TRUE(update.changed);

    const auto snapshot = table.snapshot(2, true);
    ASSERT_EQ(snapshot->addresses.size(), 1U);
    EXPECT_EQ(snapshot->addresses.front().interface_name, "new-name");
}

TEST(InterfaceTable, DeleteLinkAlsoDeletesItsAddresses) {
    sx::net::detail::InterfaceTable table;
    auto link = link_message(RTM_NEWLINK, 11, "gone0");
    ASSERT_TRUE(table.apply_netlink_datagram(link.data(), link.size()).ok);
    auto address = ipv4_message(RTM_NEWADDR, 11, "203.0.113.7");
    ASSERT_TRUE(table.apply_netlink_datagram(address.data(), address.size()).ok);

    auto deletion = link_message(RTM_DELLINK, 11, "");
    const auto update = table.apply_netlink_datagram(deletion.data(), deletion.size());
    ASSERT_TRUE(update.ok) << update.error;
    EXPECT_TRUE(update.changed);

    const auto snapshot = table.snapshot(4, true);
    EXPECT_TRUE(snapshot->interfaces.empty());
    EXPECT_TRUE(snapshot->addresses.empty());
}

TEST(InterfaceTable, RejectsMalformedBatchWithoutApplyingIt) {
    sx::net::detail::InterfaceTable table;
    auto original = link_message(RTM_NEWLINK, 3, "safe0");
    ASSERT_TRUE(table.apply_netlink_datagram(original.data(), original.size()).ok);

    auto malformed = link_message(RTM_NEWLINK, 4, "broken0");
    auto* attribute = reinterpret_cast<rtattr*>(
        reinterpret_cast<std::uint8_t*>(malformed.header()) +
        NLMSG_ALIGN(NLMSG_LENGTH(sizeof(ifinfomsg))));
    attribute->rta_len = std::numeric_limits<std::uint16_t>::max();

    const auto update = table.apply_netlink_datagram(malformed.data(), malformed.size());
    EXPECT_FALSE(update.ok);
    EXPECT_EQ(update.error_code, EBADMSG);

    const auto snapshot = table.snapshot(1, true);
    ASSERT_EQ(snapshot->interfaces.size(), 1U);
    EXPECT_EQ(snapshot->interfaces.front().name, "safe0");
}

TEST(InterfaceTable, ReportsInterruptedDump) {
    nlmsghdr done{};
    done.nlmsg_len = NLMSG_LENGTH(0);
    done.nlmsg_type = NLMSG_DONE;
    done.nlmsg_flags = NLM_F_DUMP_INTR;
    done.nlmsg_seq = 42;

    sx::net::detail::InterfaceTable table;
    const auto result = table.apply_netlink_datagram(&done, sizeof(done), 42);
    ASSERT_TRUE(result.ok) << result.error;
    EXPECT_TRUE(result.done);
    EXPECT_TRUE(result.dump_interrupted);
}

TEST(NetworkCtx, StartAttemptCanAlwaysBeStoppedCleanly) {
    auto& monitor = sx::net::NetworkCtx::instance();
    const bool synchronized = monitor.start();
    const auto snapshot = monitor.snapshot();

    ASSERT_NE(snapshot, nullptr);
    if(const char* required = std::getenv("SMITHPROXY_REQUIRE_NETLINK");
       required != nullptr && std::string(required) == "1") {
        ASSERT_TRUE(synchronized) << monitor.last_error();
        EXPECT_TRUE(snapshot->valid);
        EXPECT_FALSE(snapshot->interfaces.empty());
    }
    if(synchronized) {
        EXPECT_TRUE(snapshot->valid);
    } else {
        EXPECT_FALSE(snapshot->valid);
        EXPECT_FALSE(monitor.last_error().empty());
    }

    const auto running_stats = monitor.stats();
    EXPECT_TRUE(running_stats.running);
    EXPECT_GE(running_stats.synchronization_attempts, 1U);
    EXPECT_GE(running_stats.synchronization_attempts,
              running_stats.synchronization_successes);

    monitor.stop();
    EXPECT_FALSE(monitor.running());
    EXPECT_FALSE(monitor.stats().running);
}

} // namespace

TEST(NetworkRoles, EveryInterfaceHasExactlyOneAutomaticRole) {
    sx::net::InterfaceSnapshot snapshot;
    snapshot.interfaces = {{1, "lo", IFF_LOOPBACK}, {2, "lan", 0}, {3, "wan", 0}, {4, "unaddressed", 0}};
    EXPECT_FALSE(snapshot.all_interfaces_have_roles());
    snapshot.assign_automatic_roles({3});
    EXPECT_TRUE(snapshot.all_interfaces_have_roles());
    snapshot.valid = snapshot.roles_valid = true;
    EXPECT_EQ(snapshot.interface_role(1), "Local");
    EXPECT_EQ(snapshot.interface_role(2), "Inside");
    EXPECT_EQ(snapshot.interface_role(3), "Outside");
    EXPECT_EQ(snapshot.interface_role(4), "Inside");
    EXPECT_FALSE(snapshot.interface_role(0));
    snapshot.assign_automatic_roles({});
    EXPECT_EQ(snapshot.interface_role(3), "Inside");
    snapshot.roles_valid = false;
    EXPECT_FALSE(snapshot.interface_role(2));
}

#include <service/interface_roles.hpp>

TEST(NetworkRoles, OrderedRulesMatchInterfaceAddressesAndRoundTrip) {
    libconfig::Config config;
    config.readString(R"(settings = { interfaces = (
        { match = { if_name = "guest"; }; role = "Guest"; },
        { match = { if_address = "10.20.0.0/16"; }; role = "Office"; },
        { match = { if_address = "2001:db8::/32"; }; role = "V6"; }
    ); };)");
    auto rules = sx::net::parse_interface_roles(config.lookup("settings"));
    sx::net::InterfaceSnapshot snapshot;
    snapshot.interfaces = {{2,"guest",0}, {3,"office",0}, {4,"office2",0}, {5,"v6",0}, {6,"fallback",0}};
    for(unsigned index : {2,3,4,5}) {
        sx::net::InterfaceAddress address;
        address.interface_index = index;
        address.family = index == 5 ? AF_INET6 : AF_INET;
        address.address_size = index == 5 ? 16 : 4;
        ASSERT_EQ(inet_pton(address.family, index == 5 ? "2001:db8::5" : "10.20.30.1", address.address.data()), 1);
        snapshot.addresses.push_back(address);
    }
    snapshot.assign_automatic_roles({6});
    snapshot.assign_roles(rules);
    snapshot.valid = snapshot.roles_valid = true;
    EXPECT_EQ(snapshot.interface_role(2), "Guest");
    EXPECT_EQ(snapshot.interface_role(3), "Office");
    EXPECT_EQ(snapshot.interface_role(4), "Office");
    EXPECT_EQ(snapshot.interface_role(5), "V6");
    EXPECT_EQ(snapshot.interface_role(6), "Outside");
    EXPECT_TRUE(snapshot.all_interfaces_have_roles());
    libconfig::Config copy;
    auto& settings = copy.getRoot().add("settings", libconfig::Setting::TypeGroup);
    sx::net::save_interface_roles(settings, rules);
    const auto again = sx::net::parse_interface_roles(settings);
    ASSERT_EQ(again.size(), rules.size());
    for(std::size_t i=0; i<rules.size(); ++i) {
        EXPECT_EQ(again[i].role, rules[i].role);
        EXPECT_EQ(again[i].if_address, rules[i].if_address);
        EXPECT_EQ(again[i].if_name, rules[i].if_name);
    }
}

TEST(NetworkRoles, InvalidCandidateHasNoRuntimeSideEffects) {
    auto& context = sx::net::NetworkCtx::instance();
    const auto before = context.snapshot();
    for(const char* text : {
        "interfaces = ({match={network=\"10.0.0.0/8\";};role=\"Bad\";});",
        "interfaces = ({match={if_address=\"10.0.0.0/33\";};role=\"Bad\";});",
        "interfaces = ({match={};role=\"Bad\";});",
        "interfaces = ({match={if_name=\"x\";};role=\"\";});",
        "interfaces = {};"}) {
        libconfig::Config config;
        config.readString(text);
        EXPECT_THROW(sx::net::parse_interface_roles(config.getRoot()), std::invalid_argument);
        EXPECT_EQ(context.snapshot(), before);
    }
    libconfig::Config omitted;
    EXPECT_TRUE(sx::net::parse_interface_roles(omitted.getRoot()).empty());
}
