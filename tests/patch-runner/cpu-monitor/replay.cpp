// Test-only executable: feed exact measurements into the production core.
#include "core.hpp"
#include <iostream>

int main() {
    using namespace cpu_monitor;
    for (std::string line; std::getline(std::cin, line);) {
        try {
            const auto test = Json::parse(line);
            Config config;
            config.interval = test.value("interval", .05);
            config.window = test.value("window", .5);
            double now = 0, read_delay = 0;
            bool fail_write = false, fail_read = false;
            Counters values;
            Json samples = Json::array();
            Recorder recorder(config, [&] { return now; }, [] { return 0.0; },
                [&](int) {
                    if (fail_read) throw std::runtime_error("injected read failure");
                    now += read_delay;
                    return values;
                }, [&](const Json& sample) {
                    if (fail_write) throw std::runtime_error("injected write failure");
                    samples.push_back(sample);
                });
            std::string error;
            try {
                for (const auto& step : test.at("steps")) {
                    now = step.at("time");
                    read_delay = step.value("read_delay", 0.0);
                    fail_read = step.value("fail_read", false);
                    fail_write = step.value("fail_write", false);
                    values.clear();
                    for (const auto& [name, counter] : step.at("counters").items()) {
                        const int subject = name == "process" ? 0 : std::stoi(name.substr(7));
                        values.emplace(subject, Counter{counter.at(0), counter.at(1)});
                    }
                    if (step.contains("command")) recorder.command(step.at("command"));
                    else recorder.sample();
                }
            } catch (const std::exception& e) { error = e.what(); }
            std::cout << Json{{"report", recorder.report(error)}, {"samples", samples}}.dump() << '\n';
        } catch (const std::exception& e) {
            std::cerr << e.what() << '\n';
            return 2;
        }
    }
}
