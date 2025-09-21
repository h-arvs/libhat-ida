#include "libhat_ida.hpp"

#include "results_chooser.hpp"

libhat_ida::libhat_ida() {
    auto start = inf_get_min_ea();
    auto end = inf_get_max_ea();
    auto size = end - start;

    bytes.resize(size);

    get_bytes(bytes.data(), size, start, GMB_READALL);
}

void libhat_ida::show_results_chooser(std::vector<hat::scan_result> &results, qstring &pattern) {
    auto chooser = new results_chooser{bytes.data(), results, pattern};
    chooser->choose();
}

bool libhat_ida::run(size_t arg) {
    qstring pattern;
    ushort checkboxesBitmask;
    auto action = ask_form(
        "Scan for a pattern\n"
        "<Pattern:q:-1:50>\n"
        "<String search:C>>\n",
        &pattern,
        &checkboxesBitmask);

    if (action) {
        if (!pattern.empty()) {

            std::string_view pattern_{pattern.c_str(), pattern.length()}; // construct string view without terminating 0

            hat::signature signature{};

            if (checkboxesBitmask & 1) { // String search
                for (auto byte : pattern_) {
                    signature.emplace_back(static_cast<std::byte>(byte));
                }
            }
            else {
                if (auto signature_ = hat::parse_signature(pattern_); signature_.has_value()) {
                    signature = signature_.value();
                }
                else {
                    msg("Failed to parse pattern!\n");
                    return false;
                }
            }

            show_wait_box("Scanning...");
            msg("Scanning for %s...\n", pattern.c_str());

            auto starttime = std::chrono::high_resolution_clock::now();
            auto results = hat::find_all_pattern(bytes.begin(), bytes.end(), signature);
            auto endtime = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endtime - starttime);

            msg("Finished scan in %lldms, found %i results!", duration, results.size());
            hide_wait_box();

            show_results_chooser(results, pattern);

            return true;
        }
        msg("Pattern field empty...");
        return false;
    }

    return false;
}

