#include "libhat_ida.hpp"

#include "results_chooser.hpp"

#include <chrono>

static auto parse_signature(const std::string_view pattern, const bool stringSearch) {
    // Explicit string search
    if (stringSearch) {
        return hat::string_to_signature(pattern);
    }

    // String search via quotes
    if (pattern.starts_with('"') && pattern.ends_with('"') && pattern.size() >= 2) {
        return hat::string_to_signature(pattern.substr(1, pattern.size() - 2));
    }

    return hat::parse_signature(pattern);
}

namespace libhat_ida {

plugin::plugin() {
    auto start = inf_get_min_ea();
    auto end = inf_get_max_ea();
    auto size = end - start;

    bytes.resize(size);

    get_bytes(bytes.data(), size, start, GMB_READALL);

    if (inf_get_procname() == "metapc") {
        hints |= hat::scan_hint::x86_64;
    }
}

void plugin::show_results_chooser(std::vector<hat::scan_result> results, const qstring& pattern) {
    auto chooser = new results_chooser{bytes.data(), std::move(results), pattern};
    // results_chooser is not created with CH_KEEP, so the object will be deleted when the widget is deleted
    chooser->choose(chooser_base_t::NO_SELECTION);
}

bool plugin::run(size_t arg) {
    qstring pattern;
    ushort checkboxesBitmask;
    auto action = ask_form(
        "Scan for a pattern\n"
        "<Pattern:q:-1:50>\n"
        "<String search:C>>\n",
        &pattern,
        &checkboxesBitmask);

    if (!action) {
        return false;
    }

    if (pattern.empty()) {
        msg("Pattern field empty...");
        return false;
    }

    auto signature = parse_signature(
        {pattern.c_str(), pattern.length()},
        checkboxesBitmask & 1);
    if (!signature.has_value()) {
        msg("Failed to parse pattern!\n");
        return false;
    }

    show_wait_box("Scanning...");
    msg("Scanning for %s...\n", pattern.c_str());

    auto starttime = std::chrono::high_resolution_clock::now();
    auto results = hat::find_all_pattern(this->bytes, signature.value(),hat::scan_alignment::X1, this->hints);
    auto endtime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endtime - starttime);

    msg("Finished scan in %lldms, found %i results!", duration, results.size());
    hide_wait_box();

    this->show_results_chooser(std::move(results), pattern);

    return true;
}

}
