#include "libhat_ida.hpp"

#include "results_chooser.hpp"

#include <chrono>

static bool isCased(std::byte character) {
    return (static_cast<char>(character) >= 'a' && static_cast<char>(character) <= 'z') ||
           (static_cast<char>(character) >= 'A' && static_cast<char>(character) <= 'Z');
}

static std::optional<std::vector<hat::signature>> cased_string_to_signature_impl(const std::string_view& pattern, const bool caseSensitive) {
    auto signature = hat::string_to_signature(pattern);

    if (!signature.has_value()) {
        return std::nullopt;
    }

    if (caseSensitive ) {
        return std::vector<hat::signature>{signature.value()};
    }

    for (auto& signatureElement : signature.value() | std::views::drop(1)) { // Skip first element as it is not allowed to have a partial mask!
        if (!isCased(signatureElement.value())) continue;
        signatureElement = {signatureElement.value(), static_cast<std::byte>(0b11011111)};
    } // Apply case-insensitive mask on each element

    if (!isCased(signature.value().at(0).value())) {
        return std::vector<hat::signature>{signature.value()};
    } // We don't need to create a second signature to match a differently cased first element as it is not cased

    auto signatureCopy = signature.value(); // Copy to produce new signature with opposite case on first element
    auto& firstElement = signatureCopy.at(0);
    firstElement = { firstElement.value() ^ static_cast<std::byte>(0b00100000)}; // Flip case-insensitive bit

    return std::vector{signature.value(), signatureCopy};
}

static std::optional<std::vector<hat::signature>> parse_signature(const std::string_view pattern, const bool stringSearch, const bool caseSensitive) {
    // Explicit string search
    if (stringSearch) {
        return cased_string_to_signature_impl(pattern, caseSensitive);
    }

    // String search via quotes
    if (pattern.starts_with('"') && pattern.ends_with('"') && pattern.size() >= 2) {
        return cased_string_to_signature_impl(pattern.substr(1, pattern.size() - 2), caseSensitive);
    }

    auto signature = hat::parse_signature(pattern);
    if (!signature.has_value()) { return std::nullopt; }
    return std::vector<hat::signature>{signature.value()};
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
    const ssize_t selected = results.empty() ? chooser_base_t::NO_SELECTION : 0;
    auto chooser = new results_chooser{bytes.data(), std::move(results), pattern};
    // results_chooser is not created with CH_KEEP, so the object will be deleted when the widget is deleted
    chooser->choose(selected);
}

bool plugin::run(size_t arg) {
    qstring pattern;
    ushort checkboxesBitmask;
    auto action = ask_form(
        "Scan for a pattern\n"
        "<Pattern:q:-1:50>\n"
        "<String search:C>\n"
        "<Case sensitive:C>>\n",
        &pattern,
        &checkboxesBitmask);

    if (!action) {
        return false;
    }

    if (pattern.empty()) {
        msg("Pattern field empty...");
        return false;
    }

    auto signatures = parse_signature(
        {pattern.c_str(), pattern.length()},
        checkboxesBitmask & 1, checkboxesBitmask & 2);

    if (!signatures.has_value()) {
        msg("Failed to parse pattern!\n");
        return false;
    }

    show_wait_box("Scanning...");
    msg("Scanning for %s...\n", pattern.c_str());

    auto starttime = std::chrono::high_resolution_clock::now();
    std::vector<hat::scan_result> results {};

    for (auto& signature : signatures.value()) {
        auto toJoin = find_all_pattern(this->bytes, signature,hat::scan_alignment::X1, this->hints);
        results.insert(results.end(), toJoin.begin(), toJoin.end());
    }

    auto endtime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endtime - starttime);

    msg("Finished scan in %lldms, found %i results!", duration, results.size());
    hide_wait_box();

    this->show_results_chooser(std::move(results), pattern);

    return true;
}

}
