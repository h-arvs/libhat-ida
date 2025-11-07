#pragma once

#include <libhat/scanner.hpp>

#include <idp.hpp>

namespace libhat_ida {

class plugin final : public plugmod_t {
public:
    plugin();

    void show_results_chooser(std::vector<hat::scan_result>, const qstring&);

    bool idaapi run(size_t arg) override;

private:
    std::vector<std::byte> bytes;
    hat::scan_hint hints{};
};
}
