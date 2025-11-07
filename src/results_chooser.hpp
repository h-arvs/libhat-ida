#pragma once

#include <libhat/scanner.hpp>

#include <pro.h>
#include <kernwin.hpp>

namespace libhat_ida {

class results_chooser final : public chooser_t {
public:
    results_chooser(std::byte* base, std::vector<hat::scan_result> results, const qstring& title);

    [[nodiscard]] size_t idaapi get_count() const override;
    void idaapi get_row(qstrvec_t* out, int* out_icon, chooser_item_attrs_t* out_attrs, size_t n) const override;
    [[nodiscard]] ea_t idaapi get_ea(size_t n) const override;

private:
    qstring title_owned;
    std::byte* base;
    std::vector<hat::scan_result> results;
};

}
