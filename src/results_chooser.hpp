#pragma once


#include <libhat/scanner.hpp>

#include "def.hpp"
#include <pro.h>
#include <kernwin.hpp>

struct results_chooser : public chooser_t {
    qstring title_;
    std::byte* base;
    std::vector<hat::scan_result> results;

    results_chooser(std::byte*, std::vector<hat::scan_result>&, const qstring&);

    [[nodiscard]] size_t idaapi get_count() const override;
    void idaapi get_row(qstrvec_t* out, int *out_icon, chooser_item_attrs_t *out_attrs, size_t n) const override;
    cbret_t idaapi enter(size_t n) override;

};
