#include "results_chooser.hpp"

#include <lines.hpp>
#include <funcs.hpp>
#include <ida.hpp>
#include <segment.hpp>
#include <ua.hpp>

static constexpr int num_columns = 3;

static constexpr std::array col_headers{
    "Address",
    "Function",
    "Instruction"
};

static constexpr std::array col_widths{
    25 | CHCOL_EA,
    25,
    0
};

static_assert(col_headers.size() == num_columns);
static_assert(col_widths.size() == num_columns);

namespace libhat_ida {

results_chooser::results_chooser(std::byte* base_, std::vector<hat::scan_result> results_, const qstring& pattern) :
    chooser_t(0, num_columns, col_widths.data(), col_headers.data()), base(base_), results(std::move(results_)) {
    title_owned = qstring("Occurrences of ") + pattern;
    title = title_owned.c_str();
}

size_t results_chooser::get_count() const {
    return results.size();
}

void results_chooser::get_row(qstrvec_t* out, int* out_icon, chooser_item_attrs_t* out_attrs, const size_t n) const {
    const auto idaaddr = this->get_ea(n);

    qstring segname;
    get_segm_name(&segname, getseg(idaaddr));

    qstring funcname;
    get_func_name(&funcname, idaaddr);

    qstring disasm;
    generate_disasm_line(&disasm, idaaddr, GENDSM_REMOVE_TAGS);

    (*out)[0].sprnt("%s:%08a", segname.c_str(), idaaddr);
    (*out)[1].sprnt("%s", funcname.c_str());
    (*out)[2].sprnt("%s", disasm.c_str());
}

ea_t idaapi results_chooser::get_ea(const size_t n) const {
    return static_cast<size_t>(results[n].get() - base) + inf_get_min_ea();
}

}
