#include "results_chooser.hpp"

#include <lines.hpp>
#include <funcs.hpp>
#include <ida.hpp>
#include <segment.hpp>
#include <ua.hpp>


results_chooser::results_chooser(std::byte *base_, std::vector<hat::scan_result> &results_, const qstring &pattern)
    : results(std::move(results_)) {
    base = base_;
    static const char *headers[3] = {"Address", "Function", "Instruction"};
    columns = 3;
    header = headers;
    title_ = qstring("Occurrences of ") + pattern;
    title = title_.c_str();
}

size_t results_chooser::get_count() const {
    return results.size();
}

void results_chooser::get_row(qstrvec_t *out, int *out_icon, chooser_item_attrs_t *out_attrs, size_t n) const {
    static auto idabase = inf_get_min_ea();
    auto idaaddr = (results[n].get() - base) + idabase;

    qstring segname;
    get_segm_name(&segname, getseg(idaaddr));

    qstring funcname;
    get_func_name(&funcname, idaaddr);

    qstring disasm;
    generate_disasm_line(&disasm, idaaddr, GENDSM_REMOVE_TAGS);

    (*out)[0].sprnt("%s:%llx", segname.c_str(), idaaddr);
    (*out)[1].sprnt("%s", funcname.c_str());
    (*out)[2].sprnt("%s", disasm.c_str());
}

chooser_t::cbret_t results_chooser::enter(size_t n) {
    static auto idabase = inf_get_min_ea();
    auto idaaddr = (results[n].get() - base) + idabase;
    jumpto(idaaddr);
    return true;
}



