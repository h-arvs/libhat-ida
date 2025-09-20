#include "libhat_ida.hpp"
#include <hexrays.hpp>

static plugmod_t * idaapi init() {
    return new libhat_ida;
}

plugin_t PLUGIN =
{
    IDP_INTERFACE_VERSION,
    PLUGIN_MULTI,
    init,
    nullptr,
    nullptr,
    "A pattern scanner powered by libhat.",
    nullptr,
    "Libhat",
    "Alt+B"
};