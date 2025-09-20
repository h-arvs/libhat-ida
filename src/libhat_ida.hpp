#pragma once

#include <libhat/scanner.hpp>

#include "def.hpp"

#include <idp.hpp>

struct libhat_ida : public plugmod_t {
     std::vector<std::byte> bytes;

     libhat_ida();

     void show_results_chooser( std::vector<hat::scan_result>&, qstring&);
     bool idaapi run(size_t arg) override;
};
