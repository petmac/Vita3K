// Vita3K emulator project
// Copyright (C) 2018 Vita3K team
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

#include "ui_private.h"

#include <gui/state.h>

#include <gxm/types.h>
#include <mem/mem.h> // MemState

#include <imgui.h>

#include <mutex>

static void gxm_context_dialog(ShowGxmContexts::value_type &show_context, const MemState &mem) {
    if (!ImGui::Begin("GXM Context", &show_context.second)) {
        ImGui::End();
        return;
    }
    
    const SceGxmContext &context = *show_context.first.get(mem);
    
    ImGui::End();
}

void gxm_context_dialogs(GxmGuiState &gui, const MemState &mem) {
    const std::unique_lock<std::mutex> lock(gui.mutex);
    for (ShowGxmContexts::value_type &show_context : gui.show_contexts) {
        if (show_context.second) {
            gxm_context_dialog(show_context, mem);
        }
    }
}
