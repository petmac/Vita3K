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

#include <host/state.h>
#include <util/log.h> // log_hex

#include <imgui.h>

#include <sstream>

static void kernel_menu(KernelGuiState &gui) {
    if (ImGui::BeginMenu("Kernel")) {
        ImGui::MenuItem("Threads", nullptr, &gui.threads_dialog);
        ImGui::MenuItem("Semaphores", nullptr, &gui.semaphores_dialog);
        ImGui::MenuItem("Mutexes", nullptr, &gui.mutexes_dialog);
        ImGui::MenuItem("Lightweight Mutexes", nullptr, &gui.lwmutexes_dialog);
        ImGui::MenuItem("Condition Variables", nullptr, &gui.condvars_dialog);
        ImGui::MenuItem("Lightweight Condition Variables", nullptr, &gui.lwcondvars_dialog);
        ImGui::MenuItem("Event Flags", nullptr, &gui.eventflags_dialog);
        ImGui::EndMenu();
    }
}

static void gxm_menu(GxmGuiState &gui) {
    if (ImGui::BeginMenu("GXM")) {
        const std::unique_lock<std::mutex> lock(gui.mutex);
        for (ShowGxmContexts::value_type &context : gui.show_contexts) {
            std::ostringstream label;
            label << "Context " << log_hex(context.first.address());
            ImGui::MenuItem(label.str().c_str(), nullptr, &context.second);
        }
        ImGui::EndMenu();
    }
}

static void optimisation_menu(OptimisationGuiState &gui) {
    if (ImGui::BeginMenu("Optimisation")) {
        ImGui::MenuItem("Texture Cache", nullptr, &gui.texture_cache);
        ImGui::EndMenu();
    }
}

void DrawMainMenuBar(HostState &host) {
    if (ImGui::BeginMainMenuBar()) {
        kernel_menu(host.gui.kernel);
        gxm_menu(host.gui.gxm);
        optimisation_menu(host.gui.optimisation);
        ImGui::EndMainMenuBar();
    }
}
