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

#include <gui/functions.h>
#include <host/state.h>
#include <imgui.h>

static void kernel_menu(GuiState &gui) {
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

static void optimisation_menu(GuiState &gui) {
    if (ImGui::BeginMenu("Optimisation")) {
        ImGui::MenuItem("Texture Cache", nullptr, &gui.texture_cache);
        ImGui::EndMenu();
    }
}

void DrawMainMenuBar(HostState &host) {
    if (ImGui::BeginMainMenuBar()) {
        kernel_menu(host.gui);
        optimisation_menu(host.gui);
        ImGui::EndMainMenuBar();
    }
}
