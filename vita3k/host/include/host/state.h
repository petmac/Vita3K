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

#pragma once

#include "sfo.h"
#include "window.h"

#include <mem/mem.h> // MemState
#include <nids/types.h>

// The GDB Stub requires winsock.h on windows (included in above headers). Keep it here to prevent build errors.
#ifdef USE_GDBSTUB
#include <gdbstub/state.h>
#endif

#include <psp2/types.h>

#include <memory>
#include <string>

struct AudioState;
struct Config;
struct CtrlState;
struct DialogState;
struct DisplayState;
struct GxmState;
struct IOState;
struct KernelState;
struct NetState;
struct NpState;

namespace renderer {
struct State;
}

struct HostState {
    std::string game_version;
    std::string game_title;
    std::string base_path;
    std::string pref_path;
    std::unique_ptr<Config> cfg;
    size_t frame_count = 0;
    uint32_t sdl_ticks = 0;
    uint32_t fps = 0;
    uint32_t ms_per_frame = 0;
    bool should_update_window_title = false;
    WindowPtr window = WindowPtr(nullptr, nullptr);
    std::unique_ptr<renderer::State> renderer;
    SceIVector2 drawable_size = { 0, 0 };
    SceFVector2 viewport_pos = { 0, 0 };
    SceFVector2 viewport_size = { 0, 0 };
    MemState mem;
    std::unique_ptr<CtrlState> ctrl;
    std::shared_ptr<KernelState> kernel;
    std::unique_ptr<AudioState> audio;
    std::shared_ptr<GxmState> gxm;
    bool renderer_focused;
    std::unique_ptr<IOState> io;
    std::unique_ptr<NetState> net;
    std::unique_ptr<NpState> np;
    std::unique_ptr<DisplayState> display;
    std::unique_ptr<DialogState> common_dialog;
    SfoFile sfo_handle;
    NIDSet missing_nids;
#ifdef USE_GDBSTUB
    GDBState gdb;
#endif
};
