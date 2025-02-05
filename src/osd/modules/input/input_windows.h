// license:BSD-3-Clause
// copyright-holders:Aaron Giles, Brad Hughes
//============================================================
//
//  input_windows.h - Common code used by Windows input modules
//
//============================================================
#ifndef MAME_OSD_INPUT_INPUT_WINDOWS_H
#define MAME_OSD_INPUT_INPUT_WINDOWS_H

#pragma once

#include "input_common.h"

#include "window.h"
#include "winmain.h"

// standard windows headers
#include <windows.h>


//============================================================
//  TYPEDEFS
//============================================================

// state information for a keyboard
struct keyboard_state
{
	uint8_t                   state[MAX_KEYS];
	int8_t                    oldkey[MAX_KEYS];
	int8_t                    currkey[MAX_KEYS];
};

// state information for a mouse (matches DIMOUSESTATE exactly)
struct mouse_state
{
	LONG                    lX;
	LONG                    lY;
	LONG                    lZ;
	BYTE                    rgbButtons[8];
};

// state information for a joystick
struct joystick_state
{
	int32_t                 axes[9] = {0, 0, 0, 0, 0, 0, 0, 0, 0};
	bool                    bidirectional_trigger_axis[9] = {false, false, false, false, false, false, false, false, false};
	int32_t                 buttons[MAX_BUTTONS];
	int32_t                 hats[4] = {0, 0, 0, 0};
};

class wininput_module : public input_module_base
{
protected:
	bool  m_keyboard_global_inputs_enabled = false;
	bool  m_mouse_global_inputs_enabled = false;
	bool  m_joystick_global_inputs_enabled = false;

public:
	wininput_module(const char *type, const char *name) : input_module_base(type, name) { }

	virtual ~wininput_module() { }

	virtual bool should_hide_mouse()
	{
		if (winwindow_has_focus()  // has focus
			&& (!video_config.windowed || !osd_common_t::s_window_list.front()->win_has_menu()) // not windowed or doesn't have a menu
			&& (input_enabled() && !input_paused()) // input enabled and not paused
			&& (mouse_enabled() || lightgun_enabled())) // either mouse or lightgun enabled in the core
		{
			return true;
		}

		return false;
	}

	virtual bool handle_input_event(input_event eventid, void* data)
	{
		return false;
	}

protected:

	void before_poll(running_machine& machine) override
	{
		// periodically process events, in case they're not coming through
		// this also will make sure the mouse state is up-to-date
		winwindow_process_events_periodic(machine);
	}

	bool should_poll_devices(running_machine &machine) override
	{
		return input_enabled() && (m_keyboard_global_inputs_enabled || m_mouse_global_inputs_enabled ||  m_joystick_global_inputs_enabled || winwindow_has_focus());
	}
};

#endif // MAME_OSD_INPUT_INPUT_WINDOWS_H
