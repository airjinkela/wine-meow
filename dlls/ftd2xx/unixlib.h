/*
 * Shared interface between the PE and the Unix side of the ftd2xx wrapper
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifndef __WINE_FTD2XX_UNIXLIB_H
#define __WINE_FTD2XX_UNIXLIB_H

#include "wine/unixlib.h"

/*
 * Parameter block shared by both sides.
 *
 * Every slot is 64 bits wide, which gives the structure exactly the same
 * layout when used from a 32-bit PE module and from the native 64-bit Unix
 * library. A single set of entry points is therefore usable both for
 * __wine_unix_call_funcs and for __wine_unix_call_wow64_funcs.
 *
 * Conventions:
 *   ret        written by the Unix side, read by the PE side
 *   args[]     arguments in declaration order, always starting at args[0],
 *              including the FT_HANDLE when the function takes one
 *
 * Pointers are stored zero-extended. The FT_HANDLE values exchanged with
 * the PE side are 32-bit ids into a table owned by the Unix library, never
 * native pointers, so that they survive the 32/64-bit boundary.
 */
#define FTD2XX_MAX_PARAMS 8

struct ftd2xx_params
{
    UINT64 ret;
    UINT64 args[FTD2XX_MAX_PARAMS];
};

enum ftd2xx_funcs
{
    unix_process_attach,
    unix_process_detach,
    unix_set_vid_pid,
    unix_create_device_info_list,
    unix_get_device_info_list,
    unix_get_device_info_detail,
    unix_list_devices,
    unix_open,
    unix_open_ex,
    unix_close,
    unix_read,
    unix_write,
    unix_reset_device,
    unix_set_baud_rate,
    unix_set_divisor,
    unix_set_data_characteristics,
    unix_set_flow_control,
    unix_set_dtr,
    unix_clr_dtr,
    unix_set_rts,
    unix_clr_rts,
    unix_set_break_on,
    unix_set_break_off,
    unix_get_modem_status,
    unix_set_chars,
    unix_purge,
    unix_set_timeouts,
    unix_get_queue_status,
    unix_get_status,
    unix_set_latency_timer,
    unix_get_latency_timer,
    unix_set_bit_mode,
    unix_get_bit_mode,
    unix_set_usb_parameters,
    unix_erase_ee,
    unix_read_ee,
    unix_write_ee,
    unix_ee_ua_read,
    unix_ee_ua_size,
    unix_ee_ua_write,
    unix_ee_program,
    unix_ee_read,
    unix_ee_program_ex,
    unix_ee_read_ex,
    unix_get_device_info,
    unix_stop_in_task,
    unix_restart_in_task,
    unix_get_driver_version,
    unix_get_library_version,
    unix_set_event_notification,
    unix_w32_create_file,
    unix_w32_close_handle,
    unix_w32_read_file,
    unix_w32_write_file,
    unix_w32_get_overlapped_result,
    unix_w32_clear_comm_break,
    unix_w32_clear_comm_error,
    unix_w32_escape_comm_function,
    unix_w32_get_comm_modem_status,
    unix_w32_get_comm_state,
    unix_w32_get_comm_timeouts,
    unix_w32_get_last_error,
    unix_w32_purge_comm,
    unix_w32_set_comm_break,
    unix_w32_set_comm_mask,
    unix_w32_set_comm_state,
    unix_w32_set_comm_timeouts,
    unix_w32_setup_comm,
    unix_w32_wait_comm_event,
    unix_funcs_count
};

#endif /* __WINE_FTD2XX_UNIXLIB_H */
