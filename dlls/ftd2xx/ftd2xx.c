/*
 * Wine wrapper for the FTDI D2XX library
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

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "windef.h"
#include "winbase.h"
#include "unixlib.h"
#include "wine/debug.h"

/*
 * Use the vendor header directly.
 *
 * FTD2XX_EXPORTS is selected so that neither the dllimport branch nor the
 * FTD2XX_STATIC branch is taken; the latter would emit
 * "#pragma comment(lib, ...)" directives that clang turns into real linker
 * inputs, and the former upsets Wine's __declspec emulation. To keep the
 * dllexport branch harmless as well, __declspec is stubbed out for the
 * duration of the include: the exports come from ftd2xx.spec instead.
 */
#define FTD2XX_EXPORTS
#ifndef LPCTSTR
typedef const char *LPCTSTR;
#endif
#pragma push_macro("__declspec")
#undef __declspec
#define __declspec(x)
#include "ftdi/ftd2xx.h"
#pragma pop_macro("__declspec")

WINE_DEFAULT_DEBUG_CHANNEL(ftd2xx);

/* handles crossing the PE/Unix boundary are 32-bit ids, never native pointers */
static inline UINT64 handle_id( FT_HANDLE handle )
{
    return (UINT64)(UINT32)(ULONG_PTR)handle;
}

static inline FT_HANDLE make_handle( UINT32 id )
{
    return (FT_HANDLE)(ULONG_PTR)id;
}

static void set_args( struct ftd2xx_params *params, ULONG count, ... )
{
    va_list va;
    unsigned int i;

    memset( params, 0, sizeof(*params) );
    va_start( va, count );
    for (i = 0; i < count; i++) params->args[i] = va_arg( va, UINT64 );
    va_end( va );
}

static FT_STATUS call_status( enum ftd2xx_funcs func, struct ftd2xx_params *params )
{
    if (WINE_UNIX_CALL( func, params )) return FT_INVALID_PARAMETER;
    return (FT_STATUS)params->ret;
}

/* FTDID=<product> or FTDID=<vendor>:<product>, both in hex */
static void init_vid_pid(void)
{
    const char *cursor = getenv( "FTDID" );
    struct ftd2xx_params params;
    unsigned long product, vendor = 0x403;
    char *end;

    if (!cursor) return;
    product = strtoul( cursor, &end, 16 );
    if (product && end && *end)
    {
        unsigned long tmp = strtoul( end + 1, &end, 16 );
        if (tmp)
        {
            vendor = product;
            product = tmp;
        }
    }

    set_args( &params, 2, (UINT64)vendor, (UINT64)product );
    WINE_UNIX_CALL( unix_set_vid_pid, &params );
    TRACE( "seeking vendor:product 0x%04lx:0x%04lx\n", vendor, product );
}

BOOL WINAPI DllMain( HINSTANCE instance, DWORD reason, LPVOID reserved )
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        if (__wine_init_unix_call()) return FALSE;
        init_vid_pid();
    }
    return TRUE;
}

/* Helpers for the calls whose only argument is the handle. */
#define HANDLE_ONLY_CALL(name, func) \
    FT_STATUS WINAPI name( FT_HANDLE handle ) \
    { \
        struct ftd2xx_params params; \
        TRACE( "\n" ); \
        set_args( &params, 1, handle_id( handle ) ); \
        return call_status( func, &params ); \
    }

HANDLE_ONLY_CALL( FT_Close, unix_close )
HANDLE_ONLY_CALL( FT_ResetDevice, unix_reset_device )
HANDLE_ONLY_CALL( FT_SetDtr, unix_set_dtr )
HANDLE_ONLY_CALL( FT_ClrDtr, unix_clr_dtr )
HANDLE_ONLY_CALL( FT_SetRts, unix_set_rts )
HANDLE_ONLY_CALL( FT_ClrRts, unix_clr_rts )
HANDLE_ONLY_CALL( FT_SetBreakOn, unix_set_break_on )
HANDLE_ONLY_CALL( FT_SetBreakOff, unix_set_break_off )
HANDLE_ONLY_CALL( FT_EraseEE, unix_erase_ee )
HANDLE_ONLY_CALL( FT_StopInTask, unix_stop_in_task )
HANDLE_ONLY_CALL( FT_RestartInTask, unix_restart_in_task )


FT_STATUS WINAPI FT_CreateDeviceInfoList( LPDWORD count )
{
    struct ftd2xx_params params;
    FT_STATUS status;

    TRACE( "%p\n", count );
    set_args( &params, 1, (UINT64)(ULONG_PTR)count );
    status = call_status( unix_create_device_info_list, &params );
    TRACE( "returning %lu, count=%lu\n", status, count ? *count : 0 );
    return status;
}

FT_STATUS WINAPI FT_GetDeviceInfoList( FT_DEVICE_LIST_INFO_NODE *dest, LPDWORD count )
{
    struct ftd2xx_params params;

    TRACE( "%p %p\n", dest, count );
    set_args( &params, 2, (UINT64)(ULONG_PTR)dest, (UINT64)(ULONG_PTR)count );
    return call_status( unix_get_device_info_list, &params );
}

FT_STATUS WINAPI FT_GetDeviceInfoDetail( DWORD index, LPDWORD flags, LPDWORD type, LPDWORD id,
                                         LPDWORD locid, LPVOID serial, LPVOID description,
                                         FT_HANDLE *handle )
{
    struct ftd2xx_params params;
    UINT32 hid = 0;
    FT_STATUS status;

    TRACE( "%lu\n", index );
    set_args( &params, 8, (UINT64)index, (UINT64)(ULONG_PTR)flags, (UINT64)(ULONG_PTR)type,
             (UINT64)(ULONG_PTR)id, (UINT64)(ULONG_PTR)locid, (UINT64)(ULONG_PTR)serial,
             (UINT64)(ULONG_PTR)description, (UINT64)(ULONG_PTR)&hid );
    status = call_status( unix_get_device_info_detail, &params );
    if (status == FT_OK && handle) *handle = make_handle( hid );
    return status;
}

FT_STATUS WINAPI FT_ListDevices( PVOID arg1, PVOID arg2, DWORD flags )
{
    struct ftd2xx_params params;

    TRACE( "%p %p 0x%lx\n", arg1, arg2, flags );
    set_args( &params, 3, (UINT64)(ULONG_PTR)arg1, (UINT64)(ULONG_PTR)arg2, (UINT64)flags );
    return call_status( unix_list_devices, &params );
}

FT_STATUS WINAPI FT_Open( int device, FT_HANDLE *handle )
{
    struct ftd2xx_params params;
    UINT32 hid = 0;
    FT_STATUS status;

    TRACE( "%d\n", device );
    set_args( &params, 2, (UINT64)(LONG)device, (UINT64)(ULONG_PTR)&hid );
    status = call_status( unix_open, &params );
    if (status == FT_OK && handle) *handle = make_handle( hid );
    return status;
}

FT_STATUS WINAPI FT_OpenEx( PVOID arg, DWORD flags, FT_HANDLE *handle )
{
    struct ftd2xx_params params;
    UINT32 hid = 0;
    FT_STATUS status;

    TRACE( "%p 0x%lx\n", arg, flags );
    set_args( &params, 3, (UINT64)(ULONG_PTR)arg, (UINT64)flags, (UINT64)(ULONG_PTR)&hid );
    status = call_status( unix_open_ex, &params );
    if (status == FT_OK && handle) *handle = make_handle( hid );
    return status;
}

FT_STATUS WINAPI FT_Read( FT_HANDLE handle, LPVOID buffer, DWORD size, LPDWORD returned )
{
    struct ftd2xx_params params;

    TRACE( "%p\n", handle );
    set_args( &params, 4, handle_id( handle ), (UINT64)(ULONG_PTR)buffer, (UINT64)size,
             (UINT64)(ULONG_PTR)returned );
    return call_status( unix_read, &params );
}

FT_STATUS WINAPI FT_Write( FT_HANDLE handle, LPVOID buffer, DWORD size, LPDWORD written )
{
    struct ftd2xx_params params;

    TRACE( "%p\n", handle );
    set_args( &params, 4, handle_id( handle ), (UINT64)(ULONG_PTR)buffer, (UINT64)size,
             (UINT64)(ULONG_PTR)written );
    return call_status( unix_write, &params );
}

FT_STATUS WINAPI FT_SetBaudRate( FT_HANDLE handle, DWORD baud )
{
    struct ftd2xx_params params;

    TRACE( "%p %lu\n", handle, baud );
    set_args( &params, 2, handle_id( handle ), (UINT64)baud );
    return call_status( unix_set_baud_rate, &params );
}

FT_STATUS WINAPI FT_SetDivisor( FT_HANDLE handle, USHORT divisor )
{
    struct ftd2xx_params params;

    TRACE( "%p %u\n", handle, divisor );
    set_args( &params, 2, handle_id( handle ), (UINT64)divisor );
    return call_status( unix_set_divisor, &params );
}

FT_STATUS WINAPI FT_SetDataCharacteristics( FT_HANDLE handle, UCHAR bits, UCHAR stop, UCHAR parity )
{
    struct ftd2xx_params params;

    TRACE( "%p %u %u %u\n", handle, bits, stop, parity );
    set_args( &params, 4, handle_id( handle ), (UINT64)bits, (UINT64)stop, (UINT64)parity );
    return call_status( unix_set_data_characteristics, &params );
}

FT_STATUS WINAPI FT_SetFlowControl( FT_HANDLE handle, USHORT flow, UCHAR xon, UCHAR xoff )
{
    struct ftd2xx_params params;

    TRACE( "%p 0x%x %u %u\n", handle, flow, xon, xoff );
    set_args( &params, 4, handle_id( handle ), (UINT64)flow, (UINT64)xon, (UINT64)xoff );
    return call_status( unix_set_flow_control, &params );
}

FT_STATUS WINAPI FT_SetChars( FT_HANDLE handle, UCHAR event, UCHAR event_enable,
                              UCHAR error, UCHAR error_enable )
{
    struct ftd2xx_params params;

    TRACE( "%p\n", handle );
    set_args( &params, 5, handle_id( handle ), (UINT64)event, (UINT64)event_enable,
             (UINT64)error, (UINT64)error_enable );
    return call_status( unix_set_chars, &params );
}

FT_STATUS WINAPI FT_Purge( FT_HANDLE handle, ULONG mask )
{
    struct ftd2xx_params params;

    TRACE( "%p 0x%lx\n", handle, mask );
    set_args( &params, 2, handle_id( handle ), (UINT64)mask );
    return call_status( unix_purge, &params );
}

FT_STATUS WINAPI FT_SetTimeouts( FT_HANDLE handle, DWORD read_timeout, DWORD write_timeout )
{
    struct ftd2xx_params params;

    TRACE( "%p %lu %lu\n", handle, read_timeout, write_timeout );
    set_args( &params, 3, handle_id( handle ), (UINT64)read_timeout, (UINT64)write_timeout );
    return call_status( unix_set_timeouts, &params );
}

FT_STATUS WINAPI FT_GetModemStatus( FT_HANDLE handle, LPDWORD status )
{
    struct ftd2xx_params params;

    TRACE( "%p %p\n", handle, status );
    set_args( &params, 2, handle_id( handle ), (UINT64)(ULONG_PTR)status );
    return call_status( unix_get_modem_status, &params );
}

FT_STATUS WINAPI FT_GetQueueStatus( FT_HANDLE handle, DWORD *count )
{
    struct ftd2xx_params params;

    TRACE( "%p %p\n", handle, count );
    set_args( &params, 2, handle_id( handle ), (UINT64)(ULONG_PTR)count );
    return call_status( unix_get_queue_status, &params );
}

FT_STATUS WINAPI FT_GetStatus( FT_HANDLE handle, DWORD *rx, DWORD *tx, DWORD *event )
{
    struct ftd2xx_params params;

    TRACE( "%p %p %p %p\n", handle, rx, tx, event );
    set_args( &params, 4, handle_id( handle ), (UINT64)(ULONG_PTR)rx,
             (UINT64)(ULONG_PTR)tx, (UINT64)(ULONG_PTR)event );
    return call_status( unix_get_status, &params );
}

FT_STATUS WINAPI FT_SetLatencyTimer( FT_HANDLE handle, UCHAR latency )
{
    struct ftd2xx_params params;

    TRACE( "%p %u\n", handle, latency );
    set_args( &params, 2, handle_id( handle ), (UINT64)latency );
    return call_status( unix_set_latency_timer, &params );
}

FT_STATUS WINAPI FT_GetLatencyTimer( FT_HANDLE handle, PUCHAR latency )
{
    struct ftd2xx_params params;

    TRACE( "%p %p\n", handle, latency );
    set_args( &params, 2, handle_id( handle ), (UINT64)(ULONG_PTR)latency );
    return call_status( unix_get_latency_timer, &params );
}

FT_STATUS WINAPI FT_SetBitMode( FT_HANDLE handle, UCHAR mask, UCHAR enable )
{
    struct ftd2xx_params params;

    TRACE( "%p 0x%x 0x%x\n", handle, mask, enable );
    set_args( &params, 3, handle_id( handle ), (UINT64)mask, (UINT64)enable );
    return call_status( unix_set_bit_mode, &params );
}

FT_STATUS WINAPI FT_GetBitMode( FT_HANDLE handle, PUCHAR mode )
{
    struct ftd2xx_params params;

    TRACE( "%p %p\n", handle, mode );
    set_args( &params, 2, handle_id( handle ), (UINT64)(ULONG_PTR)mode );
    return call_status( unix_get_bit_mode, &params );
}

FT_STATUS WINAPI FT_SetUSBParameters( FT_HANDLE handle, ULONG in_size, ULONG out_size )
{
    struct ftd2xx_params params;

    TRACE( "%p %lu %lu\n", handle, in_size, out_size );
    set_args( &params, 3, handle_id( handle ), (UINT64)in_size, (UINT64)out_size );
    return call_status( unix_set_usb_parameters, &params );
}

FT_STATUS WINAPI FT_ReadEE( FT_HANDLE handle, DWORD offset, LPWORD value )
{
    struct ftd2xx_params params;

    TRACE( "%p %lu %p\n", handle, offset, value );
    set_args( &params, 3, handle_id( handle ), (UINT64)offset, (UINT64)(ULONG_PTR)value );
    return call_status( unix_read_ee, &params );
}

FT_STATUS WINAPI FT_WriteEE( FT_HANDLE handle, DWORD offset, WORD value )
{
    struct ftd2xx_params params;

    TRACE( "%p %lu 0x%x\n", handle, offset, value );
    set_args( &params, 3, handle_id( handle ), (UINT64)offset, (UINT64)value );
    return call_status( unix_write_ee, &params );
}

FT_STATUS WINAPI FT_EE_UARead( FT_HANDLE handle, UCHAR *data, DWORD size, DWORD *read )
{
    struct ftd2xx_params params;

    TRACE( "%p %p %lu %p\n", handle, data, size, read );
    set_args( &params, 4, handle_id( handle ), (UINT64)(ULONG_PTR)data, (UINT64)size,
             (UINT64)(ULONG_PTR)read );
    return call_status( unix_ee_ua_read, &params );
}

FT_STATUS WINAPI FT_EE_UASize( FT_HANDLE handle, DWORD *size )
{
    struct ftd2xx_params params;

    TRACE( "%p %p\n", handle, size );
    set_args( &params, 2, handle_id( handle ), (UINT64)(ULONG_PTR)size );
    return call_status( unix_ee_ua_size, &params );
}

FT_STATUS WINAPI FT_EE_UAWrite( FT_HANDLE handle, UCHAR *data, DWORD size )
{
    struct ftd2xx_params params;

    TRACE( "%p %p %lu\n", handle, data, size );
    set_args( &params, 3, handle_id( handle ), (UINT64)(ULONG_PTR)data, (UINT64)size );
    return call_status( unix_ee_ua_write, &params );
}

FT_STATUS WINAPI FT_EE_Program( FT_HANDLE handle, PFT_PROGRAM_DATA data )
{
    struct ftd2xx_params params;

    TRACE( "%p %p\n", handle, data );
    set_args( &params, 2, handle_id( handle ), (UINT64)(ULONG_PTR)data );
    return call_status( unix_ee_program, &params );
}

FT_STATUS WINAPI FT_EE_Read( FT_HANDLE handle, PFT_PROGRAM_DATA data )
{
    struct ftd2xx_params params;

    TRACE( "%p %p\n", handle, data );
    set_args( &params, 2, handle_id( handle ), (UINT64)(ULONG_PTR)data );
    return call_status( unix_ee_read, &params );
}

FT_STATUS WINAPI FT_EE_ProgramEx( FT_HANDLE handle, PFT_PROGRAM_DATA data, char *manufacturer,
                                  char *manufacturer_id, char *description, char *serial )
{
    struct ftd2xx_params params;

    TRACE( "%p %p\n", handle, data );
    set_args( &params, 6, handle_id( handle ), (UINT64)(ULONG_PTR)data,
             (UINT64)(ULONG_PTR)manufacturer, (UINT64)(ULONG_PTR)manufacturer_id,
             (UINT64)(ULONG_PTR)description, (UINT64)(ULONG_PTR)serial );
    return call_status( unix_ee_program_ex, &params );
}

FT_STATUS WINAPI FT_EE_ReadEx( FT_HANDLE handle, PFT_PROGRAM_DATA data, char *manufacturer,
                               char *manufacturer_id, char *description, char *serial )
{
    struct ftd2xx_params params;

    TRACE( "%p %p\n", handle, data );
    set_args( &params, 6, handle_id( handle ), (UINT64)(ULONG_PTR)data,
             (UINT64)(ULONG_PTR)manufacturer, (UINT64)(ULONG_PTR)manufacturer_id,
             (UINT64)(ULONG_PTR)description, (UINT64)(ULONG_PTR)serial );
    return call_status( unix_ee_read_ex, &params );
}

FT_STATUS WINAPI FT_GetDeviceInfo( FT_HANDLE handle, FT_DEVICE *device, LPDWORD id,
                                   PCHAR serial, PCHAR description, LPVOID dummy )
{
    struct ftd2xx_params params;
    UINT32 hid = 0;
    FT_STATUS status;

    TRACE( "%p\n", handle );
    set_args( &params, 6, handle_id( handle ), (UINT64)(ULONG_PTR)device, (UINT64)(ULONG_PTR)id,
             (UINT64)(ULONG_PTR)serial, (UINT64)(ULONG_PTR)description, (UINT64)(ULONG_PTR)&hid );
    status = call_status( unix_get_device_info, &params );
    if (status == FT_OK && dummy) *(FT_HANDLE *)dummy = make_handle( hid );
    return status;
}

FT_STATUS WINAPI FT_GetDriverVersion( FT_HANDLE handle, LPDWORD version )
{
    struct ftd2xx_params params;

    TRACE( "%p %p\n", handle, version );
    set_args( &params, 2, handle_id( handle ), (UINT64)(ULONG_PTR)version );
    return call_status( unix_get_driver_version, &params );
}

FT_STATUS WINAPI FT_GetLibraryVersion( LPDWORD version )
{
    struct ftd2xx_params params;

    TRACE( "%p\n", version );
    set_args( &params, 1, (UINT64)(ULONG_PTR)version );
    return call_status( unix_get_library_version, &params );
}

FT_STATUS WINAPI FT_SetEventNotification( FT_HANDLE handle, DWORD mask, PVOID param )
{
    struct ftd2xx_params params;

    TRACE( "%p 0x%lx %p\n", handle, mask, param );
    set_args( &params, 3, handle_id( handle ), (UINT64)mask, (UINT64)(ULONG_PTR)param );
    return call_status( unix_set_event_notification, &params );
}

FT_HANDLE WINAPI FT_W32_CreateFile( LPCTSTR name, DWORD access, DWORD share,
                                    LPSECURITY_ATTRIBUTES sa, DWORD create, DWORD flags,
                                    HANDLE templ )
{
    struct ftd2xx_params params;
    UINT32 hid = 0;
    FT_STATUS status;

    TRACE( "%p 0x%lx 0x%lx %p 0x%lx 0x%lx %p\n", name, access, share, sa, create, flags, templ );
    set_args( &params, 7, (UINT64)(ULONG_PTR)name, (UINT64)access, (UINT64)share,
             (UINT64)(ULONG_PTR)sa, (UINT64)create, (UINT64)flags, (UINT64)(ULONG_PTR)&hid );
    status = call_status( unix_w32_create_file, &params );
    if (status != FT_OK) return INVALID_HANDLE_VALUE;
    return make_handle( hid );
}

BOOL WINAPI FT_W32_CloseHandle( FT_HANDLE handle )
{
    struct ftd2xx_params params;

    TRACE( "%p\n", handle );
    set_args( &params, 1, handle_id( handle ) );
    return call_status( unix_w32_close_handle, &params );
}

BOOL WINAPI FT_W32_ReadFile( FT_HANDLE handle, LPVOID buffer, DWORD size, LPDWORD returned,
                             LPOVERLAPPED overlapped )
{
    struct ftd2xx_params params;

    TRACE( "%p\n", handle );
    set_args( &params, 5, handle_id( handle ), (UINT64)(ULONG_PTR)buffer, (UINT64)size,
             (UINT64)(ULONG_PTR)returned, (UINT64)(ULONG_PTR)overlapped );
    return call_status( unix_w32_read_file, &params );
}

BOOL WINAPI FT_W32_WriteFile( FT_HANDLE handle, LPVOID buffer, DWORD size, LPDWORD written,
                              LPOVERLAPPED overlapped )
{
    struct ftd2xx_params params;

    TRACE( "%p\n", handle );
    set_args( &params, 5, handle_id( handle ), (UINT64)(ULONG_PTR)buffer, (UINT64)size,
             (UINT64)(ULONG_PTR)written, (UINT64)(ULONG_PTR)overlapped );
    return call_status( unix_w32_write_file, &params );
}

BOOL WINAPI FT_W32_GetOverlappedResult( FT_HANDLE handle, LPOVERLAPPED overlapped,
                                        LPDWORD transferred, BOOL wait )
{
    struct ftd2xx_params params;

    TRACE( "%p\n", handle );
    set_args( &params, 4, handle_id( handle ), (UINT64)(ULONG_PTR)overlapped,
             (UINT64)(ULONG_PTR)transferred, (UINT64)wait );
    return call_status( unix_w32_get_overlapped_result, &params );
}

BOOL WINAPI FT_W32_ClearCommBreak( FT_HANDLE handle )
{
    struct ftd2xx_params params;

    TRACE( "%p\n", handle );
    set_args( &params, 1, handle_id( handle ) );
    return call_status( unix_w32_clear_comm_break, &params );
}

BOOL WINAPI FT_W32_ClearCommError( FT_HANDLE handle, LPDWORD errors, LPFTCOMSTAT stat )
{
    struct ftd2xx_params params;

    TRACE( "%p\n", handle );
    set_args( &params, 3, handle_id( handle ), (UINT64)(ULONG_PTR)errors, (UINT64)(ULONG_PTR)stat );
    return call_status( unix_w32_clear_comm_error, &params );
}

BOOL WINAPI FT_W32_EscapeCommFunction( FT_HANDLE handle, DWORD func )
{
    struct ftd2xx_params params;

    TRACE( "%p 0x%lx\n", handle, func );
    set_args( &params, 2, handle_id( handle ), (UINT64)func );
    return call_status( unix_w32_escape_comm_function, &params );
}

BOOL WINAPI FT_W32_GetCommModemStatus( FT_HANDLE handle, LPDWORD status )
{
    struct ftd2xx_params params;

    TRACE( "%p\n", handle );
    set_args( &params, 2, handle_id( handle ), (UINT64)(ULONG_PTR)status );
    return call_status( unix_w32_get_comm_modem_status, &params );
}

BOOL WINAPI FT_W32_GetCommState( FT_HANDLE handle, LPFTDCB dcb )
{
    struct ftd2xx_params params;

    TRACE( "%p\n", handle );
    set_args( &params, 2, handle_id( handle ), (UINT64)(ULONG_PTR)dcb );
    return call_status( unix_w32_get_comm_state, &params );
}

BOOL WINAPI FT_W32_GetCommTimeouts( FT_HANDLE handle, LPFTTIMEOUTS timeouts )
{
    struct ftd2xx_params params;

    TRACE( "%p\n", handle );
    set_args( &params, 2, handle_id( handle ), (UINT64)(ULONG_PTR)timeouts );
    return call_status( unix_w32_get_comm_timeouts, &params );
}

DWORD WINAPI FT_W32_GetLastError( FT_HANDLE handle )
{
    struct ftd2xx_params params;

    TRACE( "%p\n", handle );
    set_args( &params, 1, handle_id( handle ) );
    return call_status( unix_w32_get_last_error, &params );
}

BOOL WINAPI FT_W32_PurgeComm( FT_HANDLE handle, DWORD flags )
{
    struct ftd2xx_params params;

    TRACE( "%p 0x%lx\n", handle, flags );
    set_args( &params, 2, handle_id( handle ), (UINT64)flags );
    return call_status( unix_w32_purge_comm, &params );
}

BOOL WINAPI FT_W32_SetCommBreak( FT_HANDLE handle )
{
    struct ftd2xx_params params;

    TRACE( "%p\n", handle );
    set_args( &params, 1, handle_id( handle ) );
    return call_status( unix_w32_set_comm_break, &params );
}

BOOL WINAPI FT_W32_SetCommMask( FT_HANDLE handle, DWORD mask )
{
    struct ftd2xx_params params;

    TRACE( "%p 0x%lx\n", handle, mask );
    set_args( &params, 2, handle_id( handle ), (UINT64)mask );
    return call_status( unix_w32_set_comm_mask, &params );
}

BOOL WINAPI FT_W32_SetCommState( FT_HANDLE handle, LPFTDCB dcb )
{
    struct ftd2xx_params params;

    TRACE( "%p\n", handle );
    set_args( &params, 2, handle_id( handle ), (UINT64)(ULONG_PTR)dcb );
    return call_status( unix_w32_set_comm_state, &params );
}

BOOL WINAPI FT_W32_SetCommTimeouts( FT_HANDLE handle, LPFTTIMEOUTS timeouts )
{
    struct ftd2xx_params params;

    TRACE( "%p\n", handle );
    set_args( &params, 2, handle_id( handle ), (UINT64)(ULONG_PTR)timeouts );
    return call_status( unix_w32_set_comm_timeouts, &params );
}

BOOL WINAPI FT_W32_SetupComm( FT_HANDLE handle, DWORD read_size, DWORD write_size )
{
    struct ftd2xx_params params;

    TRACE( "%p %lu %lu\n", handle, read_size, write_size );
    set_args( &params, 3, handle_id( handle ), (UINT64)read_size, (UINT64)write_size );
    return call_status( unix_w32_setup_comm, &params );
}

BOOL WINAPI FT_W32_WaitCommEvent( FT_HANDLE handle, LPDWORD event, LPOVERLAPPED overlapped )
{
    struct ftd2xx_params params;

    TRACE( "%p\n", handle );
    set_args( &params, 3, handle_id( handle ), (UINT64)(ULONG_PTR)event,
             (UINT64)(ULONG_PTR)overlapped );
    return call_status( unix_w32_wait_comm_event, &params );
}
