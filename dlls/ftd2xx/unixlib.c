/*
 * Unix library for the FTDI D2XX wrapper
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

#if 0
#pragma makedep unix
#endif

#include "config.h"

#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "ntstatus.h"
#include "windef.h"
#include "winbase.h"
#include "unixlib.h"

/*
 * The FTDI headers select their own Win32 type definitions when _WIN32 is
 * not defined, which would clash with the Wine ones included above. Defining
 * it makes them use the standard windows.h path and pick up the Wine types.
 *
 * FTD2XX_STATIC expands FTD2XX_API to nothing. Wine rejects both dllimport
 * and dllexport here, and this side only calls the native library.
 */
#ifndef _WIN32
#define _WIN32
#endif
#ifndef FTD2XX_STATIC
#define FTD2XX_STATIC
#endif
/* Wine's headers do not provide this one, the FTDI W32 helpers use it */
#ifndef LPCTSTR
typedef const char *LPCTSTR;
#endif
/* the FTDI header carries MSVC-only pragmas that have no meaning here */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunknown-pragmas"
#pragma GCC diagnostic ignored "-Wpragmas"
#include "ftdi/ftd2xx.h"
#pragma GCC diagnostic pop

/* only declared for non-Windows by the FTDI header, but exported on Linux */
extern FT_STATUS FT_SetVIDPID( DWORD vid, DWORD pid );

/*
 * The 32-bit PE side cannot hold a native 64-bit FT_HANDLE, so handles are
 * exposed as a 1-based index into a table of native handles.
 */
static FT_HANDLE *handle_table;
static BOOL *handle_used;
static unsigned int handle_count;
static unsigned int handle_size;

static FT_HANDLE handle_from_id( UINT64 id )
{
    if (!id || id > handle_count) return NULL;
    if (!handle_used[id - 1]) return NULL;
    return handle_table[id - 1];
}

static UINT64 id_from_handle( FT_HANDLE handle )
{
    unsigned int i;

    if (!handle) return 0;
    for (i = 0; i < handle_count; i++)
        if (handle_used[i] && handle_table[i] == handle) return i + 1;

    /* reuse a released slot first so ids stay small */
    for (i = 0; i < handle_count; i++)
    {
        if (handle_used[i]) continue;
        handle_table[i] = handle;
        handle_used[i] = TRUE;
        return i + 1;
    }

    if (handle_count == handle_size)
    {
        unsigned int new_size = handle_size ? handle_size * 2 : 16;
        FT_HANDLE *new_table;
        BOOL *new_used;

        new_used = realloc( handle_used, new_size * sizeof(*new_used) );
        if (!new_used) return 0;
        handle_used = new_used;

        new_table = realloc( handle_table, new_size * sizeof(*new_table) );
        if (!new_table) return 0;
        handle_table = new_table;
        handle_size = new_size;
    }
    handle_table[handle_count] = handle;
    handle_used[handle_count] = TRUE;
    return ++handle_count;
}

static void remove_handle( UINT64 id )
{
    if (!id || id > handle_count) return;
    handle_used[id - 1] = FALSE;
    handle_table[id - 1] = NULL;
}

/*
 * FT_PROGRAM_DATA is 160 bytes on the PE side and 176 bytes on the Unix side,
 * because its four string pointers are 32-bit in the former and 64-bit in the
 * latter. The layout is otherwise identical:
 *
 *   offset  0  Signature1, Signature2, Version, VendorId, ProductId   (16 bytes)
 *   offset 16  Manufacturer, ManufacturerId, Description, SerialNumber
 *   offset 48  MaxPower .. PowerSaveEnableH                            (PE, 112 bytes)
 *   offset 56  MaxPower .. PowerSaveEnableH                            (Unix, 120 bytes)
 *
 * A byte-wise copy of the trailing part is therefore enough, and it avoids
 * making any assumption about the exact field list.
 */
#define PROGRAM_DATA_PE_HEADER 32
#define PROGRAM_DATA_UNIX_HEADER 48

static void program_data_from_pe( FT_PROGRAM_DATA *dst, const void *src, SIZE_T src_size )
{
    const char *in = src;
    UINT32 ptr;

    memset( dst, 0, sizeof(*dst) );

    /* common prologue, up to and including ProductId */
    memcpy( dst, in, min( src_size, (SIZE_T)16 ));

    memcpy( &ptr, in + 16, sizeof(ptr) );
    dst->Manufacturer = (char *)(ULONG_PTR)ptr;
    memcpy( &ptr, in + 20, sizeof(ptr) );
    dst->ManufacturerId = (char *)(ULONG_PTR)ptr;
    memcpy( &ptr, in + 24, sizeof(ptr) );
    dst->Description = (char *)(ULONG_PTR)ptr;
    memcpy( &ptr, in + 28, sizeof(ptr) );
    dst->SerialNumber = (char *)(ULONG_PTR)ptr;

    if (src_size > PROGRAM_DATA_PE_HEADER)
        memcpy( (char *)dst + PROGRAM_DATA_UNIX_HEADER, in + PROGRAM_DATA_PE_HEADER,
                min( src_size - PROGRAM_DATA_PE_HEADER,
                     sizeof(*dst) - PROGRAM_DATA_UNIX_HEADER ));
}

static void program_data_to_pe( void *dst, SIZE_T dst_size, const FT_PROGRAM_DATA *src )
{
    char *out = dst;

    if (dst_size < PROGRAM_DATA_PE_HEADER) return;

    memcpy( out, src, 16 );

    *(UINT32 *)(out + 16) = (UINT32)(ULONG_PTR)src->Manufacturer;
    *(UINT32 *)(out + 20) = (UINT32)(ULONG_PTR)src->ManufacturerId;
    *(UINT32 *)(out + 24) = (UINT32)(ULONG_PTR)src->Description;
    *(UINT32 *)(out + 28) = (UINT32)(ULONG_PTR)src->SerialNumber;

    memcpy( out + PROGRAM_DATA_PE_HEADER, (const char *)src + PROGRAM_DATA_UNIX_HEADER,
            min( dst_size - PROGRAM_DATA_PE_HEADER,
                 sizeof(*src) - PROGRAM_DATA_UNIX_HEADER ));
}

/*
 * FT_DEVICE_LIST_INFO_NODE is 96 bytes on the PE side and 104 bytes on the
 * Unix side. The only difference is the trailing handle.
 */
#define DEVICE_INFO_NODE_PE_SIZE 96
#define DEVICE_INFO_NODE_FIELDS_SIZE offsetof( FT_DEVICE_LIST_INFO_NODE, ftHandle )

static void device_info_list_to_pe( void *dst, const FT_DEVICE_LIST_INFO_NODE *src, unsigned int count )
{
    char *out = dst;
    unsigned int i;

    for (i = 0; i < count; i++)
    {
        memset( out, 0, DEVICE_INFO_NODE_PE_SIZE );
        memcpy( out, &src[i], min( (SIZE_T)DEVICE_INFO_NODE_FIELDS_SIZE, sizeof(src[i]) ) );
        *(UINT32 *)(out + DEVICE_INFO_NODE_FIELDS_SIZE) = (UINT32)id_from_handle( src[i].ftHandle );
        out += DEVICE_INFO_NODE_PE_SIZE;
    }
}

/*
 * Parameter helpers. Arguments are read from args[] in declaration order,
 * every slot being 8 bytes wide, so both word sizes agree on the layout.
 */

static inline void *arg_ptr( const struct ftd2xx_params *p, unsigned int i )
{
    return (void *)(ULONG_PTR)p->args[i];
}

static inline DWORD arg_dword( const struct ftd2xx_params *p, unsigned int i )
{
    return (DWORD)p->args[i];
}

static inline LONG arg_long( const struct ftd2xx_params *p, unsigned int i )
{
    return (LONG)p->args[i];
}

static inline BOOL arg_bool( const struct ftd2xx_params *p, unsigned int i )
{
    return (BOOL)p->args[i];
}

static inline UCHAR arg_uchar( const struct ftd2xx_params *p, unsigned int i )
{
    return (UCHAR)p->args[i];
}

static inline USHORT arg_ushort( const struct ftd2xx_params *p, unsigned int i )
{
    return (USHORT)p->args[i];
}

/* the handle slot is a 32-bit id in the low half of the 64-bit argument */
static inline FT_HANDLE arg_handle( const struct ftd2xx_params *p, unsigned int i )
{
    return handle_from_id( p->args[i] );
}

static inline UINT64 arg_id( const struct ftd2xx_params *p, unsigned int i )
{
    return p->args[i];
}

static inline void set_status( struct ftd2xx_params *p, UINT64 status )
{
    p->ret = status;
}


static NTSTATUS process_attach( void *args )
{
    return STATUS_SUCCESS;
}

static NTSTATUS process_detach( void *args )
{
    unsigned int i;

    for (i = 0; i < handle_count; i++)
        if (handle_used[i] && handle_table[i]) FT_Close( handle_table[i] );
    free( handle_table );
    free( handle_used );
    handle_table = NULL;
    handle_used = NULL;
    handle_count = handle_size = 0;
    return STATUS_SUCCESS;
}

static NTSTATUS set_vid_pid( void *args )
{
    struct ftd2xx_params *p = args;

    set_status( p, FT_SetVIDPID( arg_dword( p, 0 ), arg_dword( p, 1 )));
    return STATUS_SUCCESS;
}

static NTSTATUS create_device_info_list( void *args )
{
    struct ftd2xx_params *p = args;
    DWORD count = 0;
    FT_STATUS status;

    status = FT_CreateDeviceInfoList( &count );
    if (status == FT_OK) *(UINT32 *)arg_ptr( p, 0 ) = count;
    set_status( p, status );
    return STATUS_SUCCESS;
}

static NTSTATUS get_device_info_list( void *args )
{
    struct ftd2xx_params *p = args;
    UINT32 *count = arg_ptr( p, 1 );
    FT_DEVICE_LIST_INFO_NODE *list;
    DWORD n = count ? *count : 0;
    FT_STATUS status;

    if (!n)
    {
        set_status( p, FT_GetDeviceInfoList( NULL, count ));
        return STATUS_SUCCESS;
    }

    if (!(list = calloc( n, sizeof(*list) )))
    {
        set_status( p, FT_INSUFFICIENT_RESOURCES );
        return STATUS_SUCCESS;
    }

    while (1)
    {
        /* the caller's buffer holds at most n entries, never let the library write past it */
        DWORD avail = n;

        status = FT_GetDeviceInfoList( list, &avail );
        if (status != FT_OK || avail <= n) { *count = avail; break; }
        {
            FT_DEVICE_LIST_INFO_NODE *tmp = realloc( list, avail * sizeof(*list) );
            if (!tmp) { status = FT_INSUFFICIENT_RESOURCES; break; }
            list = tmp;
            memset( list + n, 0, (avail - n) * sizeof(*list) );
            n = avail;
        }
    }

    if (status == FT_OK && *count)
        device_info_list_to_pe( arg_ptr( p, 0 ), list, *count );
    free( list );
    set_status( p, status );
    return STATUS_SUCCESS;
}

static NTSTATUS get_device_info_detail( void *args )
{
    struct ftd2xx_params *p = args;
    FT_DEVICE_LIST_INFO_NODE node;
    UINT32 id = 0;
    FT_STATUS status;

    memset( &node, 0, sizeof(node) );
    status = FT_GetDeviceInfoDetail( arg_dword( p, 0 ), arg_ptr( p, 1 ), arg_ptr( p, 2 ),
                                      arg_ptr( p, 3 ), arg_ptr( p, 4 ), arg_ptr( p, 5 ),
                                      arg_ptr( p, 6 ), (FT_HANDLE *)&node.ftHandle );
    if (status == FT_OK)
    {
        id = (UINT32)id_from_handle( node.ftHandle );
        if (arg_ptr( p, 7 )) *(UINT32 *)arg_ptr( p, 7 ) = id;
    }
    set_status( p, status );
    return STATUS_SUCCESS;
}

static NTSTATUS list_devices( void *args )
{
    struct ftd2xx_params *p = args;

    set_status( p, FT_ListDevices( arg_ptr( p, 0 ), arg_ptr( p, 1 ), arg_dword( p, 2 )));
    return STATUS_SUCCESS;
}

static NTSTATUS open_device( void *args )
{
    struct ftd2xx_params *p = args;
    FT_HANDLE handle = NULL;
    FT_STATUS status;

    status = FT_Open( arg_long( p, 0 ), &handle );
    if (status == FT_OK) *(UINT32 *)arg_ptr( p, 1 ) = (UINT32)id_from_handle( handle );
    set_status( p, status );
    return STATUS_SUCCESS;
}

static NTSTATUS open_ex( void *args )
{
    struct ftd2xx_params *p = args;
    FT_HANDLE handle = NULL;
    FT_STATUS status;

    status = FT_OpenEx( arg_ptr( p, 0 ), arg_dword( p, 1 ), &handle );
    if (status == FT_OK) *(UINT32 *)arg_ptr( p, 2 ) = (UINT32)id_from_handle( handle );
    set_status( p, status );
    return STATUS_SUCCESS;
}

static NTSTATUS close_device( void *args )
{
    struct ftd2xx_params *p = args;
    UINT64 id = arg_id( p, 0 );
    FT_STATUS status = FT_Close( arg_handle( p, 0 ));

    if (status == FT_OK) remove_handle( id );
    set_status( p, status );
    return STATUS_SUCCESS;
}

static NTSTATUS read_device( void *args )
{
    struct ftd2xx_params *p = args;

    set_status( p, FT_Read( arg_handle( p, 0 ), arg_ptr( p, 1 ), arg_dword( p, 2 ), arg_ptr( p, 3 )));
    return STATUS_SUCCESS;
}

static NTSTATUS write_device( void *args )
{
    struct ftd2xx_params *p = args;

    set_status( p, FT_Write( arg_handle( p, 0 ), arg_ptr( p, 1 ), arg_dword( p, 2 ), arg_ptr( p, 3 )));
    return STATUS_SUCCESS;
}

static NTSTATUS reset_device( void *args )
{
    struct ftd2xx_params *p = args;

    set_status( p, FT_ResetDevice( arg_handle( p, 0 )));
    return STATUS_SUCCESS;
}

static NTSTATUS set_baud_rate( void *args )
{
    struct ftd2xx_params *p = args;

    set_status( p, FT_SetBaudRate( arg_handle( p, 0 ), arg_dword( p, 1 )));
    return STATUS_SUCCESS;
}

static NTSTATUS set_divisor( void *args )
{
    struct ftd2xx_params *p = args;

    set_status( p, FT_SetDivisor( arg_handle( p, 0 ), arg_ushort( p, 1 )));
    return STATUS_SUCCESS;
}

static NTSTATUS set_data_characteristics( void *args )
{
    struct ftd2xx_params *p = args;

    set_status( p, FT_SetDataCharacteristics( arg_handle( p, 0 ), arg_uchar( p, 1 ),
                                               arg_uchar( p, 2 ), arg_uchar( p, 3 )));
    return STATUS_SUCCESS;
}

static NTSTATUS set_flow_control( void *args )
{
    struct ftd2xx_params *p = args;

    set_status( p, FT_SetFlowControl( arg_handle( p, 0 ), arg_ushort( p, 1 ),
                                       arg_uchar( p, 2 ), arg_uchar( p, 3 )));
    return STATUS_SUCCESS;
}

static NTSTATUS set_dtr( void *args )
{
    struct ftd2xx_params *p = args;

    set_status( p, FT_SetDtr( arg_handle( p, 0 )));
    return STATUS_SUCCESS;
}

static NTSTATUS clr_dtr( void *args )
{
    struct ftd2xx_params *p = args;

    set_status( p, FT_ClrDtr( arg_handle( p, 0 )));
    return STATUS_SUCCESS;
}

static NTSTATUS set_rts( void *args )
{
    struct ftd2xx_params *p = args;

    set_status( p, FT_SetRts( arg_handle( p, 0 )));
    return STATUS_SUCCESS;
}

static NTSTATUS clr_rts( void *args )
{
    struct ftd2xx_params *p = args;

    set_status( p, FT_ClrRts( arg_handle( p, 0 )));
    return STATUS_SUCCESS;
}

static NTSTATUS set_break_on( void *args )
{
    struct ftd2xx_params *p = args;

    set_status( p, FT_SetBreakOn( arg_handle( p, 0 )));
    return STATUS_SUCCESS;
}

static NTSTATUS set_break_off( void *args )
{
    struct ftd2xx_params *p = args;

    set_status( p, FT_SetBreakOff( arg_handle( p, 0 )));
    return STATUS_SUCCESS;
}

static NTSTATUS get_modem_status( void *args )
{
    struct ftd2xx_params *p = args;

    set_status( p, FT_GetModemStatus( arg_handle( p, 0 ), arg_ptr( p, 1 )));
    return STATUS_SUCCESS;
}

static NTSTATUS set_chars( void *args )
{
    struct ftd2xx_params *p = args;

    set_status( p, FT_SetChars( arg_handle( p, 0 ), arg_uchar( p, 1 ), arg_uchar( p, 2 ),
                                 arg_uchar( p, 3 ), arg_uchar( p, 4 )));
    return STATUS_SUCCESS;
}

static NTSTATUS purge( void *args )
{
    struct ftd2xx_params *p = args;

    set_status( p, FT_Purge( arg_handle( p, 0 ), (ULONG)p->args[1] ));
    return STATUS_SUCCESS;
}

static NTSTATUS set_timeouts( void *args )
{
    struct ftd2xx_params *p = args;

    set_status( p, FT_SetTimeouts( arg_handle( p, 0 ), arg_dword( p, 1 ), arg_dword( p, 2 )));
    return STATUS_SUCCESS;
}

static NTSTATUS get_queue_status( void *args )
{
    struct ftd2xx_params *p = args;

    set_status( p, FT_GetQueueStatus( arg_handle( p, 0 ), arg_ptr( p, 1 )));
    return STATUS_SUCCESS;
}

static NTSTATUS get_status( void *args )
{
    struct ftd2xx_params *p = args;

    set_status( p, FT_GetStatus( arg_handle( p, 0 ), arg_ptr( p, 1 ), arg_ptr( p, 2 ), arg_ptr( p, 3 )));
    return STATUS_SUCCESS;
}

static NTSTATUS set_latency_timer( void *args )
{
    struct ftd2xx_params *p = args;

    set_status( p, FT_SetLatencyTimer( arg_handle( p, 0 ), arg_uchar( p, 1 )));
    return STATUS_SUCCESS;
}

static NTSTATUS get_latency_timer( void *args )
{
    struct ftd2xx_params *p = args;

    set_status( p, FT_GetLatencyTimer( arg_handle( p, 0 ), arg_ptr( p, 1 )));
    return STATUS_SUCCESS;
}

static NTSTATUS set_bit_mode( void *args )
{
    struct ftd2xx_params *p = args;

    set_status( p, FT_SetBitMode( arg_handle( p, 0 ), arg_uchar( p, 1 ), arg_uchar( p, 2 )));
    return STATUS_SUCCESS;
}

static NTSTATUS get_bit_mode( void *args )
{
    struct ftd2xx_params *p = args;

    set_status( p, FT_GetBitMode( arg_handle( p, 0 ), arg_ptr( p, 1 )));
    return STATUS_SUCCESS;
}

static NTSTATUS set_usb_parameters( void *args )
{
    struct ftd2xx_params *p = args;

    set_status( p, FT_SetUSBParameters( arg_handle( p, 0 ), (ULONG)p->args[1], (ULONG)p->args[2] ));
    return STATUS_SUCCESS;
}

static NTSTATUS erase_ee( void *args )
{
    struct ftd2xx_params *p = args;

    set_status( p, FT_EraseEE( arg_handle( p, 0 )));
    return STATUS_SUCCESS;
}

static NTSTATUS read_ee( void *args )
{
    struct ftd2xx_params *p = args;

    set_status( p, FT_ReadEE( arg_handle( p, 0 ), arg_dword( p, 1 ), arg_ptr( p, 2 )));
    return STATUS_SUCCESS;
}

static NTSTATUS write_ee( void *args )
{
    struct ftd2xx_params *p = args;

    set_status( p, FT_WriteEE( arg_handle( p, 0 ), arg_dword( p, 1 ), (WORD)p->args[2] ));
    return STATUS_SUCCESS;
}

static NTSTATUS ee_ua_read( void *args )
{
    struct ftd2xx_params *p = args;

    set_status( p, FT_EE_UARead( arg_handle( p, 0 ), arg_ptr( p, 1 ), arg_dword( p, 2 ), arg_ptr( p, 3 )));
    return STATUS_SUCCESS;
}

static NTSTATUS ee_ua_size( void *args )
{
    struct ftd2xx_params *p = args;

    set_status( p, FT_EE_UASize( arg_handle( p, 0 ), arg_ptr( p, 1 )));
    return STATUS_SUCCESS;
}

static NTSTATUS ee_ua_write( void *args )
{
    struct ftd2xx_params *p = args;

    set_status( p, FT_EE_UAWrite( arg_handle( p, 0 ), arg_ptr( p, 1 ), arg_dword( p, 2 )));
    return STATUS_SUCCESS;
}

static NTSTATUS ee_program( void *args )
{
    struct ftd2xx_params *p = args;
    FT_PROGRAM_DATA data;

    program_data_from_pe( &data, arg_ptr( p, 1 ), 160 );
    set_status( p, FT_EE_Program( arg_handle( p, 0 ), &data ));
    return STATUS_SUCCESS;
}

static NTSTATUS ee_read( void *args )
{
    struct ftd2xx_params *p = args;
    FT_PROGRAM_DATA data;
    FT_STATUS status;

    program_data_from_pe( &data, arg_ptr( p, 1 ), 160 );
    status = FT_EE_Read( arg_handle( p, 0 ), &data );
    if (status == FT_OK) program_data_to_pe( arg_ptr( p, 1 ), 160, &data );
    set_status( p, status );
    return STATUS_SUCCESS;
}

static NTSTATUS ee_program_ex( void *args )
{
    struct ftd2xx_params *p = args;
    FT_PROGRAM_DATA data;

    program_data_from_pe( &data, arg_ptr( p, 1 ), 160 );
    set_status( p, FT_EE_ProgramEx( arg_handle( p, 0 ), &data, arg_ptr( p, 2 ), arg_ptr( p, 3 ),
                                     arg_ptr( p, 4 ), arg_ptr( p, 5 )));
    return STATUS_SUCCESS;
}

static NTSTATUS ee_read_ex( void *args )
{
    struct ftd2xx_params *p = args;
    FT_PROGRAM_DATA data;
    FT_STATUS status;

    program_data_from_pe( &data, arg_ptr( p, 1 ), 160 );
    status = FT_EE_ReadEx( arg_handle( p, 0 ), &data, arg_ptr( p, 2 ), arg_ptr( p, 3 ),
                            arg_ptr( p, 4 ), arg_ptr( p, 5 ));
    if (status == FT_OK) program_data_to_pe( arg_ptr( p, 1 ), 160, &data );
    set_status( p, status );
    return STATUS_SUCCESS;
}

static NTSTATUS get_device_info( void *args )
{
    struct ftd2xx_params *p = args;
    FT_HANDLE handle = NULL;
    FT_STATUS status;

    status = FT_GetDeviceInfo( arg_handle( p, 0 ), arg_ptr( p, 1 ), arg_ptr( p, 2 ),
                                arg_ptr( p, 3 ), arg_ptr( p, 4 ), &handle );
    if (status == FT_OK && arg_ptr( p, 5 )) *(UINT32 *)arg_ptr( p, 5 ) = (UINT32)id_from_handle( handle );
    set_status( p, status );
    return STATUS_SUCCESS;
}

static NTSTATUS stop_in_task( void *args )
{
    struct ftd2xx_params *p = args;

    set_status( p, FT_StopInTask( arg_handle( p, 0 )));
    return STATUS_SUCCESS;
}

static NTSTATUS restart_in_task( void *args )
{
    struct ftd2xx_params *p = args;

    set_status( p, FT_RestartInTask( arg_handle( p, 0 )));
    return STATUS_SUCCESS;
}

static NTSTATUS get_driver_version( void *args )
{
    struct ftd2xx_params *p = args;

    set_status( p, FT_GetDriverVersion( arg_handle( p, 0 ), arg_ptr( p, 1 )));
    return STATUS_SUCCESS;
}

static NTSTATUS get_library_version( void *args )
{
    struct ftd2xx_params *p = args;

    set_status( p, FT_GetLibraryVersion( arg_ptr( p, 0 )));
    return STATUS_SUCCESS;
}

static NTSTATUS set_event_notification( void *args )
{
    struct ftd2xx_params *p = args;

    set_status( p, FT_SetEventNotification( arg_handle( p, 0 ), arg_dword( p, 1 ), arg_ptr( p, 2 )));
    return STATUS_SUCCESS;
}

static NTSTATUS w32_create_file( void *args )
{
    struct ftd2xx_params *p = args;
    FT_HANDLE handle;

    handle = FT_W32_CreateFile( arg_ptr( p, 0 ), arg_dword( p, 1 ), arg_dword( p, 2 ), arg_ptr( p, 3 ),
                                 arg_dword( p, 4 ), arg_dword( p, 5 ), arg_ptr( p, 6 ));
    if (handle && handle != INVALID_HANDLE_VALUE)
        *(UINT32 *)arg_ptr( p, 6 ) = (UINT32)id_from_handle( handle );
    else
        set_status( p, FT_DEVICE_NOT_OPENED );
    return STATUS_SUCCESS;
}

static NTSTATUS w32_close_handle( void *args )
{
    struct ftd2xx_params *p = args;
    UINT64 id = arg_id( p, 0 );
    FT_STATUS status = FT_W32_CloseHandle( arg_handle( p, 0 ));

    if (status) remove_handle( id );
    set_status( p, status );
    return STATUS_SUCCESS;
}

static NTSTATUS w32_read_file( void *args )
{
    struct ftd2xx_params *p = args;

    set_status( p, FT_W32_ReadFile( arg_handle( p, 0 ), arg_ptr( p, 1 ), arg_dword( p, 2 ),
                                     arg_ptr( p, 3 ), arg_ptr( p, 4 )));
    return STATUS_SUCCESS;
}

static NTSTATUS w32_write_file( void *args )
{
    struct ftd2xx_params *p = args;

    set_status( p, FT_W32_WriteFile( arg_handle( p, 0 ), arg_ptr( p, 1 ), arg_dword( p, 2 ),
                                      arg_ptr( p, 3 ), arg_ptr( p, 4 )));
    return STATUS_SUCCESS;
}

static NTSTATUS w32_get_overlapped_result( void *args )
{
    struct ftd2xx_params *p = args;

    set_status( p, FT_W32_GetOverlappedResult( arg_handle( p, 0 ), arg_ptr( p, 1 ),
                                                arg_ptr( p, 2 ), arg_bool( p, 3 )));
    return STATUS_SUCCESS;
}

static NTSTATUS w32_clear_comm_break( void *args )
{
    struct ftd2xx_params *p = args;

    set_status( p, FT_W32_ClearCommBreak( arg_handle( p, 0 )));
    return STATUS_SUCCESS;
}

static NTSTATUS w32_clear_comm_error( void *args )
{
    struct ftd2xx_params *p = args;

    set_status( p, FT_W32_ClearCommError( arg_handle( p, 0 ), arg_ptr( p, 1 ), arg_ptr( p, 2 )));
    return STATUS_SUCCESS;
}

static NTSTATUS w32_escape_comm_function( void *args )
{
    struct ftd2xx_params *p = args;

    set_status( p, FT_W32_EscapeCommFunction( arg_handle( p, 0 ), arg_dword( p, 1 )));
    return STATUS_SUCCESS;
}

static NTSTATUS w32_get_comm_modem_status( void *args )
{
    struct ftd2xx_params *p = args;

    set_status( p, FT_W32_GetCommModemStatus( arg_handle( p, 0 ), arg_ptr( p, 1 )));
    return STATUS_SUCCESS;
}

static NTSTATUS w32_get_comm_state( void *args )
{
    struct ftd2xx_params *p = args;

    set_status( p, FT_W32_GetCommState( arg_handle( p, 0 ), arg_ptr( p, 1 )));
    return STATUS_SUCCESS;
}

static NTSTATUS w32_get_comm_timeouts( void *args )
{
    struct ftd2xx_params *p = args;

    set_status( p, FT_W32_GetCommTimeouts( arg_handle( p, 0 ), arg_ptr( p, 1 )));
    return STATUS_SUCCESS;
}

static NTSTATUS w32_get_last_error( void *args )
{
    struct ftd2xx_params *p = args;

    set_status( p, FT_W32_GetLastError( arg_handle( p, 0 )));
    return STATUS_SUCCESS;
}

static NTSTATUS w32_purge_comm( void *args )
{
    struct ftd2xx_params *p = args;

    set_status( p, FT_W32_PurgeComm( arg_handle( p, 0 ), arg_dword( p, 1 )));
    return STATUS_SUCCESS;
}

static NTSTATUS w32_set_comm_break( void *args )
{
    struct ftd2xx_params *p = args;

    set_status( p, FT_W32_SetCommBreak( arg_handle( p, 0 )));
    return STATUS_SUCCESS;
}

static NTSTATUS w32_set_comm_mask( void *args )
{
    struct ftd2xx_params *p = args;

    set_status( p, FT_W32_SetCommMask( arg_handle( p, 0 ), arg_dword( p, 1 )));
    return STATUS_SUCCESS;
}

static NTSTATUS w32_set_comm_state( void *args )
{
    struct ftd2xx_params *p = args;

    set_status( p, FT_W32_SetCommState( arg_handle( p, 0 ), arg_ptr( p, 1 )));
    return STATUS_SUCCESS;
}

static NTSTATUS w32_set_comm_timeouts( void *args )
{
    struct ftd2xx_params *p = args;

    set_status( p, FT_W32_SetCommTimeouts( arg_handle( p, 0 ), arg_ptr( p, 1 )));
    return STATUS_SUCCESS;
}

static NTSTATUS w32_setup_comm( void *args )
{
    struct ftd2xx_params *p = args;

    set_status( p, FT_W32_SetupComm( arg_handle( p, 0 ), arg_dword( p, 1 ), arg_dword( p, 2 )));
    return STATUS_SUCCESS;
}

static NTSTATUS w32_wait_comm_event( void *args )
{
    struct ftd2xx_params *p = args;

    set_status( p, FT_W32_WaitCommEvent( arg_handle( p, 0 ), arg_ptr( p, 1 ), arg_ptr( p, 2 )));
    return STATUS_SUCCESS;
}

const unixlib_entry_t __wine_unix_call_funcs[] =
{
    process_attach,
    process_detach,
    set_vid_pid,
    create_device_info_list,
    get_device_info_list,
    get_device_info_detail,
    list_devices,
    open_device,
    open_ex,
    close_device,
    read_device,
    write_device,
    reset_device,
    set_baud_rate,
    set_divisor,
    set_data_characteristics,
    set_flow_control,
    set_dtr,
    clr_dtr,
    set_rts,
    clr_rts,
    set_break_on,
    set_break_off,
    get_modem_status,
    set_chars,
    purge,
    set_timeouts,
    get_queue_status,
    get_status,
    set_latency_timer,
    get_latency_timer,
    set_bit_mode,
    get_bit_mode,
    set_usb_parameters,
    erase_ee,
    read_ee,
    write_ee,
    ee_ua_read,
    ee_ua_size,
    ee_ua_write,
    ee_program,
    ee_read,
    ee_program_ex,
    ee_read_ex,
    get_device_info,
    stop_in_task,
    restart_in_task,
    get_driver_version,
    get_library_version,
    set_event_notification,
    w32_create_file,
    w32_close_handle,
    w32_read_file,
    w32_write_file,
    w32_get_overlapped_result,
    w32_clear_comm_break,
    w32_clear_comm_error,
    w32_escape_comm_function,
    w32_get_comm_modem_status,
    w32_get_comm_state,
    w32_get_comm_timeouts,
    w32_get_last_error,
    w32_purge_comm,
    w32_set_comm_break,
    w32_set_comm_mask,
    w32_set_comm_state,
    w32_set_comm_timeouts,
    w32_setup_comm,
    w32_wait_comm_event,
};

C_ASSERT( ARRAYSIZE(__wine_unix_call_funcs) == unix_funcs_count );

#ifdef _WIN64
/* The parameter block uses fixed 8-byte slots, so the same entry points work for WoW64. */
const unixlib_entry_t __wine_unix_call_wow64_funcs[] =
{
    process_attach,
    process_detach,
    set_vid_pid,
    create_device_info_list,
    get_device_info_list,
    get_device_info_detail,
    list_devices,
    open_device,
    open_ex,
    close_device,
    read_device,
    write_device,
    reset_device,
    set_baud_rate,
    set_divisor,
    set_data_characteristics,
    set_flow_control,
    set_dtr,
    clr_dtr,
    set_rts,
    clr_rts,
    set_break_on,
    set_break_off,
    get_modem_status,
    set_chars,
    purge,
    set_timeouts,
    get_queue_status,
    get_status,
    set_latency_timer,
    get_latency_timer,
    set_bit_mode,
    get_bit_mode,
    set_usb_parameters,
    erase_ee,
    read_ee,
    write_ee,
    ee_ua_read,
    ee_ua_size,
    ee_ua_write,
    ee_program,
    ee_read,
    ee_program_ex,
    ee_read_ex,
    get_device_info,
    stop_in_task,
    restart_in_task,
    get_driver_version,
    get_library_version,
    set_event_notification,
    w32_create_file,
    w32_close_handle,
    w32_read_file,
    w32_write_file,
    w32_get_overlapped_result,
    w32_clear_comm_break,
    w32_clear_comm_error,
    w32_escape_comm_function,
    w32_get_comm_modem_status,
    w32_get_comm_state,
    w32_get_comm_timeouts,
    w32_get_last_error,
    w32_purge_comm,
    w32_set_comm_break,
    w32_set_comm_mask,
    w32_set_comm_state,
    w32_set_comm_timeouts,
    w32_setup_comm,
    w32_wait_comm_event,
};

C_ASSERT( ARRAYSIZE(__wine_unix_call_wow64_funcs) == unix_funcs_count );
#endif
