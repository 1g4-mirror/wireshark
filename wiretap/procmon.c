/** procmon.c
 *
 * Implements reading of MS Procmon files
 * Used a lot of information from https://github.com/eronnen/procmon-parser
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#define WS_LOG_DOMAIN LOG_DOMAIN_WIRETAP

#include "procmon.h"
#include "file_wrappers.h"
#include "wtap-int.h"
#include "pcapng_module.h"

#include <wsutil/buffer.h>


typedef struct procmon_header_s {
    uint32_t signature;                 // Magic Signature - 'PML_'
    uint32_t version;                   // Version of the PML file. 9 in the current version.
    uint32_t system_bitness;            // System bitness: 1 if the system is 64 bit, 0 otherwise.
    uint16_t computer_name[16];         // Name of the computer (that did the capture).
    uint16_t system_root_path[260];     // System root path (e.g. "C:\Windows").
    uint32_t num_events;                // Total number of events in the log file.
    uint64_t unused;                    // ? (seems to be unused)
    uint64_t start_events_offset;       // File offset to the start of the events array.
    uint64_t array_offsets_offset;      // File offset to an array of offsets to all the events.
    uint64_t process_array_offset;      // File offset to the array of processes.
    uint64_t string_array_offset;       // File offset to the array of strings.
    uint64_t icon_array_offset;         // File offset to the icons array.
    uint64_t maximum_user_address;      // SYSTEM_INFO.lpMaximumApplicationAddress: Maximum User Address
    uint32_t os_version_info_size;      // OSVERSIONINFOEXW.dwOSVersionInfoSize: sizeof(OSVERSIONINFOEXW)
    uint32_t major_version;             // OSVERSIONINFOEXW.dwMajorVersion: Major version number of the operating system.
    uint32_t minor_version;             // OSVERSIONINFOEXW.dwMinorVersion: Minor version number of the operating system.
    uint32_t build_number;              // OSVERSIONINFOEXW.dwBuildNumber: Build number of the operating system.
    uint32_t platform_id;               // OSVERSIONINFOEXW.dwPlatformId: Operating system platform.
    uint16_t csd_version[128];          // OSVERSIONINFOEXW.szCSDVersion: Indicates the latest Service Pack installed.
    uint16_t service_pack_major;        // OSVERSIONINFOEXW.wServicePackMajor: Major version number of the latest Service Pack.
    uint16_t service_pack_minor;        // OSVERSIONINFOEXW.wServicePackMinor: Minor version number of the latest Service Pack.
    uint16_t suite_mask;                // OSVERSIONINFOEXW.wSuiteMask: Bit mask that identifies the product suites available.
    uint8_t product_type;               // OSVERSIONINFOEXW.wProductType: Additional information about the system.
    uint8_t version_reserved;           // OSVERSIONINFOEXW.wReserved: Reserved for future use.
    uint32_t num_processors;            // SYSTEM_INFO.dwNumberOfProcessors: Number of logical processors.
    uint64_t total_physical_memory;     // MEMORYSTATUSEX.ullTotalPhys: Total physical memory (in bytes).
    uint64_t start_events_offset_dup;   // File offset to the start of the events array (again).
    uint64_t host_port_array_offset;    // File offset to hosts and ports arrays.

} procmon_header_t;

typedef enum {
    PROCMON_EVENT_TYPE_UNKNOWN = 0,
    PROCMON_EVENT_TYPE_PROCESS = 1,
    PROCMON_EVENT_TYPE_REGISTRY = 2,
    PROCMON_EVENT_TYPE_FILE_SYSTEM = 3,
    PROCMON_EVENT_TYPE_PROFILING = 4,
    PROCMON_EVENT_TYPE_NETWORK = 5,
} procmon_event_class_type_t;

typedef struct procmon_event_header_s {
    uint32_t process_index;             // The index to the process of the event.
    uint32_t thread_id;                 // Thread Id.
    uint32_t event_class;               // Event class (of type procmon_event_class_type_t)
    uint16_t operation_type;            // Operation type (dependent on the event class)
    uint8_t  unknown[6];                // Unknown
    uint64_t duration;                  // Duration of the operation in 100 nanoseconds interval.
    uint64_t timestamp;                 // The time when the event was captured (in FILETIME format)
    uint32_t event_result;              // The value of the event result.
    uint16_t stack_trace_depth;         // The depth of the captured stack trace.
    uint16_t unknown3;                  // Unknown
    uint32_t details_size;              // The size of the specific detail structure (contains path and other details)
    uint32_t extra_details_offset;      // The offset from the start of the event to extra detail structure (not necessarily continuous with this structure).

} procmon_event_header_t;

#define COMMON_EVENT_STRUCT_SIZE        52

typedef struct procmon_event_s {
    procmon_event_header_t header;
    uint8_t* stack_trace_addresses;     // Array of stack trace addresses (size = header.stack_trace_depth * 4 or 8 bytes depending on system bitness)
    uint8_t* operation_details;         // A detail structure based on the operation type.
} procmon_event_t;

static int procmon_file_type_subtype = -1;

void register_procmon(void);

static bool procmon_read_event(FILE_T fh, const char* pathname, wtap_rec* rec, procmon_header_t* header, int* err, char** err_info)
{
    wtapng_block_t wblock;
    procmon_event_header_t event_header;
    unsigned char unknown_buffer[10];       //Spot to read unknown bytes of the header

    wblock.rec = rec;

    wblock.block = wtap_block_create(WTAP_BLOCK_SYSDIG_EVENT);

    wtap_setup_syscall_rec(wblock.rec);
    wblock.rec->rec_header.syscall_header.record_type = BLOCK_TYPE_SYSDIG_EVENT_V2;
    wblock.rec->presence_flags = WTAP_HAS_CAP_LEN /*|WTAP_HAS_INTERFACE_ID */;
    wblock.rec->tsprec = WTAP_TSPREC_NSEC;
    wblock.rec->rec_header.syscall_header.pathname = pathname;


    if (!wtap_read_bytes(fh, &event_header.process_index, sizeof event_header.process_index, err, err_info)) {
        ws_debug("Failed to read procmon process index");
        return false;
    }
    if (!wtap_read_bytes(fh, &event_header.thread_id, sizeof event_header.thread_id, err, err_info)) {
        ws_debug("Failed to read procmon thread id");
        return false;
    }
    if (!wtap_read_bytes(fh, &event_header.event_class, sizeof event_header.event_class, err, err_info)) {
        ws_debug("Failed to read procmon event class");
        return false;
    }
    if (!wtap_read_bytes(fh, &event_header.operation_type, sizeof event_header.operation_type, err, err_info)) {
        ws_debug("Failed to read procmon operation type");
        return false;
    }
    if (!wtap_read_bytes(fh, unknown_buffer, 6, err, err_info)) {
        ws_debug("Failed to read procmon unknown data");
        return false;
    }
    if (!wtap_read_bytes(fh, &event_header.duration, sizeof event_header.duration, err, err_info)) {
        ws_debug("Failed to read procmon duration");
        return false;
    }
    if (!wtap_read_bytes(fh, &event_header.timestamp, sizeof event_header.timestamp, err, err_info)) {
        ws_debug("Failed to read procmon timestamp");
        return false;
    }
    if (!wtap_read_bytes(fh, &event_header.event_result, sizeof event_header.event_result, err, err_info)) {
        ws_debug("Failed to read procmon event result");
        return false;
    }
    if (!wtap_read_bytes(fh, &event_header.stack_trace_depth, sizeof event_header.stack_trace_depth, err, err_info)) {
        ws_debug("Failed to read procmon stack trace depth");
        return false;
    }
    if (!wtap_read_bytes(fh, unknown_buffer, 2, err, err_info)) {
        ws_debug("Failed to read procmon unknown data");
        return false;
    }
    if (!wtap_read_bytes(fh, &event_header.details_size, sizeof event_header.details_size, err, err_info)) {
        ws_debug("Failed to read procmon details size");
        return false;
    }
    if (!wtap_read_bytes(fh, &event_header.extra_details_offset, sizeof event_header.extra_details_offset, err, err_info)) {
        ws_debug("Failed to read procmon stack details offset");
        return false;
    }

    /* Translate Procmon events into syscall events (for now) */
    wblock.rec->rec_header.syscall_header.byte_order = G_LITTLE_ENDIAN;

    wblock.rec->presence_flags |= WTAP_HAS_TS;
    filetime_to_nstime(&wblock.rec->ts, event_header.timestamp);

    wblock.rec->rec_header.syscall_header.cpu_id = event_header.process_index;
    wblock.rec->rec_header.syscall_header.flags = 0;
    wblock.rec->rec_header.syscall_header.thread_id = event_header.thread_id;
    wblock.rec->rec_header.syscall_header.event_len = 0;
    wblock.rec->rec_header.syscall_header.event_data_len = event_header.details_size;
    wblock.rec->rec_header.syscall_header.event_type = event_header.event_class;
    wblock.rec->rec_header.syscall_header.nparams = 0;


    /* Read (to currently ignore) stack trace data */
    int sizeof_stacktrace = event_header.stack_trace_depth * (header->system_bitness ? 8 : 4);
    char* test_stacktrace_data = g_malloc(sizeof_stacktrace);
    if (!wtap_read_bytes(fh, test_stacktrace_data, sizeof_stacktrace, err, err_info)) {
        ws_debug("Failed to read procmon stack trace data");
        return false;
    }
    g_free(test_stacktrace_data);

    if (!wtap_read_bytes_buffer(fh, &wblock.rec->data, event_header.details_size, err, err_info)) {
        ws_debug("Failed to read procmon detail data");
        return false;
    }

    if (event_header.extra_details_offset > 0)
    {
        int64_t current_offset = file_tell(fh);

        /* The extra details structure surprisingly can be separated from the event structure */
        int64_t real_details_offset = event_header.extra_details_offset - (COMMON_EVENT_STRUCT_SIZE + event_header.details_size + sizeof_stacktrace);
        if (file_seek(fh, real_details_offset, SEEK_CUR, err) == -1) {
            ws_debug("Failed to locate procmon extra details data");
            return false;
        }
        uint16_t extra_details_stream_size;
        if (!wtap_read_bytes(fh, &extra_details_stream_size, sizeof extra_details_stream_size, err, err_info)) {
            ws_debug("Failed to read procmon extra details offset");
            return false;
        }

        char* test_extra_details_data = g_malloc(extra_details_stream_size);
        if (!wtap_read_bytes(fh, test_extra_details_data, extra_details_stream_size, err, err_info)) {
            ws_debug("Failed to read procmon extra detail data");
            return false;
        }

        g_free(test_extra_details_data);

        /* If the extra data doesn't immediately follow the other data */
        if (real_details_offset != 0)
        {
            if (file_seek(fh, current_offset, SEEK_SET, err) == -1) {
                ws_debug("Failed to restore procmon event data location");
                return false;
            }
        }
    }

    /*
     * We return these to the caller in procmon_read().
     */
    wblock.internal = false;

    /*
     * We want dissectors (particularly packet_frame) to be able to
     * access packet comments and whatnot that are in the block. wblock->block
     * will be unref'd by procmon_seek_read(), so move the block to where
     * dissectors can find it.
     */
    wblock.rec->block = wblock.block;
    wblock.block = NULL;
    return true;
}

static bool procmon_read(wtap *wth, wtap_rec *rec,
    int *err, char **err_info, int64_t *data_offset)
{
    procmon_header_t* header = (procmon_header_t*)wth->priv;

    *data_offset = file_tell(wth->fh);
    ws_noisy("data_offset is %" PRId64, *data_offset);

    /* Stop processing one offset reaches past events */
    if (*data_offset >= (int64_t)header->array_offsets_offset)
    {
        ws_debug("end of events");
        return false;
    }

    if (*data_offset+COMMON_EVENT_STRUCT_SIZE >= (int64_t)header->array_offsets_offset) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("procmon: No enough room for event content at offset %"  PRIi64, *data_offset);
        return false;
    }

    return procmon_read_event(wth->fh, wth->pathname, rec, header, err, err_info);
}

static bool procmon_seek_read(wtap *wth, int64_t seek_off, wtap_rec *rec,
    int *err, char **err_info)
{
    procmon_header_t* header = (procmon_header_t*)wth->priv;

    /* seek to the right file position */
    if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) < 0) {
        return false;   /* Seek error */
    }
    ws_noisy("reading at offset %" PRIu64, seek_off);

    return procmon_read_event(wth->random_fh, wth->pathname, rec, header, err, err_info);
}

static const uint8_t procmon_magic[] = { 'P', 'M', 'L', '_' };

wtap_open_return_val procmon_open(wtap *wth, int *err _U_, char **err_info _U_)
{
    procmon_header_t* header = g_new(procmon_header_t, 1);

    ws_debug("opening file");
    /*
     * First, try to read the procmon header.
     */
    if (!wtap_read_bytes_or_eof(wth->fh, header, sizeof(procmon_header_t), err, err_info))
    {
        g_free(header);
        ws_debug("wtap_read_bytes_or_eof() failed, err = %d.", *err);
        if (*err == 0 || *err == WTAP_ERR_SHORT_READ) {
            /*
             * Short read or EOF.
             *
             * We're reading this as part of an open, so
             * the file is too short to be a procmon file.
             */
            *err = 0;
            g_free(*err_info);
            *err_info = NULL;
            return WTAP_OPEN_NOT_MINE;
        }
        return WTAP_OPEN_ERROR;
    }

    if (memcmp(&header->signature, procmon_magic, sizeof(procmon_magic)))
    {
        g_free(header);
        return WTAP_OPEN_NOT_MINE;
    }

    wth->meta_events = g_array_new(false, false, sizeof(wtap_block_t));

    wth->priv = header;
    wth->file_type_subtype = procmon_file_type_subtype;
    wth->file_encap = WTAP_ENCAP_PROCMON;

    wth->snapshot_length = 0;
    wth->file_tsprec = WTAP_TSPREC_SEC;

    wth->subtype_read = procmon_read;
    wth->subtype_seek_read = procmon_seek_read;

    return WTAP_OPEN_MINE;
}

/* Options for meta event blocks. */
static const struct supported_option_type meta_events_block_options_supported[] = {
    { OPT_COMMENT, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_CUSTOM_STR_COPY, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_CUSTOM_BIN_COPY, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_CUSTOM_STR_NO_COPY, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_CUSTOM_BIN_NO_COPY, MULTIPLE_OPTIONS_SUPPORTED }
};


static const struct supported_block_type procmon_blocks_supported[] = {

    /* Multiple blocks of meta evens.. */
    { WTAP_BLOCK_META_EVENT, MULTIPLE_BLOCKS_SUPPORTED, OPTION_TYPES_SUPPORTED(meta_events_block_options_supported) },

    /* Multiple custom blocks. */
    { WTAP_BLOCK_CUSTOM, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED },
};

static const struct file_type_subtype_info procmon_info = {
    "MS Procmon files", "procmon", NULL, NULL,
    false, BLOCKS_SUPPORTED(procmon_blocks_supported),
    NULL, NULL, NULL
};

void register_procmon(void)
{
    procmon_file_type_subtype = wtap_register_file_type_subtype(&procmon_info);

    /*
     * Register name for backwards compatibility with the
     * wtap_filetypes table in Lua.
     */
    wtap_register_backwards_compatibility_lua_name("Procmon", procmon_file_type_subtype);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
