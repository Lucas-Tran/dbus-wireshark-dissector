/* packet-dbus.c
 * Routines for D-Bus dissection
 * Copyright 2015, Lucas Hong Tran <hongtd2k@gmail.com>
 * Copyright 2012, Jakub Zawadzki <darkjames-ws@darkjames.pl>
 *
 * Protocol specification available at http://dbus.freedesktop.org/doc/dbus-specification.html
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define NEW_PROTO_TREE_API

#define DBUSDUMP_HDR_FIELD_EXT_PID_PATH 1
#define DBUS_BODY_PARSER_TESTING        1

#include "config.h"

#include <epan/packet.h>
#include <wiretap/wtap.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include "dbus-protocol.h"

#if DBUSDUMP_HDR_FIELD_EXT_PID_PATH
#include "dbus_hf_ext.h"
#endif


#define DEBUG_ydbus
#define UNUSED(x) (void)(x)

#if (defined(DEBUG_ydbus) || defined(DEBUG_ydbus))
#   define DEBUGLOG(fmt, ...) \
{                                                           \
    g_printerr("%s:%u:%s ", __FILE__, __LINE__, __FUNCTION__); \
    g_printerr (fmt, __VA_ARGS__);                             \
    g_printerr ("\n");                                         \
}

#   define DEBUGLOG_TVB_DUMP(buf, pos, len)    _dbus_debuglog_tvb_dump(buf, pos, len);

static
void _dbus_debuglog_tvb_dump(tvbuff_t *tvb, guint32 pos, guint32 len)
{
    guint32 i;
    guint32 pos_end;

#define TVB_GET_UINT8(tvb, pos, pos_end)    \
    (pos >= pos_end) ?          \
            '?' : tvb_get_guint8(tvb, pos)

#define TVB_GET_UINT8_NONCTRL(tvb, pos, pos_end)    \
    (pos >=  pos_end) ?          \
            '?' :           \
            ( ( tvb_get_guint8(tvb, pos) < 0x20 ) ? \
                    '.' :   \
                    tvb_get_guint8(tvb, pos) )
    pos_end = pos + len;
    g_print("tvb_length = %d\n", tvb_length(tvb));

    for (i=0; i< len  ; i += 16)
    {
        g_printerr("%04X:  %02X %02X %02X %02X %02X %02X %02X %02X  %02X %02X %02X %02X %02X %02X %02X %02X "
                "\t|%c%c%c%c%c%c%c%c %c%c%c%c%c%c%c%c| \n",
                pos +   i,
                TVB_GET_UINT8(tvb, pos + i, pos_end),
                TVB_GET_UINT8(tvb, pos + i + 1, pos_end),
                TVB_GET_UINT8(tvb, pos + i + 2, pos_end),
                TVB_GET_UINT8(tvb, pos + i + 3, pos_end),
                TVB_GET_UINT8(tvb, pos + i + 4, pos_end),
                TVB_GET_UINT8(tvb, pos + i + 5, pos_end),
                TVB_GET_UINT8(tvb, pos + i + 6, pos_end),
                TVB_GET_UINT8(tvb, pos + i + 7, pos_end),
                TVB_GET_UINT8(tvb, pos + i + 8, pos_end),
                TVB_GET_UINT8(tvb, pos + i + 9, pos_end),
                TVB_GET_UINT8(tvb, pos + i + 10, pos_end),
                TVB_GET_UINT8(tvb, pos + i + 11, pos_end),
                TVB_GET_UINT8(tvb, pos + i + 12, pos_end),
                TVB_GET_UINT8(tvb, pos + i + 13, pos_end),
                TVB_GET_UINT8(tvb, pos + i + 14, pos_end),
                TVB_GET_UINT8(tvb, pos + i + 15, pos_end),
                TVB_GET_UINT8_NONCTRL(tvb, pos + i, pos_end),
                TVB_GET_UINT8_NONCTRL(tvb, pos + i +1, pos_end),
                TVB_GET_UINT8_NONCTRL(tvb, pos + i + 2, pos_end),
                TVB_GET_UINT8_NONCTRL(tvb, pos + i + 3, pos_end),
                TVB_GET_UINT8_NONCTRL(tvb, pos + i + 4, pos_end),
                TVB_GET_UINT8_NONCTRL(tvb, pos + i + 5, pos_end),
                TVB_GET_UINT8_NONCTRL(tvb, pos + i + 6, pos_end),
                TVB_GET_UINT8_NONCTRL(tvb, pos + i + 7, pos_end),
                TVB_GET_UINT8_NONCTRL(tvb, pos + i + 8, pos_end),
                TVB_GET_UINT8_NONCTRL(tvb, pos + i + 9, pos_end),
                TVB_GET_UINT8_NONCTRL(tvb, pos + i + 10, pos_end),
                TVB_GET_UINT8_NONCTRL(tvb, pos + i + 11, pos_end),
                TVB_GET_UINT8_NONCTRL(tvb, pos + i + 12, pos_end),
                TVB_GET_UINT8_NONCTRL(tvb, pos + i + 13, pos_end),
                TVB_GET_UINT8_NONCTRL(tvb, pos + i + 14, pos_end),
                TVB_GET_UINT8_NONCTRL(tvb, pos + i + 15, pos_end)
                );
    }
}

#else
#   define DEBUGLOG(x) ;
#   define DEBUGLOG_DUMP(buf, len, fmt, ...);
#endif


#define DBUS_ALIGN_VALUE(this, boundary) \
  (( ((guint32 )(this)) + (((guint32)(boundary)) -1)) & (~(((guint32)(boundary))-1)))

#define CHK_DBUS_SIG_CONTAINER_START(sign)                   \
     (    (DBUS_STRUCT_BEGIN_CHAR == sign)              \
            || (DBUS_DICT_ENTRY_BEGIN_CHAR == sign)     \
            || (DBUS_TYPE_ARRAY == sign)                \
            || (DBUS_TYPE_VARIANT == sign)              \
    )
#define CHK_DBUS_SIG_CONTAINER_END(sign)                   \
     (    (DBUS_STRUCT_END_CHAR == sign)              \
            || (DBUS_DICT_ENTRY_END_CHAR == sign)   \
    )

void proto_register_dbus(void);
void proto_reg_handoff_dbus(void);

static gboolean dbus_desegment = TRUE;

static dissector_handle_t dbus_handle;
static dissector_handle_t dbus_handle_tcp;

static const value_string message_type_vals[] = {
	{ DBUS_MESSAGE_TYPE_INVALID, "Invalid" },
	{ DBUS_MESSAGE_TYPE_METHOD_CALL, "Method call" },
	{ DBUS_MESSAGE_TYPE_METHOD_RETURN, "Method reply" },
	{ DBUS_MESSAGE_TYPE_ERROR, "Error reply" },
	{ DBUS_MESSAGE_TYPE_SIGNAL, "Signal emission" },
	{ 0, NULL }
};

static const value_string field_code_vals[] = {
	{ DBUS_HEADER_FIELD_INVALID, "INVALID" },
	{ DBUS_HEADER_FIELD_PATH, "PATH" },
	{ DBUS_HEADER_FIELD_INTERFACE, "INTERFACE" },
	{ DBUS_HEADER_FIELD_MEMBER, "MEMBER" },
	{ DBUS_HEADER_FIELD_ERROR_NAME, "ERROR_NAME" },
	{ DBUS_HEADER_FIELD_REPLY_SERIAL, "REPLY_SERIAL" },
	{ DBUS_HEADER_FIELD_DESTINATION, "DESTINATION" },
	{ DBUS_HEADER_FIELD_SENDER, "SENDER" },
	{ DBUS_HEADER_FIELD_SIGNATURE, "SIGNATURE" },
	{ DBUS_HEADER_FIELD_UNIX_FDS, "UNIX_FDS" },
#if DBUSDUMP_HDR_FIELD_EXT_PID_PATH
	{ DBUS_HEADER_FIELD_EXT_SENDER_PID, "SENDER PID"},
	{ DBUS_HEADER_FIELD_EXT_SENDER_CMDLINE, "SENDER CMD LINE"},
	{ DBUS_HEADER_FIELD_EXT_DEST_PID, "DESTINATION PID"},
	{ DBUS_HEADER_FIELD_EXT_DEST_CMDLINE, "DESTINATION CMD LINE"},
#endif

	{ 0, NULL }
};

static header_field_info *hfi_dbus = NULL;

#define DBUS_HFI_INIT HFI_INIT(proto_dbus)

/* XXX, FT_NONE -> FT_BYTES? */

/* Header */
static header_field_info hfi_dbus_hdr DBUS_HFI_INIT =
	{ "Header", "dbus.header", FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL };

static header_field_info hfi_dbus_hdr_endianness DBUS_HFI_INIT =
	{ "Endianness Flag", "dbus.endianness", FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL };

static header_field_info hfi_dbus_hdr_type DBUS_HFI_INIT =
	{ "Message Type", "dbus.type", FT_UINT8, BASE_DEC, VALS(message_type_vals), 0x00, NULL, HFILL };

static header_field_info hfi_dbus_hdr_flags DBUS_HFI_INIT =
	{ "Message Flags", "dbus.flags", FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL };

static header_field_info hfi_dbus_hdr_version DBUS_HFI_INIT =
	{ "Protocol Version", "dbus.version", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL };

static header_field_info hfi_dbus_hdr_body_length DBUS_HFI_INIT =
	{ "Message body Length", "dbus.length", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL };

static header_field_info hfi_dbus_hdr_serial DBUS_HFI_INIT =
	{ "Message Serial (cookie)", "dbus.serial", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL };

static header_field_info hfi_dbus_hdr_fields_length DBUS_HFI_INIT =
	{ "Header fields Length", "dbus.fields_length", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL };

/* Header field */

static header_field_info hfi_dbus_hdr_field DBUS_HFI_INIT =
	{ "Header Field", "dbus.field", FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL };

static header_field_info hfi_dbus_hdr_field_code DBUS_HFI_INIT =
	{ "Field code", "dbus.field_code", FT_UINT8, BASE_DEC, VALS(field_code_vals), 0x00, NULL, HFILL };

static header_field_info hfi_dbus_type_signature DBUS_HFI_INIT =
    { "Type signature", "dbus.type_signature", FT_STRINGZ, BASE_NONE, NULL, 0x00, NULL, HFILL };

/* Header field per field code */
static header_field_info hfi_dbus_object_path DBUS_HFI_INIT =
    { "Object path", "dbus.object_path", FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL };

static header_field_info hfi_dbus_interface DBUS_HFI_INIT =
    { "Interface", "dbus.interface", FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL };

static header_field_info hfi_dbus_member DBUS_HFI_INIT =
    { "Member", "dbus.member", FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL };

static header_field_info hfi_dbus_error_name DBUS_HFI_INIT =
    { "Error name", "dbus.error_name", FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL };

static header_field_info hfi_dbus_reply_serial DBUS_HFI_INIT =
    { "Reply serial", "dbus.reply_serial", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL };

static header_field_info hfi_dbus_destination DBUS_HFI_INIT =
    { "Destination", "dbus.destination", FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL };

#if DBUSDUMP_HDR_FIELD_EXT_PID_PATH
static header_field_info hfi_dbus_destination_pid DBUS_HFI_INIT =
    { "Destination PID", "dbus.destination.pid", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL };

static header_field_info hfi_dbus_destination_cmdline DBUS_HFI_INIT =
    { "Destination command line", "dbus.destination.cmdline", FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL };

static header_field_info hfi_dbus_sender_pid DBUS_HFI_INIT =
    { "Sender PID", "dbus.sender.pid", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL };

static header_field_info hfi_dbus_sender_cmdline DBUS_HFI_INIT =
    { "Sender command line", "dbus.sender.cmdline", FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL };

#endif

static header_field_info hfi_dbus_sender DBUS_HFI_INIT =
    { "Sender", "dbus.sender", FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL };

static header_field_info hfi_dbus_body_signature DBUS_HFI_INIT =
    { "Body signature", "dbus.body_signature", FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL };

static header_field_info hfi_dbus_unix_fds DBUS_HFI_INIT =
    { "UNIX FDS", "dbus.unix_fds", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL };

/* Body */
static header_field_info hfi_dbus_body DBUS_HFI_INIT =
	{ "Body", "dbus.body", FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL };

/* Values */
static header_field_info hfi_dbus_value_bool DBUS_HFI_INIT =
	{ "Value", "dbus.value.bool", FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL };

static header_field_info hfi_dbus_value_number_int64 DBUS_HFI_INIT =
  { "Value", "dbus.value.number.int64", FT_INT64, BASE_DEC, NULL, 0x00, NULL, HFILL };

static header_field_info hfi_dbus_value_number_uint64 DBUS_HFI_INIT =
  { "Value", "dbus.value.number.unit64", FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL };

static header_field_info hfi_dbus_value_number_int DBUS_HFI_INIT =
	{ "Value", "dbus.value.int", FT_INT32, BASE_DEC, NULL, 0x00, NULL, HFILL };

static header_field_info hfi_dbus_value_number_uint DBUS_HFI_INIT =
	{ "Value", "dbus.value.uint", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL };

static header_field_info hfi_dbus_value_str DBUS_HFI_INIT =
	{ "Value", "dbus.value.str", FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL };

static header_field_info hfi_dbus_value_double DBUS_HFI_INIT =
	{ "Value", "dbus.value.double", FT_DOUBLE, BASE_NONE, NULL, 0x00, NULL, HFILL };

static int ett_dbus = -1;
static int ett_dbus_hdr = -1;
static int ett_dbus_body = -1;
static int ett_dbus_field = -1;
static int ett_dbus_error_reply = -1;

static expert_field ei_dbus_value_bool_invalid = EI_INIT;
static expert_field ei_dbus_value_str_invalid = EI_INIT;
static expert_field ei_dbus_invalid_object_path = EI_INIT;
static expert_field ei_dbus_invalid_signature = EI_INIT;
static expert_field ei_dbus_error_reply = EI_INIT;
static expert_field ei_dbus_info_hf_ext = EI_INIT;
static expert_field ei_dbus_info_dict_key = EI_INIT;


typedef struct {
	packet_info *pinfo;

	guint16 (*get16)(tvbuff_t *, const gint);
	guint32 (*get32)(tvbuff_t *, const gint);
	guint64 (*get64)(tvbuff_t *, const gint);
	gdouble (*getdouble)(tvbuff_t *, const gint);
	int enc;

	guint32 body_len;
	guint32 fields_len;
	const char *body_sig;
} dbus_info_t;

typedef union {
	char *str;
	guint uint;
	gdouble dbl;
	guint64 uint64;
} dbus_val_t;


static int dissect_dbus_sig_container(tvbuff_t *tvb, dbus_info_t *dinfo, proto_tree *tree, int offset, char *sig, char **sig_ret, dbus_val_t *ret);
static gboolean dbus_validate_object_path(const char *path);
static gboolean dbus_validate_signature(const char *sig _U_);
static int dbus_type_get_alignment (int typecode);
static int dissect_dbus_sig_container_variant(tvbuff_t *tvb, dbus_info_t *dinfo, proto_tree *tree, int offset, char sig, dbus_val_t *ret);

static int
dissect_dbus_sig_container_array(tvbuff_t *tvb, dbus_info_t *dinfo, proto_tree *tree, int ofs, char *sig, char **sig_ret, dbus_val_t *ret);

static int
dissect_dbus_sig_container_struct(tvbuff_t *tvb, dbus_info_t *dinfo, proto_tree *tree, int ofs, char *sig, char **sig_ret, dbus_val_t *ret);

static int
dissect_dbus_sig_container_dict(tvbuff_t *tvb, dbus_info_t *dinfo, proto_tree *tree, int ofs, char *sig, char **sig_ret, dbus_val_t *ret);
static int dissect_dbus_sig_container(tvbuff_t *tvb, dbus_info_t *dinfo, proto_tree *tree, int offset, char *sig, char **sig_ret, dbus_val_t *ret);

static int dissect_dbus_sig_basic(tvbuff_t *tvb, dbus_info_t *dinfo, proto_tree *tree, int offset, char sig, dbus_val_t *ret, int field_code, proto_item **ret_ti);

static int dissect_dbus_field_signature(tvbuff_t *tvb, dbus_info_t *dinfo, proto_tree *tree, int offset, int field_code);

static int dissect_dbus_hdr_fields(tvbuff_t *tvb, dbus_info_t *dinfo, proto_tree *tree, int offset);
static int dissect_dbus_hdr(tvbuff_t *tvb, dbus_info_t *dinfo, proto_tree *tree, int offset);

static int dissect_dbus_body(tvbuff_t *tvb, dbus_info_t *dinfo, proto_tree *tree, int offset);

static int dissect_dbus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_);

static guint get_dbus_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset);

static int dissect_dbus_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static int dissect_dbus_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);


#if DBUS_BODY_PARSER_TESTING

#define BODY_PARSER_TEST_TEXT_LEN   50000
#define BODY_PARSER_TEST_STR_MAX_LEN   100

//static char * body_parser_test_text = NULL;
static char body_parser_test_text[BODY_PARSER_TEST_TEXT_LEN] ;
static gboolean body_parser_test_record_enabled = FALSE;
static char body_parser_test_prev_sig = '\0';
static const value_string body_parser_test_sig_vals[] = {
    {DBUS_TYPE_BYTE, "BYTE"},
    {DBUS_TYPE_BOOLEAN, "BOOLEAN"},
    {DBUS_TYPE_INT16, "INT16"},
    {DBUS_TYPE_UINT16, "UINT16"},
    {DBUS_TYPE_INT32, "INT32"},
    {DBUS_TYPE_UINT32, "UINT32"},
    {DBUS_TYPE_INT64, "INT64"},
    {DBUS_TYPE_UINT64, "UINT64"},
    {DBUS_TYPE_DOUBLE, "DOUBLE"},
    {DBUS_TYPE_STRING, "STRING"},
    {DBUS_TYPE_OBJECT_PATH, "OBJECT_PATH"},
    {DBUS_TYPE_SIGNATURE, "SIGNATURE"},
    {DBUS_TYPE_UNIX_FD, "UNIX_FD"},
    {DBUS_TYPE_ARRAY, "ARRAY"},
    {DBUS_TYPE_VARIANT, "VARIANT"},
    {DBUS_STRUCT_BEGIN_CHAR, "STRUCT"},
    {DBUS_DICT_ENTRY_BEGIN_CHAR, "DICT"},
    { 0, NULL }
};

static void dbus_body_parser_test_record_start(void);

static void dbus_body_parser_test_record_stop(void);

static void dbus_body_parser_test_append_sig_value(char sig, char *buf, guint32 buf_max_len, dbus_val_t *val );
static void dbus_body_parser_test_add_value(char sig, dbus_val_t *val, gboolean is_container_type_end);

static void dbus_body_parser_test_print_text(void);

static void dbus_body_parser_test_record_start(void)
{
    body_parser_test_record_enabled = TRUE;
    body_parser_test_text[0]='\0';
    body_parser_test_prev_sig='\0';
    return;
}

static void dbus_body_parser_test_record_stop(void)
{
    body_parser_test_record_enabled = FALSE;
    return;
}

static void dbus_body_parser_test_append_sig_value(char sig, char *buf, guint32 buf_max_len, dbus_val_t *val )
{
    #define TMP_STR_LEN     BODY_PARSER_TEST_STR_MAX_LEN
    char tmp[TMP_STR_LEN + 1 ];

    switch (sig){

        case DBUS_TYPE_BYTE:
        case DBUS_TYPE_BOOLEAN:
        case DBUS_TYPE_INT16:
        case DBUS_TYPE_INT32:
            g_snprintf(tmp, TMP_STR_LEN, "%d", val->uint);
            break;

        case DBUS_TYPE_UNIX_FD:
        case DBUS_TYPE_UINT16:
        case DBUS_TYPE_UINT32:
            g_snprintf(tmp, TMP_STR_LEN, "%u", val->uint);
            break;

        case DBUS_TYPE_INT64:
            g_snprintf(tmp, TMP_STR_LEN, "%ld", val->uint64);
            break;

        case DBUS_TYPE_UINT64:
            g_snprintf(tmp, TMP_STR_LEN, "%lu", val->uint64);
            break;

        case DBUS_TYPE_DOUBLE:
            g_snprintf(tmp, TMP_STR_LEN, "%f", val->dbl);
            break;

        case DBUS_TYPE_STRING:
        case DBUS_TYPE_OBJECT_PATH:
        case DBUS_TYPE_SIGNATURE:
            strncpy(tmp, val->str, BODY_PARSER_TEST_STR_MAX_LEN);
            break;
    }

    strncat(buf, tmp, buf_max_len);

    return;
}

static void dbus_body_parser_test_add_value(char sig, dbus_val_t *val, gboolean is_container_type_end)
{
    if (!body_parser_test_record_enabled)
        return;

    if (is_container_type_end)
    {
        if (CHK_DBUS_SIG_CONTAINER_START(sig))
        {
            strncat(body_parser_test_text, ")", BODY_PARSER_TEST_TEXT_LEN);
        }

        sig = 0xFF;
    }
    else
    {
        if ( ((body_parser_test_prev_sig != '\0') &&
                ! (CHK_DBUS_SIG_CONTAINER_START(body_parser_test_prev_sig)))
                || (body_parser_test_prev_sig == '\255')
                )
        {
            strncat(body_parser_test_text, ",", BODY_PARSER_TEST_TEXT_LEN);
        }
        strncat(body_parser_test_text,
                val_to_str(sig, body_parser_test_sig_vals, "?%d?"),
                BODY_PARSER_TEST_TEXT_LEN);


        if (CHK_DBUS_SIG_CONTAINER_START(sig))
        {
            strncat(body_parser_test_text,"(", BODY_PARSER_TEST_TEXT_LEN);
        }
        else
        {
            /*fixed type */
            strncat(body_parser_test_text,":", BODY_PARSER_TEST_TEXT_LEN);
        }
        dbus_body_parser_test_append_sig_value(sig, body_parser_test_text,
                BODY_PARSER_TEST_TEXT_LEN, val);
    }

    body_parser_test_prev_sig = sig;
    return;
}

static void dbus_body_parser_test_print_text(void)
{
    g_print("dbus_body_parser_test_print_text %s\n", body_parser_test_text);

    return;

}
#else

#define dbus_body_parser_test_record_start()

#define dbus_body_parser_test_record_stop()

#define dbus_body_parser_test_append_sig_value( sig, buf,  buf_max_len, val )

#define dbus_body_parser_test_add_value( sig, val,  is_container_type_end)
#define dbus_body_parser_test_print_text()

#endif

static gboolean
dbus_validate_object_path(const char *path)
{
	/* XXX check */
	if (*path != '/')
		return FALSE;

	do {
		path++;

		if (*path == '/')
			return FALSE;

		while ((*path >= 'A' && *path <= 'Z') || (*path >= 'a' && *path <= 'z') || (*path >= '0' && *path <= '9') || *path == '_')
			path++;

		if (*path == '\0')
			return TRUE;

	} while (*path == '/');

	return FALSE;
}

static gboolean
dbus_validate_signature(const char *sig _U_)
{
	/* XXX implement */
	return TRUE;
}

static int
dbus_type_get_alignment (int typecode)
{
  switch (typecode)
    {
    case DBUS_TYPE_BYTE:
    case DBUS_TYPE_VARIANT:
    case DBUS_TYPE_SIGNATURE:
      return 1;
    case DBUS_TYPE_INT16:
    case DBUS_TYPE_UINT16:
      return 2;
    case DBUS_TYPE_BOOLEAN:
    case DBUS_TYPE_INT32:
    case DBUS_TYPE_UINT32:
    case DBUS_TYPE_UNIX_FD:
      /* this stuff is 4 since it starts with a length */
    case DBUS_TYPE_STRING:
    case DBUS_TYPE_OBJECT_PATH:
    case DBUS_TYPE_ARRAY:
      return 4;
    case DBUS_TYPE_INT64:
    case DBUS_TYPE_UINT64:
    case DBUS_TYPE_DOUBLE:
      /* struct is 8 since it could contain an 8-aligned item
       * and it's simpler to just always align structs to 8;
       * we want the amount of padding in a struct of a given
       * type to be predictable, not location-dependent.
       * DICT_ENTRY is always the same as struct.
       */
    case DBUS_TYPE_STRUCT:
    case DBUS_TYPE_DICT_ENTRY:
    case DBUS_STRUCT_BEGIN_CHAR:
    case DBUS_DICT_ENTRY_BEGIN_CHAR:
      return 8;

    default:
//      _dbus_assert_not_reached ("unknown typecode in _dbus_type_get_alignment()");
      return 0;
    }
}

/**
 * Skips to the next "complete" type inside a type signature.
 * The signature is read starting at type_pos, and the next
 * type position is stored in the same variable.
 *
 * @param type_str a type signature (must be valid)
 * @param type_pos an integer position in the type signature (in and out)
 */
static void
dbus_type_signature_next (const char       *type_str,
               int              *type_pos)
{
  const unsigned char *p;
  const unsigned char *start;


  start = type_str;
  p = start + *type_pos;


  while (*p == DBUS_TYPE_ARRAY)
    ++p;


  if (*p == DBUS_STRUCT_BEGIN_CHAR)
    {
      int depth;

      depth = 1;

      while (TRUE)
        {

          ++p;


          if (*p == DBUS_STRUCT_BEGIN_CHAR)
            depth += 1;
          else if (*p == DBUS_STRUCT_END_CHAR)
            {
              depth -= 1;
              if (depth == 0)
                {
                  ++p;
                  break;
                }
            }
        }
    }
  else if (*p == DBUS_DICT_ENTRY_BEGIN_CHAR)
    {
      int depth;

      depth = 1;

      while (TRUE)
        {

          ++p;


          if (*p == DBUS_DICT_ENTRY_BEGIN_CHAR)
            depth += 1;
          else if (*p == DBUS_DICT_ENTRY_END_CHAR)
            {
              depth -= 1;
              if (depth == 0)
                {
                  ++p;
                  break;
                }
            }
        }
    }
  else
    {
      ++p;
    }

  *type_pos = (int) (p - start);
}


static int
dissect_dbus_sig_container_variant(tvbuff_t *tvb, dbus_info_t *dinfo, proto_tree *tree, int ofs, char sig, dbus_val_t *ret)
{
    guint element_sig_len;
    char *element_sig;
    char *element_sig_ret;
    dbus_val_t val;
    guint container_alignment;

    UNUSED(sig);
    UNUSED(ret);

    DEBUGLOG_TVB_DUMP(tvb, ofs, tvb_length(tvb) - ofs);

    /* Variant sig len is only 1 byte */
    element_sig_len = tvb_get_guint8(tvb, ofs);
    ofs += 1;

    element_sig = tvb_get_string(wmem_packet_scope(), tvb, ofs, element_sig_len);
    ofs += (element_sig_len + 1);

    container_alignment = dbus_type_get_alignment(*element_sig );
    ofs = DBUS_ALIGN_VALUE(ofs, container_alignment);

    DEBUGLOG("element_sig=%s, element_sig_len=%d(%0x), current ofs=%d(%0x)", element_sig, element_sig_len, element_sig_len, ofs, ofs);

    // TODO: element_sig/element_sig_len = 0? check
    element_sig_ret = element_sig;

    while (*element_sig) {
        if ( CHK_DBUS_SIG_CONTAINER_START(*element_sig) )
        {
            ofs = dissect_dbus_sig_container(tvb, dinfo, tree, ofs, element_sig, &element_sig_ret, &val);
            DEBUGLOG("container sign return ofs=%d, element_sig='%s', element_sig_ret='%s'",
                    ofs,
                    element_sig,
                    element_sig_ret);
            element_sig = element_sig_ret;
        }
        else /* CHK_DBUS_SIGN_CONTAINER(*sig) */
        {
            ofs = dissect_dbus_sig_basic(tvb, dinfo, tree, ofs, *element_sig, &val, -1, NULL);
            DEBUGLOG("basic sign return ofs=%d(0x%0x)", ofs, ofs);
            element_sig++;
        }
    }

    return ofs;
}

static int
dissect_dbus_sig_container_array(tvbuff_t *tvb, dbus_info_t *dinfo, proto_tree *tree, int ofs, char *sig, char **sig_ret, dbus_val_t *ret)
{
    const int ofs_org = ofs;
    guint32 len;
    int ofs_end;
    guint32 container_alignment;
    dbus_val_t val;

    UNUSED(ret);

    /* Get array length */
    len = dinfo->get32(tvb, ofs);
    ofs += 4;

    DEBUGLOG("ofs_org=%d, len=%d", ofs_org, len);

    container_alignment = dbus_type_get_alignment(*(sig+1));

    /* Calculate ofs of the first array element */
    ofs = DBUS_ALIGN_VALUE(ofs, container_alignment);
    ofs_end = ofs + len;

    DEBUGLOG("ofs value=%d, len=%d(0x%0x), ofs_end=%d, tvb len=%d\n", ofs, len, len, ofs_end, tvb_length(tvb));
    DEBUGLOG_TVB_DUMP(tvb, ofs_org, ofs_end - ofs_org);

    if (0 == len)
    {
        gint next_sig_pos = 0;

        dbus_type_signature_next(sig, &next_sig_pos);
        *sig_ret = sig + next_sig_pos;

        DEBUGLOG("array len=0 ofs=%d(0x%0x), next sig=%s", ofs, ofs, *sig_ret);
        return ofs;
    }

    *sig_ret = sig;
    /* skip the 'a' sign */
    sig++;
    while (/*(*sig)
            &&*/
            (ofs < ofs_end))
    {
        DEBUGLOG("sig='%c' ofs=%d(0x%0x)  ofs_end=%d(0x%0x)", *sig, ofs, ofs, ofs_end, ofs_end);
        if ( CHK_DBUS_SIG_CONTAINER_START(*sig) )
        {
            DEBUGLOG("CHK_DBUS_SIG_CONTAINER_START sig='%c'", *sig);
            ofs = dissect_dbus_sig_container(tvb, dinfo, tree, ofs, sig, sig_ret, &val);
            //sig = *sig_ret + 1;
            DEBUGLOG("container sign return ofs=%d, sig='%s', sig_ret='%s'",
                    ofs,
                    sig,
                    *sig_ret);
        }
        else /* CHK_DBUS_SIGN_CONTAINER(*sig) */
        {
            ofs = dissect_dbus_sig_basic(tvb, dinfo, tree, ofs, *sig, &val, -1, NULL);
            DEBUGLOG("basic sign return ofs=%d(0x%0x), ofs_end=%d, sig='%s'", ofs, ofs, ofs_end, sig);
            /* update sig_ret to next sig when array fetching is finished */
            *sig_ret = sig + 1;
        }
        /* repeat again with sig type until the array is end */
    }

    DEBUGLOG(" return ofs=%d(0x%0x), ofs_end=%d, *sig_ret='%s'", ofs, ofs, ofs_end, *sig_ret);
    return ofs;
}

static int
dissect_dbus_sig_container_struct(tvbuff_t *tvb, dbus_info_t *dinfo, proto_tree *tree, int ofs, char *sig, char **sig_ret, dbus_val_t *ret)
{
    dbus_val_t val;

    UNUSED(ret);

    DEBUGLOG("ofs=%d, sig=%s", ofs, sig);
    DEBUGLOG_TVB_DUMP(tvb, 0, tvb_length(tvb));

    /* skip the '(' sign */
    sig++;
    *sig_ret = sig;
    while ((*sig != DBUS_STRUCT_END_CHAR))
    {

        DEBUGLOG("ofs=%d, sig='%c'", ofs, *sig);

        if ( CHK_DBUS_SIG_CONTAINER_START(*sig) )
        {
            ofs = dissect_dbus_sig_container(tvb, dinfo, tree, ofs, sig, sig_ret, &val);
            sig = *sig_ret;
            DEBUGLOG("container sign return ofs=%d, sig='%s', sig_ret='%s'",
                    ofs,
                    sig,
                    *sig_ret);
        }
        else /* CHK_DBUS_SIGN_CONTAINER(*sig) */
        {
            ofs = dissect_dbus_sig_basic(tvb, dinfo, tree, ofs, *sig, &val, -1, NULL);
            sig++;
            *sig_ret = sig;
            DEBUGLOG("basic sign return ofs=%d(0x%0x), sig='%s', *sig_ret='%s'",
                    ofs, ofs,
                    sig, *sig_ret);
        }
        /* repeat again with sig type until the struct is end */
    }

    /* skip the DBUS_STRUCT_ENTRY_END_CHAR */

    *sig_ret += 1;

    DEBUGLOG("ofs=%d, last sig='%s', *sig_ret='%s'",
            ofs, sig, *sig_ret);

    return ofs;

}

static int
dissect_dbus_sig_container_dict(tvbuff_t *tvb, dbus_info_t *dinfo, proto_tree *tree, int ofs, char *sig, char **sig_ret, dbus_val_t *ret)
{
    dbus_val_t val;
    proto_item *ti;

    UNUSED(ret);


    sig++; /* skip the '{' sign */

    /* First item is key */
    /* TODO: make sure the key is basic type */

    while ((*sig != DBUS_DICT_ENTRY_END_CHAR)
            //&& (ofs < array_ofs_end)
            )
    {
        DEBUGLOG("ofs=%d, sig='%c'", ofs, *sig);

        if ( CHK_DBUS_SIG_CONTAINER_START(*sig) )
        {
            ofs = dissect_dbus_sig_container(tvb, dinfo, tree, ofs, sig, sig_ret, &val);
            sig = *sig_ret;
            DEBUGLOG("container sign return ofs=%d, sig='%s', sig_ret='%s'",
                    ofs,
                    sig,
                    *sig_ret);
        }
        else /* CHK_DBUS_SIGN_CONTAINER(*sig) */
        {
            ofs = dissect_dbus_sig_basic(tvb, dinfo, tree, ofs, *sig, &val, -1, &ti);
            if (*(sig-1) ==  DBUS_DICT_ENTRY_BEGIN_CHAR)
            {
                expert_add_info(dinfo->pinfo, ti, &ei_dbus_info_dict_key);
            }
            sig++;
            *sig_ret = sig;
            DEBUGLOG("basic sign return ofs=%d(0x%0x)", ofs, ofs);
        }
        /* repeat again with sig type until the array is end */
    }

    /* skip the DBUS_DICT_ENTRY_END_CHAR */
    *sig_ret += 1;

    DEBUGLOG("return ofs=%d, **sig_ret='%c', *sig='%c'", ofs, **sig_ret, *sig);

    return ofs;
}

static int
dissect_dbus_sig_container(tvbuff_t *tvb, dbus_info_t *dinfo, proto_tree *tree, int ofs, char *sig, char **sig_ret, dbus_val_t *ret)
{
    dbus_val_t addr_val;
    const int org_ofs = ofs;
    guint container_alignment;
    proto_item *ti;
    proto_tree *container_field_tree;

    UNUSED(ret);

    container_alignment = dbus_type_get_alignment(*sig);

    /* Calculate ofs of the first array element */
    ofs = DBUS_ALIGN_VALUE(ofs, container_alignment);
    DEBUGLOG("ofs=%d(%0x), sig=%s", ofs, ofs, sig);

    *sig_ret = sig;

    switch (*sig)
    {
        case DBUS_TYPE_VARIANT:

            dbus_body_parser_test_add_value(DBUS_TYPE_VARIANT, NULL, FALSE);

            ti = proto_tree_add_text(tree, tvb, org_ofs, 0, "Variant");
            container_field_tree = proto_item_add_subtree(ti, ett_dbus_body);

            ofs = dissect_dbus_sig_container_variant(tvb, dinfo, container_field_tree, ofs, *sig, &addr_val);

            /* sig variant is fixed as 'v' -> return *sig_ret = next sig */
            *sig_ret = sig + 1;

            /* TODO: indicate variant size only - not include padding */
            proto_item_set_text(ti,
                    "Variant (%d bytes including padding)", ofs - org_ofs);

            proto_item_set_end(ti, tvb, ofs);

            dbus_body_parser_test_add_value(DBUS_TYPE_VARIANT, NULL, TRUE);

            break;

        case DBUS_TYPE_ARRAY:

            dbus_body_parser_test_add_value(DBUS_TYPE_ARRAY, NULL, FALSE);

            ti = proto_tree_add_text(tree, tvb, org_ofs, 0, "Array");
            container_field_tree = proto_item_add_subtree(ti, ett_dbus_body);

            ofs = dissect_dbus_sig_container_array(tvb, dinfo,
                    container_field_tree,
                    ofs, sig, sig_ret, &addr_val);

            /* TODO: indicate array size only - not include padding */
            proto_item_set_text(ti,
                    "Array (%d bytes including padding)", ofs - org_ofs);

            proto_item_set_end(ti, tvb, ofs);

            dbus_body_parser_test_add_value(DBUS_TYPE_ARRAY, NULL, TRUE);

            break;

        case DBUS_STRUCT_BEGIN_CHAR:

            dbus_body_parser_test_add_value(DBUS_STRUCT_BEGIN_CHAR, NULL, FALSE);

            ti = proto_tree_add_text(tree, tvb, org_ofs, 0, "Struct");
            container_field_tree = proto_item_add_subtree(ti, ett_dbus_body);

            ofs = dissect_dbus_sig_container_struct(tvb, dinfo, container_field_tree, ofs, sig, sig_ret, &addr_val);

            /* TODO: indicate struct size only - not include padding */
            proto_item_set_text(ti,
                    "Struct (%d bytes including padding)", ofs - org_ofs);

            proto_item_set_end(ti, tvb, ofs);

            dbus_body_parser_test_add_value(DBUS_STRUCT_BEGIN_CHAR, NULL, TRUE);

            break;

        case DBUS_DICT_ENTRY_BEGIN_CHAR:

            dbus_body_parser_test_add_value(DBUS_DICT_ENTRY_BEGIN_CHAR, NULL, FALSE);

            ti = proto_tree_add_text(tree, tvb, org_ofs, 0, "Dict Entry");
            container_field_tree = proto_item_add_subtree(ti, ett_dbus_body);


            ofs = dissect_dbus_sig_container_dict(tvb, dinfo, container_field_tree, ofs, sig, sig_ret, &addr_val);

            /* TODO: indicate dict size only - not include padding */
            proto_item_set_text(ti,
                    "Dict Entry (%d bytes including padding)", ofs - org_ofs);

            proto_item_set_end(ti, tvb, ofs);

            dbus_body_parser_test_add_value(DBUS_DICT_ENTRY_BEGIN_CHAR, NULL, TRUE);

            break;


        default:
            /* smth wrong here! */
            break;
    }

    return ofs;

}

static int
dissect_dbus_sig_basic(tvbuff_t *tvb, dbus_info_t *dinfo, proto_tree *tree, int offset, char sig, dbus_val_t *ret, int field_code, proto_item **ret_ti)
{
	int org_offset;
	guint container_alignment;
	proto_item *ti_tmp;
    proto_item **ti;

    if ( NULL != ret_ti )
        ti = ret_ti;
    else
        ti = &ti_tmp;

	container_alignment = dbus_type_get_alignment(sig);

    /* Calculate ofs of the first array element */
	offset = DBUS_ALIGN_VALUE(offset, container_alignment);
    DEBUGLOG("ofs=%d(%0x), sig=%c", offset, offset, sig);
    org_offset = offset;

	switch (sig) {
		case 'y':	/* BYTE */
		{
			guint8 val;

			val = tvb_get_guint8(tvb, offset);
			offset += 1;

			*ti = proto_tree_add_uint_format(tree, hfi_dbus_value_number_uint.id,
			        tvb, org_offset, offset - org_offset, val, "BYTE: %u", val);
			ret->uint = val;

			dbus_body_parser_test_add_value(sig, ret, FALSE);

			DEBUGLOG("return byte=%d(0x%0x)", ret->uint, ret->uint);

			return offset;
		}

		case 'b':	/* BOOLEAN */
		{
			guint32 val;

			val = dinfo->get32(tvb, offset);
			offset += 4;

			*ti = proto_tree_add_boolean_format(tree, hfi_dbus_value_bool.id, tvb, org_offset, offset - org_offset, val, "BOOLEAN: %s", val ? "True" : "False");
			if (val != 0 && val != 1) {
				expert_add_info_format(dinfo->pinfo, *ti, &ei_dbus_value_bool_invalid, "Invalid boolean value (must be 0 or 1 is: %u)", val);
				return -1;
			}
			ret->uint = val;

			dbus_body_parser_test_add_value(sig, ret, FALSE);

			DEBUGLOG("return boolean=%d", ret->uint);
			return offset;
		}

		case 'n':	/* INT16 */
		{
			gint16 val;

			val = (gint16 )dinfo->get16(tvb, offset);
			offset += 2;

			*ti = proto_tree_add_int_format(tree, hfi_dbus_value_number_int.id, tvb, org_offset, offset - org_offset, val, "INT16: %d", val);
			/* XXX ret */
			ret->uint = val;

			dbus_body_parser_test_add_value(sig, ret, FALSE);

			DEBUGLOG("return int16=%d(0x%0x)", ret->uint, ret->uint);
			return offset;
		}

		case 'q':	/* UINT16 */
		{
			guint16 val;

			val = dinfo->get16(tvb, offset);
			offset += 2;

			*ti = proto_tree_add_uint_format(tree, hfi_dbus_value_number_uint.id,
			        tvb, org_offset, offset - org_offset, val, "UINT16: %u", val);
			ret->uint = val;
			dbus_body_parser_test_add_value(sig, ret, FALSE);
			DEBUGLOG("return uint16=%d(0x%0x)", ret->uint, ret->uint);
			return offset;
		}

		case 'i':	/* INT32 */
		{
			gint32 val;

			val = (gint32) dinfo->get32(tvb, offset);
			offset += 4;

			*ti = proto_tree_add_int_format(tree, hfi_dbus_value_number_int.id, tvb, org_offset, offset - org_offset, val, "INT32: %d", val);
			/* XXX ret */
			ret->uint = val;

			dbus_body_parser_test_add_value(sig, ret, FALSE);

			DEBUGLOG("return int32=%d(0x%0x)", ret->uint, ret->uint);
			return offset;
		}

		case 'u':	/* UINT32 */
		{
			guint32 val;

			val = dinfo->get32(tvb, offset);
			offset += 4;

			if (DBUS_HEADER_FIELD_REPLY_SERIAL== field_code)
            {
			    *ti = proto_tree_add_uint_format(tree, hfi_dbus_reply_serial.id, tvb, org_offset, offset - org_offset, val, "REPLY SERIAL: %u", val);
            }
			else if (DBUS_HEADER_FIELD_UNIX_FDS== field_code)
            {
			    *ti = proto_tree_add_uint_format(tree, hfi_dbus_unix_fds.id, tvb, org_offset, offset - org_offset, val, "UNIX FDS: %u", val);
            }
#if DBUSDUMP_HDR_FIELD_EXT_PID_PATH
            else if (DBUS_HEADER_FIELD_EXT_SENDER_PID == field_code)
            {
                *ti = proto_tree_add_uint_format(tree, hfi_dbus_sender_pid.id, tvb, org_offset, offset - org_offset, val, "SENDER PID: %u", val);
                expert_add_info(dinfo->pinfo, *ti, &ei_dbus_info_hf_ext);
            }
            else if (DBUS_HEADER_FIELD_EXT_DEST_PID == field_code)
            {
                *ti = proto_tree_add_uint_format(tree, hfi_dbus_destination_pid.id, tvb, org_offset, offset - org_offset, val, "DESTINATION PID: %u", val);
                expert_add_info(dinfo->pinfo, *ti, &ei_dbus_info_hf_ext);
            }
#endif
			else
			{
			    *ti = proto_tree_add_uint_format(tree, hfi_dbus_value_number_uint.id, tvb, org_offset, offset - org_offset, val, "UINT32: %u", val);
			}

			ret->uint = val;

			dbus_body_parser_test_add_value(sig, ret, FALSE);
			DEBUGLOG("return uint32=%d(0x%0x)", ret->uint, ret->uint);
			return offset;
		}

		case 'x':	/* INT64 */
		{
            guint64 val;

            val = dinfo->get64(tvb, offset);
            offset += 8;
            /* TODO: */
            *ti = proto_tree_add_int64_format(tree, hfi_dbus_value_number_int64.id, tvb, org_offset, offset - org_offset, val, "INT64: %ld" , val);
            /* XXX ret */
            ret->uint64 = val;

            dbus_body_parser_test_add_value(sig, ret, FALSE);

            DEBUGLOG("return int64=%ld", ret->uint64);
            return offset;
        }
		case 't':	/* UINT64 */
		{
		    guint64 val;

            val = dinfo->get64(tvb, offset);
            offset += 8;
            /* TODO: */
            *ti = proto_tree_add_uint64_format(tree, hfi_dbus_value_number_uint64.id, tvb, org_offset, offset - org_offset, val, "UINT64: %lu", val);
            /* XXX ret */
            ret->uint64 = val;

            dbus_body_parser_test_add_value(sig, ret, FALSE);

            DEBUGLOG("return uint64=%lu", ret->uint64);
            return offset;
		}

		case 'd':	/* DOUBLE */
		{
			gdouble val;

			val = dinfo->getdouble(tvb, offset);
			offset += 8;

			*ti = proto_tree_add_double_format(tree, hfi_dbus_value_double.id, tvb, org_offset, offset - org_offset, val, "DOUBLE: %." G_STRINGIFY(DBL_DIG) "g", val);
			/* XXX ret */
			ret->dbl = val;

			dbus_body_parser_test_add_value(sig, ret, FALSE);

			DEBUGLOG("return double=%f", ret->dbl);
			return offset;
		}

		case 's':	/* STRING */
		case 'o':	/* OBJECT_PATH */
		{
			guint32 len;
			char *val;

			len = dinfo->get32(tvb, offset);
			offset += 4;

			val = tvb_get_string(wmem_packet_scope(), tvb, offset, len);
			/* skip NULL byte */
			offset += len + 1;

			if (sig == 's') {
			    if (DBUS_HEADER_FIELD_INTERFACE == field_code)
                {
			        *ti = proto_tree_add_string_format(tree, hfi_dbus_interface.id, tvb, org_offset, offset - org_offset, val, "INTERFACE: %s", val);
                }
                else if (DBUS_HEADER_FIELD_MEMBER == field_code)
                {
                    *ti = proto_tree_add_string_format(tree, hfi_dbus_member.id, tvb, org_offset, offset - org_offset, val, "MEMBER: %s", val);
                }
                else if (DBUS_HEADER_FIELD_ERROR_NAME == field_code)
                {
                    *ti = proto_tree_add_string_format(tree, hfi_dbus_error_name.id, tvb, org_offset, offset - org_offset, val, "ERROR NAME: %s", val);
                    expert_add_info(dinfo->pinfo, *ti, &ei_dbus_error_reply);
                }
                else if (DBUS_HEADER_FIELD_DESTINATION == field_code)
                {
                    *ti = proto_tree_add_string_format(tree, hfi_dbus_destination.id, tvb, org_offset, offset - org_offset, val, "DESTINATION: %s", val);
                }
                else if (DBUS_HEADER_FIELD_SENDER == field_code)
			    {
                    *ti = proto_tree_add_string_format(tree, hfi_dbus_sender.id, tvb, org_offset, offset - org_offset, val, "SENDER: %s", val);
			    }
#if DBUSDUMP_HDR_FIELD_EXT_PID_PATH
                else if (DBUS_HEADER_FIELD_EXT_SENDER_CMDLINE == field_code)
                {
                    *ti = proto_tree_add_string_format(tree, hfi_dbus_sender_cmdline.id, tvb, org_offset, offset - org_offset, val, "SENDER CMD LINE: %s", val);
                    expert_add_info(dinfo->pinfo, *ti, &ei_dbus_info_hf_ext);
                }
                else if (DBUS_HEADER_FIELD_EXT_DEST_CMDLINE == field_code)
                {
                    *ti = proto_tree_add_string_format(tree, hfi_dbus_destination_cmdline.id, tvb, org_offset, offset - org_offset, val, "DESTINATION CMDLINE: %s", val);
                    expert_add_info(dinfo->pinfo, *ti, &ei_dbus_info_hf_ext);
                }
#endif
                else
                {
                    /* Normal body value */
                    *ti = proto_tree_add_string_format(tree, hfi_dbus_value_str.id, tvb, org_offset, offset - org_offset, val, "STRING: %s", val);
                    if (!g_utf8_validate(val, -1, NULL)) {
                        expert_add_info(dinfo->pinfo, *ti, &ei_dbus_value_str_invalid);
                        return -1;
                    }
			    }
			} else {
			    /* sig = 'o' */
				*ti = proto_tree_add_string_format(tree, hfi_dbus_object_path.id, tvb, org_offset, offset - org_offset, val, "OBJECT_PATH: %s", val);
				if (!dbus_validate_object_path(val)) {
					expert_add_info(dinfo->pinfo, *ti, &ei_dbus_invalid_object_path);
					return -1;
				}
			}

			ret->str = val;
			dbus_body_parser_test_add_value(sig, ret, FALSE);

			DEBUGLOG("return string='%s', offset=%d", ret->str, offset);
			return offset;
		}

		case 'g':	/* SIGNATURE */
		{
			guint8 len;
			char *val;

			len = tvb_get_guint8(tvb, offset);
			offset += 1;

			val = tvb_get_string(wmem_packet_scope(), tvb, offset, len);
			offset += (len + 1);

			*ti = proto_tree_add_string_format(tree, hfi_dbus_body_signature.id, tvb, org_offset, offset - org_offset, val, "SIGNATURE: %s", val);
			if (!dbus_validate_signature(val)) {
				expert_add_info(dinfo->pinfo, *ti, &ei_dbus_invalid_signature);
				return -1;
			}
			ret->str = val;

			dbus_body_parser_test_add_value(sig, ret, FALSE);
			DEBUGLOG("return signature string='%s'", ret->str);
			return offset;
		}

		/* ... */
	}
	return -1;
}

static int
dissect_dbus_field_signature(tvbuff_t *tvb, dbus_info_t *dinfo, proto_tree *tree, int offset, int field_code)
{
	const int org_offset = offset;

	proto_item *ti;
	guint sig_len;
	char *sig;

	sig_len = tvb_get_guint8(tvb, offset);
	offset += 1;


	sig = tvb_get_string(wmem_packet_scope(), tvb, offset, sig_len);
	offset += (sig_len + 1);

	ti = proto_tree_add_string(tree, &hfi_dbus_type_signature, tvb, org_offset, offset - org_offset, sig);
	if (!dbus_validate_signature(sig)) {
		expert_add_info(dinfo->pinfo, ti, &ei_dbus_invalid_signature);
		return -1;
	}

	switch (field_code) {
		case DBUS_HEADER_FIELD_REPLY_SERIAL:
			if (!strcmp(sig, "u")) {	/* UINT32 */
				dbus_val_t serial_val;

				offset = dissect_dbus_sig_basic(tvb, dinfo, tree, offset, 'u', &serial_val, field_code, NULL);
				if (offset != -1)
					{ /* XXX link with sending frame (serial_val.uint) */ }
				return offset;
			}
			break;

		case DBUS_HEADER_FIELD_DESTINATION:
		case DBUS_HEADER_FIELD_SENDER:
			if (!strcmp(sig, "s")) {	/* STRING */
				dbus_val_t addr_val;

				offset = dissect_dbus_sig_basic(tvb, dinfo, tree, offset, 's', &addr_val, field_code, NULL);
				if (offset != -1)
					SET_ADDRESS((field_code == DBUS_HEADER_FIELD_DESTINATION) ? &dinfo->pinfo->dst : &dinfo->pinfo->src,
					            AT_STRINGZ, (int)strlen(addr_val.str)+1, addr_val.str);
				return offset;
			}
			break;

		case DBUS_HEADER_FIELD_SIGNATURE:
			if (!strcmp(sig, "g")) {	/* SIGNATURE */
				dbus_val_t sig_val;

				offset = dissect_dbus_sig_basic(tvb, dinfo, tree, offset, 'g', &sig_val, field_code, NULL);
				if (offset != -1)
					dinfo->body_sig = sig_val.str;
				return offset;
			}
			break;
	}

	while (*sig) {
		dbus_val_t val;

		offset = dissect_dbus_sig_basic(tvb, dinfo, tree, offset, *sig, &val, field_code, NULL);
		if (offset == -1)
			return -1;
		sig++;
	}
	return offset;
}

static int
dissect_dbus_hdr_fields(tvbuff_t *tvb, dbus_info_t *dinfo, proto_tree *tree, int offset)
{
	int end_offset;

	end_offset = offset + dinfo->fields_len;

	while (offset < end_offset) {
		proto_tree *field_tree;
		proto_item *ti;

		guint8 field_code;

		ti = proto_tree_add_item(tree, &hfi_dbus_hdr_field, tvb, offset, 0, ENC_NA);
		field_tree = proto_item_add_subtree(ti, ett_dbus_field);

		field_code = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(field_tree, &hfi_dbus_hdr_field_code, tvb, offset, 1, dinfo->enc);
		proto_item_append_text(ti, ": %s", val_to_str(field_code, field_code_vals, "Unknown: %d"));
		offset += 1;

		offset = dissect_dbus_field_signature(tvb, dinfo, field_tree, offset, field_code);
		if (offset == -1)
			break;

		/* sig string for header is "yyyyuua(yv)", each header field is struct element -> align 8 */
		offset = DBUS_ALIGN_VALUE(offset, dbus_type_get_alignment(DBUS_TYPE_STRUCT));

		proto_item_set_end(ti, tvb, offset);
	}

	/* XXX, verify if all required fields are preset */

	if (offset >= end_offset) {
		/* XXX expert */
	}

	return end_offset;
}

static int
dissect_dbus_hdr(tvbuff_t *tvb, dbus_info_t *dinfo, proto_tree *tree, int offset)
{
	proto_tree *hdr_tree;
	proto_item *ti;

	guint8 type;

	ti = proto_tree_add_item(tree, &hfi_dbus_hdr, tvb, offset, 0, ENC_NA);
	hdr_tree = proto_item_add_subtree(ti, ett_dbus_hdr);

	proto_tree_add_item(hdr_tree, &hfi_dbus_hdr_endianness, tvb, offset, 1, ENC_ASCII | ENC_NA);
	offset += 1;

	type = tvb_get_guint8(tvb, offset);
	col_set_str(dinfo->pinfo->cinfo, COL_INFO, val_to_str_const(type, message_type_vals, ""));
	proto_tree_add_item(hdr_tree, &hfi_dbus_hdr_type, tvb, offset, 1, dinfo->enc);
	offset += 1;

	proto_tree_add_item(hdr_tree, &hfi_dbus_hdr_flags, tvb, offset, 1, dinfo->enc);
	offset += 1;

	proto_tree_add_item(hdr_tree, &hfi_dbus_hdr_version, tvb, offset, 1, dinfo->enc);
	offset += 1;

	dinfo->body_len = dinfo->get32(tvb, offset);
	proto_tree_add_item(hdr_tree, &hfi_dbus_hdr_body_length, tvb, offset, 4, dinfo->enc);
	offset += 4;

	proto_tree_add_item(hdr_tree, &hfi_dbus_hdr_serial, tvb, offset, 4, dinfo->enc);
	offset += 4;

	dinfo->fields_len = dinfo->get32(tvb, offset);
	proto_tree_add_item(hdr_tree, &hfi_dbus_hdr_fields_length, tvb, offset, 4, dinfo->enc);
	offset += 4;

	return offset;
}

static int
dissect_dbus_body(tvbuff_t *tvb, dbus_info_t *dinfo, proto_tree *tree, int offset)
{
	proto_tree *body_tree;
	proto_item *ti;
	char * sig_ret= NULL;
	dbus_val_t val;

	if (dinfo->body_len && dinfo->body_sig[0]) {
		char *sig = (char *)dinfo->body_sig;

		ti = proto_tree_add_item(tree, &hfi_dbus_body, tvb, offset, 0, ENC_NA);
		body_tree = proto_item_add_subtree(ti, ett_dbus_body);

		while (*sig) {


			if ( CHK_DBUS_SIG_CONTAINER_START(*sig) )
			{
			    DEBUGLOG("Container sig %c in sig string %s", *sig, sig);
			    offset = dissect_dbus_sig_container(tvb, dinfo, body_tree, offset, sig, &sig_ret, &val);
			    sig = sig_ret;
//			    sig++;
//			    offset++;
			}
			else /* CHK_DBUS_SIGN_CONTAINER(*sig) */
			{
			    offset = dissect_dbus_sig_basic(tvb, dinfo, body_tree, offset, *sig, &val, -1, NULL);
			    sig += 1;
			}

			if (offset == -1)
				return -1;


		}

		proto_item_set_end(ti, tvb, offset);

	} else if (dinfo->body_len || dinfo->body_sig[0]) {
		/* XXX smth wrong */
	}
	return offset;
}

static int
dissect_dbus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	proto_tree *dbus_tree = NULL;
	dbus_info_t dinfo;

	int offset;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "D-BUS");
	col_clear(pinfo->cinfo, COL_INFO);

	memset(&dinfo, 0, sizeof(dinfo));
	dinfo.pinfo = pinfo;
	switch (tvb_get_guint8(tvb, 0)) {
		case 'l':
			dinfo.enc   = ENC_LITTLE_ENDIAN;
			dinfo.get16 = tvb_get_letohs;
			dinfo.get32 = tvb_get_letohl;
			dinfo.getdouble = tvb_get_letohieee_double;
			dinfo.get64 = tvb_get_letoh64;
			break;
		case 'B':
			dinfo.enc   = ENC_BIG_ENDIAN;
			dinfo.get16 = tvb_get_ntohs;
			dinfo.get32 = tvb_get_ntohl;
			dinfo.getdouble = tvb_get_ntohieee_double;
			dinfo.get64 = tvb_get_ntoh64;
			break;
		default:	/* same as BIG_ENDIAN */
			/* XXX we should probably return 0; */
			dinfo.enc   = ENC_NA;
			dinfo.get16 = tvb_get_ntohs;
			dinfo.get32 = tvb_get_ntohl;
			dinfo.getdouble = tvb_get_ntohieee_double;
	}

	if (tree) {
		proto_item *ti = proto_tree_add_item(tree, hfi_dbus, tvb, 0, -1, ENC_NA);
		dbus_tree = proto_item_add_subtree(ti, ett_dbus);
	}

	DEBUGLOG_TVB_DUMP(tvb, 0, tvb_length(tvb));

	offset = 0;
	offset = dissect_dbus_hdr(tvb, &dinfo, dbus_tree, offset);
	offset = dissect_dbus_hdr_fields(tvb, &dinfo, dbus_tree, offset);
	/* header aligned to 8B */
	offset = DBUS_ALIGN_VALUE(offset, 8);

	if (!dinfo.body_sig)
		dinfo.body_sig = "";

	dbus_body_parser_test_record_start();

	offset = dissect_dbus_body(tvb, &dinfo, dbus_tree, offset);

	dbus_body_parser_test_print_text();

	dbus_body_parser_test_record_stop();
	return offset;
}

#define DBUS_HEADER_LEN 16

static guint
get_dbus_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
	guint32 (*get_guint32)(tvbuff_t *, const gint);

	guint32 len_body, len_hdr;

	switch (tvb_get_guint8(tvb, offset)) {
		case 'l':
			get_guint32 = tvb_get_letohl;
			break;
		case 'B':
		default:
			get_guint32 = tvb_get_ntohl;
			break;
	}

	len_hdr = DBUS_HEADER_LEN + get_guint32(tvb, offset + 12);
	len_hdr = DBUS_ALIGN_VALUE(len_hdr, 8);

	len_body = get_guint32(tvb, offset + 4);

	return len_hdr + len_body;
}

static int
dissect_dbus_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	return dissect_dbus(tvb, pinfo, tree, data);
}

static int
dissect_dbus_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	tcp_dissect_pdus(tvb, pinfo, tree, dbus_desegment, DBUS_HEADER_LEN, get_dbus_message_len, dissect_dbus_pdu, data);
	return tvb_length(tvb);
}


void
proto_register_dbus(void)
{
#ifndef HAVE_HFI_SECTION_INIT
	static header_field_info *hfi[] = {
	/* Header */
		&hfi_dbus_hdr,
		&hfi_dbus_hdr_endianness,
		&hfi_dbus_hdr_type,
		&hfi_dbus_hdr_flags,
		&hfi_dbus_hdr_version,
		&hfi_dbus_hdr_body_length,
		&hfi_dbus_hdr_serial,
		&hfi_dbus_hdr_fields_length,

	/* Header field */
		&hfi_dbus_hdr_field,
        &hfi_dbus_hdr_field_code,
        &hfi_dbus_type_signature,
        &hfi_dbus_object_path,
        &hfi_dbus_interface,
        &hfi_dbus_member,
        &hfi_dbus_error_name,
        &hfi_dbus_reply_serial,
        &hfi_dbus_destination,
        &hfi_dbus_sender,
        &hfi_dbus_body_signature,
        &hfi_dbus_unix_fds,

#if DBUSDUMP_HDR_FIELD_EXT_PID_PATH
        &hfi_dbus_destination_pid,
        &hfi_dbus_destination_cmdline,
        &hfi_dbus_sender_pid,
        &hfi_dbus_sender_cmdline,
#endif

		&hfi_dbus_body,
	/* Values */
		&hfi_dbus_value_bool,
		&hfi_dbus_value_number_int,
		&hfi_dbus_value_number_uint,
		&hfi_dbus_value_number_int64,
		&hfi_dbus_value_number_uint64,
		&hfi_dbus_value_str,
		&hfi_dbus_value_double,
	};
#endif

	static gint *ett[] = {
		&ett_dbus,
		&ett_dbus_hdr,
		&ett_dbus_body,
		&ett_dbus_field,
		&ett_dbus_error_reply
	};

	static ei_register_info ei[] = {
		{ &ei_dbus_value_bool_invalid, { "dbus.value.bool.invalid", PI_PROTOCOL, PI_WARN, "Invalid boolean value", EXPFILL }},
		{ &ei_dbus_value_str_invalid, { "dbus.value.str.invalid", PI_PROTOCOL, PI_WARN, "Invalid string (not UTF-8)", EXPFILL }},
		{ &ei_dbus_invalid_object_path, { "dbus.invalid_object_path", PI_PROTOCOL, PI_WARN, "Invalid object_path", EXPFILL }},
		{ &ei_dbus_invalid_signature, { "dbus.invalid_signature", PI_PROTOCOL, PI_WARN, "Invalid signature", EXPFILL }},
		{ &ei_dbus_error_reply, { "dbus.error_reply", PI_PROTOCOL, PI_WARN, "Reply with ERROR_NAME", EXPFILL }},
		{ &ei_dbus_info_dict_key, { "dbus.hf_dict_key", PI_PROTOCOL, PI_NOTE, "Dictionary key", EXPFILL }},

#if DBUSDUMP_HDR_FIELD_EXT_PID_PATH
		{ &ei_dbus_info_hf_ext, { "dbus.hf_ext", PI_PROTOCOL, PI_NOTE, "Extension Header Field (not avail in spec v0.26), only custom for dbusdump pcap file", EXPFILL }},
#endif

	};

	expert_module_t *expert_dbus;

	int proto_dbus;

	proto_dbus = proto_register_protocol("yD-Bus", "yD-BUS", "ydbus");
	hfi_dbus = proto_registrar_get_nth(proto_dbus);

	proto_register_fields(proto_dbus, hfi, array_length(hfi));
	proto_register_subtree_array(ett, array_length(ett));
	expert_dbus = expert_register_protocol(proto_dbus);
	expert_register_field_array(expert_dbus, ei, array_length(ei));

	dbus_handle = new_create_dissector_handle(dissect_dbus, proto_dbus);
	dbus_handle_tcp = new_create_dissector_handle(dissect_dbus_tcp, proto_dbus);

}

void
proto_reg_handoff_dbus(void)
{
	dissector_add_uint("wtap_encap", WTAP_ENCAP_DBUS, dbus_handle);
	dissector_add_handle("tcp.port", dbus_handle_tcp);
}

