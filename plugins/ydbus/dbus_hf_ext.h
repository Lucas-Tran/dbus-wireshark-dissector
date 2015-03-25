/* dbus_hf_ext.h
 * Routines for D-Bus dissection
 * Copyright 2015, Lucas Hong Tran <hongtd2k@gmail.com>
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
#ifndef _DBUS_HF_EXT_H
#define _DBUS_HF_EXT_H

#define DBUSDUMP_HDR_FIELD_EXT_PID_PATH             1

#define DBUS_HEADER_FIELD_EXT_SENDER_PID            103
#define DBUS_HEADER_FIELD_EXT_SENDER_CMDLINE        104
#define DBUS_HEADER_FIELD_EXT_DEST_PID              105
#define DBUS_HEADER_FIELD_EXT_DEST_CMDLINE          106

#endif
