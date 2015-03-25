/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/* dbus-protocol.h  D-Bus protocol constants
 *
 * Copyright (C) 2002, 2003  CodeFactory AB
 * Copyright (C) 2004, 2005 Red Hat, Inc.
 *
 * Licensed under the Academic Free License version 2.1
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifndef DBUS_PROTOCOL_H
#define DBUS_PROTOCOL_H


/* Message byte order */
#define DBUS_LITTLE_ENDIAN ('l')  /**< Code marking LSB-first byte order in the wire protocol. */
#define DBUS_BIG_ENDIAN    ('B')  /**< Code marking MSB-first byte order in the wire protocol. */

/** Protocol version. */
#define DBUS_MAJOR_PROTOCOL_VERSION 1

/** Type code that is never equal to a legitimate type code */
#define DBUS_TYPE_INVALID       ((char) '\0')
/** #DBUS_TYPE_INVALID as a string literal instead of a int literal */
#define DBUS_TYPE_INVALID_AS_STRING        "\0"

/* Primitive types */
/** Type code marking an 8-bit unsigned integer */
#define DBUS_TYPE_BYTE          ((char) 'y')
/** #DBUS_TYPE_BYTE as a string literal instead of a int literal */
#define DBUS_TYPE_BYTE_AS_STRING           "y"
/** Type code marking a boolean */
#define DBUS_TYPE_BOOLEAN       ((char) 'b')
/** #DBUS_TYPE_BOOLEAN as a string literal instead of a int literal */
#define DBUS_TYPE_BOOLEAN_AS_STRING        "b"
/** Type code marking a 16-bit signed integer */
#define DBUS_TYPE_INT16         ((char) 'n')
/** #DBUS_TYPE_INT16 as a string literal instead of a int literal */
#define DBUS_TYPE_INT16_AS_STRING          "n"
/** Type code marking a 16-bit unsigned integer */
#define DBUS_TYPE_UINT16        ((char) 'q')
/** #DBUS_TYPE_UINT16 as a string literal instead of a int literal */
#define DBUS_TYPE_UINT16_AS_STRING         "q"
/** Type code marking a 32-bit signed integer */
#define DBUS_TYPE_INT32         ((char) 'i')
/** #DBUS_TYPE_INT32 as a string literal instead of a int literal */
#define DBUS_TYPE_INT32_AS_STRING          "i"
/** Type code marking a 32-bit unsigned integer */
#define DBUS_TYPE_UINT32        ((char) 'u')
/** #DBUS_TYPE_UINT32 as a string literal instead of a int literal */
#define DBUS_TYPE_UINT32_AS_STRING         "u"
/** Type code marking a 64-bit signed integer */
#define DBUS_TYPE_INT64         ((char) 'x')
/** #DBUS_TYPE_INT64 as a string literal instead of a int literal */
#define DBUS_TYPE_INT64_AS_STRING          "x"
/** Type code marking a 64-bit unsigned integer */
#define DBUS_TYPE_UINT64        ((char) 't')
/** #DBUS_TYPE_UINT64 as a string literal instead of a int literal */
#define DBUS_TYPE_UINT64_AS_STRING         "t"
/** Type code marking an 8-byte double in IEEE 754 format */
#define DBUS_TYPE_DOUBLE        ((char) 'd')
/** #DBUS_TYPE_DOUBLE as a string literal instead of a int literal */
#define DBUS_TYPE_DOUBLE_AS_STRING         "d"
/** Type code marking a UTF-8 encoded, nul-terminated Unicode string */
#define DBUS_TYPE_STRING        ((char) 's')
/** #DBUS_TYPE_STRING as a string literal instead of a int literal */
#define DBUS_TYPE_STRING_AS_STRING         "s"
/** Type code marking a D-Bus object path */
#define DBUS_TYPE_OBJECT_PATH   ((char) 'o')
/** #DBUS_TYPE_OBJECT_PATH as a string literal instead of a int literal */
#define DBUS_TYPE_OBJECT_PATH_AS_STRING    "o"
/** Type code marking a D-Bus type signature */
#define DBUS_TYPE_SIGNATURE     ((char) 'g')
/** #DBUS_TYPE_SIGNATURE as a string literal instead of a int literal */
#define DBUS_TYPE_SIGNATURE_AS_STRING      "g"
/** Type code marking a unix file descriptor */
#define DBUS_TYPE_UNIX_FD      ((char) 'h')
/** #DBUS_TYPE_UNIX_FD as a string literal instead of a int literal */
#define DBUS_TYPE_UNIX_FD_AS_STRING        "h"

/* Compound types */
/** Type code marking a D-Bus array type */
#define DBUS_TYPE_ARRAY         ((char) 'a')
/** #DBUS_TYPE_ARRAY as a string literal instead of a int literal */
#define DBUS_TYPE_ARRAY_AS_STRING          "a"
/** Type code marking a D-Bus variant type */
#define DBUS_TYPE_VARIANT       ((char) 'v')
/** #DBUS_TYPE_VARIANT as a string literal instead of a int literal */
#define DBUS_TYPE_VARIANT_AS_STRING        "v"

/** STRUCT and DICT_ENTRY are sort of special since their codes can't
 * appear in a type string, instead
 * DBUS_STRUCT_BEGIN_CHAR/DBUS_DICT_ENTRY_BEGIN_CHAR have to appear
 */
/** Type code used to represent a struct; however, this type code does not appear
 * in type signatures, instead #DBUS_STRUCT_BEGIN_CHAR and #DBUS_STRUCT_END_CHAR will
 * appear in a signature.
 */
#define DBUS_TYPE_STRUCT        ((char) 'r')
/** #DBUS_TYPE_STRUCT as a string literal instead of a int literal */
#define DBUS_TYPE_STRUCT_AS_STRING         "r"
/** Type code used to represent a dict entry; however, this type code does not appear
 * in type signatures, instead #DBUS_DICT_ENTRY_BEGIN_CHAR and #DBUS_DICT_ENTRY_END_CHAR will
 * appear in a signature.
 */
#define DBUS_TYPE_DICT_ENTRY    ((char) 'e')
/** #DBUS_TYPE_DICT_ENTRY as a string literal instead of a int literal */
#define DBUS_TYPE_DICT_ENTRY_AS_STRING     "e"

/** Does not include #DBUS_TYPE_INVALID, #DBUS_STRUCT_BEGIN_CHAR, #DBUS_STRUCT_END_CHAR,
 * #DBUS_DICT_ENTRY_BEGIN_CHAR, or #DBUS_DICT_ENTRY_END_CHAR - i.e. it is the number of
 * valid types, not the number of distinct characters that may appear in a type signature.
 */
#define DBUS_NUMBER_OF_TYPES    (16)

/* characters other than typecodes that appear in type signatures */

/** Code marking the start of a struct type in a type signature */
#define DBUS_STRUCT_BEGIN_CHAR   ((char) '(')
/** #DBUS_STRUCT_BEGIN_CHAR as a string literal instead of a int literal */
#define DBUS_STRUCT_BEGIN_CHAR_AS_STRING   "("
/** Code marking the end of a struct type in a type signature */
#define DBUS_STRUCT_END_CHAR     ((char) ')')
/** #DBUS_STRUCT_END_CHAR a string literal instead of a int literal */
#define DBUS_STRUCT_END_CHAR_AS_STRING     ")"
/** Code marking the start of a dict entry type in a type signature */
#define DBUS_DICT_ENTRY_BEGIN_CHAR   ((char) '{')
/** #DBUS_DICT_ENTRY_BEGIN_CHAR as a string literal instead of a int literal */
#define DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING   "{"
/** Code marking the end of a dict entry type in a type signature */
#define DBUS_DICT_ENTRY_END_CHAR     ((char) '}')
/** #DBUS_DICT_ENTRY_END_CHAR as a string literal instead of a int literal */
#define DBUS_DICT_ENTRY_END_CHAR_AS_STRING     "}"


#define DBUS_HEADER_FIELD_INVALID        0
#define DBUS_HEADER_FIELD_PATH           1
#define DBUS_HEADER_FIELD_INTERFACE      2
#define DBUS_HEADER_FIELD_MEMBER         3
#define DBUS_HEADER_FIELD_ERROR_NAME     4
#define DBUS_HEADER_FIELD_REPLY_SERIAL   5
#define DBUS_HEADER_FIELD_DESTINATION    6
#define DBUS_HEADER_FIELD_SENDER         7
#define DBUS_HEADER_FIELD_SIGNATURE      8
#define DBUS_HEADER_FIELD_UNIX_FDS       9

#define DBUS_MESSAGE_TYPE_INVALID 0
#define DBUS_MESSAGE_TYPE_METHOD_CALL 1
#define DBUS_MESSAGE_TYPE_METHOD_RETURN 2
#define DBUS_MESSAGE_TYPE_ERROR 3
#define DBUS_MESSAGE_TYPE_SIGNAL 4


#define DBUS_HEADER_LEN 16
#endif /* DBUS_PROTOCOL_H */
