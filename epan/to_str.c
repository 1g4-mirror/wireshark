/* to_str.c
 * Routines for utilities to convert various other types to strings.
 *
 * $Id: to_str.c,v 1.13 2001/09/14 07:23:33 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_WINSOCK_H
# include <winsock.h>   /* for "u_char" */
#endif

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef NEED_INET_V6DEFS_H
# include "inet_v6defs.h"
#endif

#include "to_str.h"
#include "resolv.h"
#include "pint.h"
#include <stdio.h>
#include <time.h>


/* Wrapper for the most common case of asking
 * for a string using a colon as the hex-digit separator.
 */

gchar *
ether_to_str(const guint8 *ad)
{
	return ether_to_str_punct(ad, ':');
}

/* Places char punct in the string as the hex-digit separator.
 * If punct is '\0', no punctuation is applied (and thus
 * the resulting string is 5 bytes shorter)
 */
gchar *
ether_to_str_punct(const guint8 *ad, char punct) {
  static gchar  str[3][18];
  static gchar *cur;
  gchar        *p;
  int          i;
  guint32      octet;
  static const gchar hex_digits[16] = "0123456789abcdef";

  if (cur == &str[0][0]) {
    cur = &str[1][0];
  } else if (cur == &str[1][0]) {  
    cur = &str[2][0];
  } else {  
    cur = &str[0][0];
  }
  p = &cur[18];
  *--p = '\0';
  i = 5;
  for (;;) {
    octet = ad[i];
    *--p = hex_digits[octet&0xF];
    octet >>= 4;
    *--p = hex_digits[octet&0xF];
    if (i == 0)
      break;
    if (punct)
      *--p = punct;
    i--;
  }
  return p;
}

gchar *
ip_to_str(const guint8 *ad) {
  static gchar  str[4][16];
  static gchar *cur;

  if (cur == &str[0][0]) {
    cur = &str[1][0];
  } else if (cur == &str[1][0]) {
    cur = &str[2][0];
  } else if (cur == &str[2][0]) {
    cur = &str[3][0];
  } else {  
    cur = &str[0][0];
  }
  ip_to_str_buf(ad, cur);
  return cur;
}

void
ip_to_str_buf(const guint8 *ad, gchar *buf)
{
  gchar        *p;
  int           i;
  guint32       octet;
  guint32       digit;
  gboolean      saw_nonzero;

  p = buf;
  i = 0;
  for (;;) {
    saw_nonzero = FALSE;
    octet = ad[i];
    digit = octet/100;
    if (digit != 0) {
      *p++ = digit + '0';
      saw_nonzero = TRUE;
    }
    octet %= 100;
    digit = octet/10;
    if (saw_nonzero || digit != 0)
      *p++ = digit + '0';
    digit = octet%10;
    *p++ = digit + '0';
    if (i == 3)
      break;
    *p++ = '.';
    i++;
  }
  *p = '\0';
}

gchar *
ip6_to_str(struct e_in6_addr *ad) {
#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif
  static gchar buf[INET6_ADDRSTRLEN];

  inet_ntop(AF_INET6, (u_char*)ad, (gchar*)buf, sizeof(buf));
  return buf;
}

gchar*
ipx_addr_to_str(guint32 net, const guint8 *ad)
{
	static gchar	str[3][8+1+MAXNAMELEN+1]; /* 8 digits, 1 period, NAME, 1 null */
	static gchar	*cur;
	char		*name;

	if (cur == &str[0][0]) {
		cur = &str[1][0];
	} else if (cur == &str[1][0]) {
		cur = &str[2][0];
	} else {
		cur = &str[0][0];
	}

	name = get_ether_name_if_known(ad);

	if (name) {
		sprintf(cur, "%s.%s", get_ipxnet_name(net), name);
	}
	else {
		sprintf(cur, "%s.%s", get_ipxnet_name(net), ether_to_str_punct(ad, '\0'));
	}
	return cur;
}

gchar*
ipxnet_to_string(const guint8 *ad)
{
	guint32	addr = pntohl(ad);
	return ipxnet_to_str_punct(addr, ' ');
}

gchar *
ipxnet_to_str_punct(const guint32 ad, char punct)
{
  static gchar  str[3][12];
  static gchar *cur;
  gchar        *p;
  int          i;
  guint32      octet;
  static const gchar hex_digits[16] = "0123456789ABCDEF";
  static const guint32  octet_mask[4] =
	  { 0xff000000 , 0x00ff0000, 0x0000ff00, 0x000000ff };

  if (cur == &str[0][0]) {
    cur = &str[1][0];
  } else if (cur == &str[1][0]) {  
    cur = &str[2][0];
  } else {  
    cur = &str[0][0];
  }
  p = &cur[12];
  *--p = '\0';
  i = 3;
  for (;;) {
    octet = (ad & octet_mask[i]) >> ((3 - i) * 8);
    *--p = hex_digits[octet&0xF];
    octet >>= 4;
    *--p = hex_digits[octet&0xF];
    if (i == 0)
      break;
    if (punct)
      *--p = punct;
    i--;
  }
  return p;
}

gchar *
vines_addr_to_str(const guint8 *addrp)
{
  static gchar	str[3][214];
  static gchar	*cur;

  if (cur == &str[0][0]) {
    cur = &str[1][0];
  } else if (cur == &str[1][0]) {
    cur = &str[2][0];
  } else {
    cur = &str[0][0];
  }

  sprintf(cur, "%08x.%04x", pntohl(&addrp[0]), pntohs(&addrp[4]));
  return cur;
}

#define	PLURALIZE(n)	(((n) > 1) ? "s" : "")
#define	COMMA(do_it)	((do_it) ? ", " : "")

/*
 * Maximum length of a string showing days/hours/minutes/seconds.
 * (Does not include the terminating '\0'.)
 */
#define TIME_SECS_LEN	(8+1+4+2+2+5+2+2+7+2+2+7)

/*
 * Convert a value in seconds and fractions of a second to a string,
 * giving time in days, hours, minutes, and seconds, and put the result
 * into a buffer.
 * "is_nsecs" says that "frac" is microseconds if true and milliseconds
 * if false.
 */
static void
time_secs_to_str_buf(guint32 time, guint32 frac, gboolean is_nsecs,
			   gchar *buf)
{
  static gchar *p;
  int hours, mins, secs;
  int do_comma;

  secs = time % 60;
  time /= 60;
  mins = time % 60;
  time /= 60;
  hours = time % 24;
  time /= 24;

  p = buf;
  if (time != 0) {
    sprintf(p, "%u day%s", time, PLURALIZE(time));
    p += strlen(p);
    do_comma = 1;
  } else
    do_comma = 0;
  if (hours != 0) {
    sprintf(p, "%s%u hour%s", COMMA(do_comma), hours, PLURALIZE(hours));
    p += strlen(p);
    do_comma = 1;
  } else
    do_comma = 0;
  if (mins != 0) {
    sprintf(p, "%s%u minute%s", COMMA(do_comma), mins, PLURALIZE(mins));
    p += strlen(p);
    do_comma = 1;
  } else
    do_comma = 0;
  if (secs != 0 || frac != 0) {
    if (frac != 0) {
      if (is_nsecs)
        sprintf(p, "%s%u.%09u seconds", COMMA(do_comma), secs, frac);
      else
        sprintf(p, "%s%u.%03u seconds", COMMA(do_comma), secs, frac);
    } else
      sprintf(p, "%s%u second%s", COMMA(do_comma), secs, PLURALIZE(secs));
  }
}

gchar *
time_secs_to_str(guint32 time)
{
  static gchar  str[3][TIME_SECS_LEN+1];
  static gchar *cur;

  if (cur == &str[0][0]) {
    cur = &str[1][0];
  } else if (cur == &str[1][0]) {  
    cur = &str[2][0];
  } else {  
    cur = &str[0][0];
  }

  if (time == 0) {
    sprintf(cur, "0 time");
    return cur;
  }

  time_secs_to_str_buf(time, 0, FALSE, cur);
  return cur;
}

gchar *
time_msecs_to_str(guint32 time)
{
  static gchar  str[3][TIME_SECS_LEN+1+3+1];
  static gchar *cur;
  int msecs;

  if (cur == &str[0][0]) {
    cur = &str[1][0];
  } else if (cur == &str[1][0]) {  
    cur = &str[2][0];
  } else {  
    cur = &str[0][0];
  }

  if (time == 0) {
    sprintf(cur, "0 time");
    return cur;
  }

  msecs = time % 1000;
  time /= 1000;

  time_secs_to_str_buf(time, msecs, FALSE, cur);
  return cur;
}

static const char *mon_names[12] = {
	"Jan",
	"Feb",
	"Mar",
	"Apr",
	"May",
	"Jun",
	"Jul",
	"Aug",
	"Sep",
	"Oct",
	"Nov",
	"Dec"
};

gchar *
abs_time_to_str(nstime_t *abs_time)
{
        struct tm *tmp;
        static gchar *cur;
        static char str[3][3+1+2+2+4+1+2+1+2+1+2+1+6+1 + 5 /* extra */];

        if (cur == &str[0][0]) {
                cur = &str[1][0];
        } else if (cur == &str[1][0]) {
                cur = &str[2][0];
        } else {
                cur = &str[0][0];
        }

        tmp = localtime(&abs_time->secs);
        if (tmp) {
          sprintf(cur, "%s %2d, %d %02d:%02d:%02d.%09ld",
                  mon_names[tmp->tm_mon],
                  tmp->tm_mday,
                  tmp->tm_year + 1900,
                  tmp->tm_hour,
                  tmp->tm_min,
                  tmp->tm_sec,
                  (long)abs_time->nsecs);
        } else {
          strncpy(cur, "Not representable", sizeof(str[0]));
        }
        return cur;
}

void
display_signed_time(gchar *buf, int buflen, gint32 sec, gint32 frac,
    time_res_t units)
{
	char *sign;

	/* If the fractional part of the time stamp is negative,
	   print its absolute value and, if the seconds part isn't
	   (the seconds part should be zero in that case), stick
	   a "-" in front of the entire time stamp. */
	sign = "";
	if (frac < 0) {
		frac = -frac;
		if (sec >= 0)
			sign = "-";
	}
	switch (units) {

	case MSECS:
		snprintf(buf, buflen, "%s%d.%03d", sign, sec, frac);
		break;

	case USECS:
		snprintf(buf, buflen, "%s%d.%06d", sign, sec, frac);
		break;

	case NSECS:
		snprintf(buf, buflen, "%s%d.%09d", sign, sec, frac);
		break;
	}
}

/*
 * Display a relative time as days/hours/minutes/seconds.
 */
gchar *
rel_time_to_str(nstime_t *rel_time)
{
	static gchar *cur;
	static char str[3][1+TIME_SECS_LEN+1+6+1];
	char *p;
	char *sign;
	guint32 time;
	gint32 nsec;

	if (cur == &str[0][0]) {
		cur = &str[1][0];
	} else if (cur == &str[1][0]) {
		cur = &str[2][0];
	} else {
		cur = &str[0][0];
	}
	p = cur;

	/* If the nanoseconds part of the time stamp is negative,
	   print its absolute value and, if the seconds part isn't
	   (the seconds part should be zero in that case), stick
	   a "-" in front of the entire time stamp. */
	sign = "";
	time = rel_time->secs;
	nsec = rel_time->nsecs;
	if (time == 0 && nsec == 0) {
		sprintf(cur, "0.000000000 seconds");
		return cur;
	}
	if (nsec < 0) {
		nsec = -nsec;
		*p++ = '-';

		/*
		 * We assume here that "rel_time->secs" is negative
		 * or zero; if it's not, the time stamp is bogus,
		 * with a positive seconds and negative microseconds.
		 */
		time = -rel_time->secs;
	}

	time_secs_to_str_buf(time, nsec, TRUE, p);
	return cur;
}

#define REL_TIME_SECS_LEN	(1+10+1+9+1)

/*
 * Display a relative time as seconds.
 */
gchar *
rel_time_to_secs_str(nstime_t *rel_time)
{
        static gchar *cur;
        static char str[3][REL_TIME_SECS_LEN];

        if (cur == &str[0][0]) {
                cur = &str[1][0];
        } else if (cur == &str[1][0]) {
                cur = &str[2][0];
        } else {
                cur = &str[0][0];
        }

        display_signed_time(cur, REL_TIME_SECS_LEN, rel_time->secs,
            rel_time->nsecs, NSECS);
        return cur;
}

/* Generate, into "buf", a string showing the bits of a bitfield.
   Return a pointer to the character after that string. */
char *
decode_bitfield_value(char *buf, guint32 val, guint32 mask, int width)
{
  int i;
  guint32 bit;
  char *p;

  i = 0;
  p = buf;
  bit = 1 << (width - 1);
  for (;;) {
    if (mask & bit) {
      /* This bit is part of the field.  Show its value. */
      if (val & bit)
        *p++ = '1';
      else
        *p++ = '0';
    } else {
      /* This bit is not part of the field. */
      *p++ = '.';
    }
    bit >>= 1;
    i++;
    if (i >= width)
      break;
    if (i % 4 == 0)
      *p++ = ' ';
  }
  strcpy(p, " = ");
  p += 3;
  return p;
}

/* Generate a string describing a Boolean bitfield (a one-bit field that
   says something is either true of false). */
const char *
decode_boolean_bitfield(guint32 val, guint32 mask, int width,
    const char *truedesc, const char *falsedesc)
{
  static char buf[1025];
  char *p;

  p = decode_bitfield_value(buf, val, mask, width);
  if (val & mask)
    strcpy(p, truedesc);
  else
    strcpy(p, falsedesc);
  return buf;
}

/* Generate a string describing a numeric bitfield (an N-bit field whose
   value is just a number). */
const char *
decode_numeric_bitfield(guint32 val, guint32 mask, int width,
    const char *fmt)
{
  static char buf[1025];
  char *p;
  int shift = 0;

  /* Compute the number of bits we have to shift the bitfield right
     to extract its value. */
  while ((mask & (1<<shift)) == 0)
    shift++;

  p = decode_bitfield_value(buf, val, mask, width);
  sprintf(p, fmt, (val & mask) >> shift);
  return buf;
}



