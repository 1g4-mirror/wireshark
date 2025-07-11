/* main.c
 *
 * $Id: main.c,v 1.232 2002/02/08 10:07:38 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Richard Sharpe, 13-Feb-1999, added support for initializing structures
 *                              needed by dissect routines
 * Jeff Foster,    2001/03/12,  added support tabbed hex display windowss
 * 
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
 *
 *
 * To do:
 * - Graphs
 * - Check for end of packet in dissect_* routines.
 * - Playback window
 * - Multiple window support
 * - Add cut/copy/paste
 * - Create header parsing routines
 * - Make byte view selections more fancy?
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <gtk/gtk.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <errno.h>

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_IO_H
#include <io.h> /* open/close on win32 */
#endif

#ifdef HAVE_DIRECT_H
#include <direct.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include <signal.h>

#ifdef HAVE_LIBPCAP
#include <pcap.h>
#endif

#ifdef HAVE_LIBZ
#include <zlib.h>	/* to get the libz version number */
#endif

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#if defined(HAVE_UCD_SNMP_SNMP_H)
#ifdef HAVE_UCD_SNMP_VERSION_H
#include <ucd-snmp/version.h>
#endif /* HAVE_UCD_SNMP_VERSION_H */
#elif defined(HAVE_SNMP_SNMP_H)
#ifdef HAVE_SNMP_VERSION_H
#include <snmp/version.h>
#endif /* HAVE_SNMP_VERSION_H */
#endif /* SNMP */

#ifdef NEED_STRERROR_H
#include "strerror.h"
#endif

#ifdef NEED_GETOPT_H
#include "getopt.h"
#endif

#ifdef WIN32 /* Needed for console I/O */
#include <fcntl.h>
#include <conio.h>
#endif

#include <epan/epan.h>
#include <epan/filesystem.h>
#include <epan/epan_dissect.h>

#include "main.h"
#include <epan/timestamp.h>
#include <epan/packet.h>
#include "capture.h"
#include "summary.h"
#include "file.h"
#include "filters.h"
#include "prefs.h"
#include "menu.h"
#include "../menu.h"
#include "color.h"
#include "color_utils.h"
#include "filter_prefs.h"
#include "file_dlg.h"
#include "column.h"
#include "print.h"
#include <epan/resolv.h>
#ifdef HAVE_LIBPCAP
#include "pcap-util.h"
#endif
#include "statusbar.h"
#include "simple_dialog.h"
#include "proto_draw.h"
#include <epan/dfilter/dfilter.h>
#include "keys.h"
#include "packet_win.h"
#include "gtkglobals.h"
#include <epan/plugins.h>
#include "colors.h"
#include <epan/strutil.h>
#include "register.h"
#include "ringbuffer.h"
#include "ui_util.h"
#include "image/clist_ascend.xpm"
#include "image/clist_descend.xpm"

#ifdef WIN32
#include "capture-wpcap.h"
#endif

typedef struct column_arrows {
  GtkWidget *table;
  GtkWidget *ascend_pm;
  GtkWidget *descend_pm;
} column_arrows;

capture_file cfile;
GtkWidget   *top_level, *packet_list, *tree_view, *byte_nb_ptr,
            *tv_scrollw, *pkt_scrollw;
static GtkWidget	*info_bar, *bv_scrollw;
GdkFont     *m_r_font, *m_b_font;
guint		m_font_height, m_font_width;
static guint    main_ctx, file_ctx, help_ctx;
static GString *comp_info_str;
gchar       *ethereal_path = NULL;
gchar       *last_open_dir = NULL;
gint   root_x = G_MAXINT, root_y = G_MAXINT, top_width, top_height;

ts_type timestamp_type = RELATIVE;

GtkStyle *item_style;

/* Specifies the field currently selected in the GUI protocol tree */
field_info *finfo_selected = NULL;

#ifdef WIN32
static gboolean has_no_console;	/* TRUE if app has no console */
static gboolean console_was_created; /* TRUE if console was created */
static void create_console(void);
static void destroy_console(void);
static void console_log_handler(const char *log_domain,
    GLogLevelFlags log_level, const char *message, gpointer user_data);
#endif

static void create_main_window(gint, gint, gint, e_prefs*);

/* About Ethereal window */
void
about_ethereal( GtkWidget *w, gpointer data ) {
  simple_dialog(ESD_TYPE_INFO, NULL,
		"Ethereal - Network Protocol Analyzer\n"
		"Version " VERSION " (C) 1998-2000 Gerald Combs <gerald@ethereal.com>\n"
                "Compiled %s\n\n"

		"Check the man page for complete documentation and\n"
		"for the list of contributors.\n"

		"\nSee http://www.ethereal.com/ for more information.",
                 comp_info_str->str);
}

void
set_fonts(GdkFont *regular, GdkFont *bold)
{
	/* Yes, assert. The code that loads the font should check
	 * for NULL and provide its own error message. */
	g_assert(m_r_font && m_b_font);
	m_r_font = regular;
	m_b_font = bold;

	m_font_height = m_r_font->ascent + m_r_font->descent;
	m_font_width = gdk_string_width(m_r_font, "0");
}


/* Match selected byte pattern */
void
match_selected_cb_do(gpointer data, int action, gchar *text)
{
    char		*ptr;
    GtkWidget		*filter_te;

    if (!text)
	return;
    g_assert(data);
    filter_te = gtk_object_get_data(GTK_OBJECT(data), E_DFILTER_TE_KEY);
    g_assert(filter_te);

    ptr = gtk_editable_get_chars(GTK_EDITABLE(filter_te),0,-1);

    switch (action&MATCH_SELECTED_MASK) {

    case MATCH_SELECTED_REPLACE:
	ptr = g_strdup(text);
	break;

    case MATCH_SELECTED_AND:
	if ((!ptr) || (0 == strlen(ptr)))
	    ptr = g_strdup(text);
	else
	    ptr = g_strconcat("(", ptr, ") && (", text, ")", NULL);
	break;

    case MATCH_SELECTED_OR:
	if ((!ptr) || (0 == strlen(ptr)))
	    ptr = g_strdup(text);
	else
	    ptr = g_strconcat("(", ptr, ") || (", text, ")", NULL);
	break;

    case MATCH_SELECTED_NOT:
	ptr = g_strconcat("!(", text, ")", NULL);
	break;

    case MATCH_SELECTED_AND_NOT:
	if ((!ptr) || (0 == strlen(ptr)))
	    ptr = g_strconcat("!(", text, ")", NULL);
	else
	    ptr = g_strconcat("(", ptr, ") && !(", text, ")", NULL);
	break;

    case MATCH_SELECTED_OR_NOT:
	if ((!ptr) || (0 == strlen(ptr)))
	    ptr = g_strconcat("!(", text, ")", NULL);
	else
	    ptr = g_strconcat("(", ptr, ") || !(", text, ")", NULL);
	break;

    default:
	break;
    }

    /* create a new one and set the display filter entry accordingly */
    gtk_entry_set_text(GTK_ENTRY(filter_te), ptr);

    /* Run the display filter so it goes in effect. */
    if (action&MATCH_SELECTED_APPLY_NOW)
	filter_packets(&cfile, ptr);

    /* Don't g_free(ptr) here. filter_packets() will do it the next time
       it's called. */
    g_free(text);
}

void
match_selected_cb_replace(GtkWidget *w, gpointer data)
{
    if (finfo_selected)
	match_selected_cb_do((data ? data : w),
	    MATCH_SELECTED_REPLACE|MATCH_SELECTED_APPLY_NOW,
	    proto_alloc_dfilter_string(finfo_selected, cfile.pd));
}

void
match_selected_cb_and(GtkWidget *w, gpointer data)
{
    if (finfo_selected)
	match_selected_cb_do((data ? data : w),
	    MATCH_SELECTED_AND|MATCH_SELECTED_APPLY_NOW,
	    proto_alloc_dfilter_string(finfo_selected, cfile.pd));
}

void
match_selected_cb_or(GtkWidget *w, gpointer data)
{
    if (finfo_selected)
	match_selected_cb_do((data ? data : w),
	    MATCH_SELECTED_OR|MATCH_SELECTED_APPLY_NOW,
	    proto_alloc_dfilter_string(finfo_selected, cfile.pd));
}

void
match_selected_cb_not(GtkWidget *w, gpointer data)
{
    if (finfo_selected)
	match_selected_cb_do((data ? data : w),
	    MATCH_SELECTED_NOT|MATCH_SELECTED_APPLY_NOW,
	    proto_alloc_dfilter_string(finfo_selected, cfile.pd));
}

void
match_selected_cb_and_not(GtkWidget *w, gpointer data)
{
    if (finfo_selected)
	match_selected_cb_do((data ? data : w),
	    MATCH_SELECTED_AND_NOT|MATCH_SELECTED_APPLY_NOW,
	    proto_alloc_dfilter_string(finfo_selected, cfile.pd));
}

void
match_selected_cb_or_not(GtkWidget *w, gpointer data)
{
    if (finfo_selected)
	match_selected_cb_do((data ? data : w),
	    MATCH_SELECTED_OR_NOT,
	    proto_alloc_dfilter_string(finfo_selected, cfile.pd));
}

void
prepare_selected_cb_replace(GtkWidget *w, gpointer data)
{
    if (finfo_selected)
	match_selected_cb_do((data ? data : w),
	    MATCH_SELECTED_REPLACE,
	    proto_alloc_dfilter_string(finfo_selected, cfile.pd));
}

void
prepare_selected_cb_and(GtkWidget *w, gpointer data)
{
    if (finfo_selected)
	match_selected_cb_do((data ? data : w),
	    MATCH_SELECTED_AND,
	    proto_alloc_dfilter_string(finfo_selected, cfile.pd));
}

void
prepare_selected_cb_or(GtkWidget *w, gpointer data)
{
    if (finfo_selected)
	match_selected_cb_do((data ? data : w),
	    MATCH_SELECTED_OR,
	    proto_alloc_dfilter_string(finfo_selected, cfile.pd));
}

void
prepare_selected_cb_not(GtkWidget *w, gpointer data)
{
    if (finfo_selected)
	match_selected_cb_do((data ? data : w),
	    MATCH_SELECTED_NOT,
	    proto_alloc_dfilter_string(finfo_selected, cfile.pd));
}

void
prepare_selected_cb_and_not(GtkWidget *w, gpointer data)
{
    if (finfo_selected)
	match_selected_cb_do((data ? data : w),
	    MATCH_SELECTED_AND_NOT,
	    proto_alloc_dfilter_string(finfo_selected, cfile.pd));
}

void
prepare_selected_cb_or_not(GtkWidget *w, gpointer data)
{
    if (finfo_selected)
	match_selected_cb_do((data ? data : w),
	    MATCH_SELECTED_OR_NOT,
	    proto_alloc_dfilter_string(finfo_selected, cfile.pd));
}

static gchar *
get_text_from_packet_list(gpointer data)
{
    gint	row = (gint)gtk_object_get_data(GTK_OBJECT(data), E_MPACKET_LIST_ROW_KEY);
    gint	column = (gint)gtk_object_get_data(GTK_OBJECT(data), E_MPACKET_LIST_COL_KEY);
    frame_data *fdata = (frame_data *)gtk_clist_get_row_data(GTK_CLIST(packet_list), row);
    epan_dissect_t *edt;
    gchar      *buf=NULL;
    int         len;

    if (fdata != NULL) {
	wtap_seek_read(cfile.wth, fdata->file_off, &cfile.pseudo_header,
		       cfile.pd, fdata->cap_len);

	edt = epan_dissect_new(FALSE, FALSE);
	epan_dissect_run(edt, &cfile.pseudo_header, cfile.pd, fdata,
			 &cfile.cinfo);
	epan_dissect_fill_in_columns(edt);

	if (strlen(cfile.cinfo.col_expr[column]) != 0 &&
	    strlen(cfile.cinfo.col_expr_val[column]) != 0) {
	    len = strlen(cfile.cinfo.col_expr[column]) +
		  strlen(cfile.cinfo.col_expr_val[column]) + 5;
	    buf = g_malloc0(len);
	    snprintf(buf, len, "%s == %s", cfile.cinfo.col_expr[column],
		     cfile.cinfo.col_expr_val[column]);
    	}

	epan_dissect_free(edt);
    }
	    
    return buf;
}

void
match_selected_cb_replace2(GtkWidget *w, gpointer data)
{
    match_selected_cb_do(data,
        MATCH_SELECTED_REPLACE|MATCH_SELECTED_APPLY_NOW,
        get_text_from_packet_list(data));
}

void
match_selected_cb_and2(GtkWidget *w, gpointer data)
{
    match_selected_cb_do(data,
        MATCH_SELECTED_AND|MATCH_SELECTED_APPLY_NOW,
        get_text_from_packet_list(data));
}

void
match_selected_cb_or2(GtkWidget *w, gpointer data)
{
    match_selected_cb_do(data,
        MATCH_SELECTED_OR|MATCH_SELECTED_APPLY_NOW,
        get_text_from_packet_list(data));
}

void
match_selected_cb_not2(GtkWidget *w, gpointer data)
{
    match_selected_cb_do(data,
        MATCH_SELECTED_NOT|MATCH_SELECTED_APPLY_NOW,
        get_text_from_packet_list(data));
}

void
match_selected_cb_and_not2(GtkWidget *w, gpointer data)
{
    match_selected_cb_do(data,
        MATCH_SELECTED_AND_NOT|MATCH_SELECTED_APPLY_NOW,
        get_text_from_packet_list(data));
}

void
match_selected_cb_or_not2(GtkWidget *w, gpointer data)
{
    match_selected_cb_do(data,
        MATCH_SELECTED_OR_NOT|MATCH_SELECTED_APPLY_NOW,
        get_text_from_packet_list(data));
}

void
prepare_selected_cb_replace2(GtkWidget *w, gpointer data)
{
    match_selected_cb_do(data,
        MATCH_SELECTED_REPLACE,
        get_text_from_packet_list(data));
}

void
prepare_selected_cb_and2(GtkWidget *w, gpointer data)
{
    match_selected_cb_do(data,
        MATCH_SELECTED_AND,
        get_text_from_packet_list(data));
}

void
prepare_selected_cb_or2(GtkWidget *w, gpointer data)
{
    match_selected_cb_do(data,
        MATCH_SELECTED_OR,
        get_text_from_packet_list(data));
}

void
prepare_selected_cb_not2(GtkWidget *w, gpointer data)
{
    match_selected_cb_do(data,
        MATCH_SELECTED_NOT,
        get_text_from_packet_list(data));
}

void
prepare_selected_cb_and_not2(GtkWidget *w, gpointer data)
{
    match_selected_cb_do(data,
        MATCH_SELECTED_AND_NOT,
        get_text_from_packet_list(data));
}

void
prepare_selected_cb_or_not2(GtkWidget *w, gpointer data)
{
    match_selected_cb_do(data,
        MATCH_SELECTED_OR_NOT,
        get_text_from_packet_list(data));
}

/* Run the current display filter on the current packet set, and
   redisplay. */
static void
filter_activate_cb(GtkWidget *w, gpointer data)
{
  GtkCombo  *filter_cm = gtk_object_get_data(GTK_OBJECT(w), E_DFILTER_CM_KEY);
  GList     *filter_list = gtk_object_get_data(GTK_OBJECT(w), E_DFILTER_FL_KEY);
  GList     *li, *nl = NULL;
  gboolean   add_filter = TRUE;
  char *s = NULL;
  
  g_assert(data);
  s = gtk_entry_get_text(GTK_ENTRY(data));
  
  /* GtkCombos don't let us get at their list contents easily, so we maintain
     our own filter list, and feed it to gtk_combo_set_popdown_strings when
     a new filter is added. */
  if (filter_packets(&cfile, g_strdup(s))) {
    li = g_list_first(filter_list);
    while (li) {
      if (li->data && strcmp(s, li->data) == 0)
        add_filter = FALSE;
      li = li->next;
    }

    if (add_filter) {
      filter_list = g_list_append(filter_list, g_strdup(s));
      li = g_list_first(filter_list);
      while (li) {
        nl = g_list_append(nl, strdup(li->data));
        li = li->next;
      }
      gtk_combo_set_popdown_strings(filter_cm, nl);
      gtk_entry_set_text(GTK_ENTRY(filter_cm->entry), g_list_last(filter_list)->data);
    }
  }
}

/* redisplay with no display filter */
static void
filter_reset_cb(GtkWidget *w, gpointer data)
{
  GtkWidget *filter_te = NULL;

  if ((filter_te = gtk_object_get_data(GTK_OBJECT(w), E_DFILTER_TE_KEY))) {
    gtk_entry_set_text(GTK_ENTRY(filter_te), "");
  }
  filter_packets(&cfile, NULL);
}

/* GTKClist compare routine, overrides default to allow numeric comparison */
static gint
packet_list_compare(GtkCList *clist, gconstpointer  ptr1, gconstpointer  ptr2)
{
  /* Get row text strings */
  char *text1 = GTK_CELL_TEXT (((GtkCListRow *)ptr1)->cell[clist->sort_column])->text;
  char *text2 = GTK_CELL_TEXT (((GtkCListRow *)ptr2)->cell[clist->sort_column])->text;

  /* Attempt to convert to numbers */
  double  num1 = atof(text1);
  double  num2 = atof(text2);
  
  gint  col_fmt = cfile.cinfo.col_fmt[clist->sort_column];
  
  if ((col_fmt == COL_NUMBER) || (col_fmt == COL_REL_TIME) || (col_fmt == COL_DELTA_TIME) ||
      ((col_fmt == COL_CLS_TIME) && (timestamp_type == RELATIVE)) ||
      ((col_fmt == COL_CLS_TIME) && (timestamp_type == DELTA))    ||
      (col_fmt == COL_UNRES_SRC_PORT) || (col_fmt == COL_UNRES_DST_PORT) ||
      ((num1 != 0) && (num2 != 0) && ((col_fmt == COL_DEF_SRC_PORT) || (col_fmt == COL_RES_SRC_PORT) ||
                                      (col_fmt == COL_DEF_DST_PORT) || (col_fmt == COL_RES_DST_PORT))) ||
      (col_fmt == COL_PACKET_LENGTH)) {

    /* Compare numeric column */

    if (num1 < num2)
      return -1;
    else if (num1 > num2)
      return 1;
    else
      return 0;
  }
  
  else {
    
    /* Compare text column */
    if (!text2)
      return (text1 != NULL);

    if (!text1)
      return -1;

    return strcmp(text1, text2);
  }
}

/* What to do when a column is clicked */
static void 
packet_list_click_column_cb(GtkCList *clist, gint column, gpointer data)
{
  column_arrows *col_arrows = (column_arrows *) data;
  int i;
  
  gtk_clist_freeze(clist);
  
  for (i = 0; i < cfile.cinfo.num_cols; i++) {
    gtk_widget_hide(col_arrows[i].ascend_pm);
    gtk_widget_hide(col_arrows[i].descend_pm);
  }
  
  if (column == clist->sort_column) {
    if (clist->sort_type == GTK_SORT_ASCENDING) {
      clist->sort_type = GTK_SORT_DESCENDING;
      gtk_widget_show(col_arrows[column].descend_pm);
    } else {
      clist->sort_type = GTK_SORT_ASCENDING;
      gtk_widget_show(col_arrows[column].ascend_pm);
    }
  }
  else {
    clist->sort_type = GTK_SORT_ASCENDING;
    gtk_widget_show(col_arrows[column].ascend_pm);
    gtk_clist_set_sort_column(clist, column);
  }
  gtk_clist_thaw(clist);

  gtk_clist_sort(clist);
}

/* mark packets */
static void 
set_frame_mark(gboolean set, frame_data *frame, gint row) {
  GdkColor fg, bg;

  if (row == -1)
    return;
  if (set) {
    mark_frame(&cfile, frame);
    color_t_to_gdkcolor(&fg, &prefs.gui_marked_fg);
    color_t_to_gdkcolor(&bg, &prefs.gui_marked_bg);
  } else {
    unmark_frame(&cfile, frame);
    fg = BLACK;
    bg = WHITE;
  }
  file_set_save_marked_sensitive();
  gtk_clist_set_background(GTK_CLIST(packet_list), row, &bg);
  gtk_clist_set_foreground(GTK_CLIST(packet_list), row, &fg);
}

static void
packet_list_button_pressed_cb(GtkWidget *w, GdkEvent *event, gpointer data) {
  
  GdkEventButton *event_button = (GdkEventButton *)event;
  gint row, column;

  if (w == NULL || event == NULL)
    return;

  if (event->type == GDK_BUTTON_PRESS && event_button->button == 2 &&
      gtk_clist_get_selection_info(GTK_CLIST(w), event_button->x, event_button->y,
				   &row, &column)) {
    frame_data *fdata = (frame_data *) gtk_clist_get_row_data(GTK_CLIST(w), row);
    set_frame_mark(!fdata->flags.marked, fdata, row);
  }
}

void mark_frame_cb(GtkWidget *w, gpointer data) {
  if (cfile.current_frame) {
    /* XXX hum, should better have a "cfile->current_row" here ... */
    set_frame_mark(!cfile.current_frame->flags.marked,
		   cfile.current_frame, 
		   gtk_clist_find_row_from_data(GTK_CLIST(packet_list), 
						cfile.current_frame));
  }
}

static void mark_all_frames(gboolean set) {
  frame_data *fdata;
  for (fdata = cfile.plist; fdata != NULL; fdata = fdata->next) {
    set_frame_mark(set,
		   fdata,
		   gtk_clist_find_row_from_data(GTK_CLIST(packet_list), fdata));    
  }
}

void update_marked_frames(void) {
  frame_data *fdata;
  if (cfile.plist == NULL) return;
  for (fdata = cfile.plist; fdata != NULL; fdata = fdata->next) {
    if (fdata->flags.marked)
      set_frame_mark(TRUE,
		     fdata,
		     gtk_clist_find_row_from_data(GTK_CLIST(packet_list),
						  fdata));
  }
}

void mark_all_frames_cb(GtkWidget *w, gpointer data) {
  mark_all_frames(TRUE);
}

void unmark_all_frames_cb(GtkWidget *w, gpointer data) {
  mark_all_frames(FALSE);
}

/* What to do when a list item is selected/unselected */
static void
packet_list_select_cb(GtkWidget *w, gint row, gint col, gpointer evt) {

/* Remove the hex display tabbed pages */
  while( (gtk_notebook_get_nth_page( GTK_NOTEBOOK(byte_nb_ptr), 0)))
    gtk_notebook_remove_page( GTK_NOTEBOOK(byte_nb_ptr), 0);

  select_packet(&cfile, row);
}


static void
packet_list_unselect_cb(GtkWidget *w, gint row, gint col, gpointer evt) {

  unselect_packet(&cfile);
}


static void
tree_view_select_row_cb(GtkCTree *ctree, GList *node, gint column, gpointer user_data)
{
	field_info	*finfo;
	gchar		*help_str = NULL;
	gboolean        has_blurb = FALSE;
	guint           length = 0, byte_len;
	GtkWidget	*byte_view;
	guint8		*byte_data;

	g_assert(node);
	finfo = gtk_ctree_node_get_row_data( ctree, GTK_CTREE_NODE(node) );
	if (!finfo) return;

	if (finfo->ds_name != NULL)
		set_notebook_page(  byte_nb_ptr, find_notebook_page( byte_nb_ptr, finfo->ds_name));

        byte_view = gtk_object_get_data(GTK_OBJECT(byte_nb_ptr), E_BYTE_VIEW_TEXT_INFO_KEY);
        byte_data = gtk_object_get_data(GTK_OBJECT(byte_view), E_BYTE_VIEW_DATA_PTR_KEY);
        byte_len = GPOINTER_TO_INT(gtk_object_get_data(GTK_OBJECT(byte_view), E_BYTE_VIEW_DATA_LEN_KEY));

	g_assert(byte_data);

	finfo_selected = finfo;
	set_menus_for_selected_tree_row(TRUE);

	if (finfo->hfinfo) {
	  if (finfo->hfinfo->blurb != NULL && 
	      finfo->hfinfo->blurb[0] != '\0') {
	    has_blurb = TRUE;
	    length = strlen(finfo->hfinfo->blurb);
	  } else {
	    length = strlen(finfo->hfinfo->name);
	  }
	  statusbar_pop_field_msg();	/* get rid of current help msg */
          if (length) {
	    length += strlen(finfo->hfinfo->abbrev) + 10;
	    help_str = g_malloc(sizeof(gchar) * length);
	    sprintf(help_str, "%s (%s)", 
	       (has_blurb) ? finfo->hfinfo->blurb : finfo->hfinfo->name,
	       finfo->hfinfo->abbrev);
	    statusbar_push_field_msg(help_str);
	    g_free(help_str);
          } else {
            /*
	     * Don't show anything if the field name is zero-length;
	     * the pseudo-field for "proto_tree_add_text()" is such
	     * a field, and we don't want "Text (text)" showing up
	     * on the status line if you've selected such a field.
	     *
	     * XXX - there are zero-length fields for which we *do*
	     * want to show the field name.
	     *
	     * XXX - perhaps the name and abbrev field should be null
	     * pointers rather than null strings for that pseudo-field,
	     * but we'd have to add checks for null pointers in some
	     * places if we did that.
	     *
	     * Or perhaps protocol tree items added with
	     * "proto_tree_add_text()" should have -1 as the field index,
	     * with no pseudo-field being used, but that might also
	     * require special checks for -1 to be added.
	     */
	    statusbar_push_field_msg("");
          }
	}

	packet_hex_print(GTK_TEXT(byte_view), byte_data, cfile.current_frame,
		finfo, byte_len);
}

static void
tree_view_unselect_row_cb(GtkCTree *ctree, GList *node, gint column, gpointer user_data)
{
	GtkWidget	*byte_view;
	guint8	*data;
	gint	len;	

	/*
	 * Which byte view is displaying the current protocol tree
	 * row's data?
	 */
	len = get_byte_view_and_data( byte_nb_ptr, &byte_view, &data);
	if ( len < 0)
		return;	/* none */

	unselect_field();
	packet_hex_print(GTK_TEXT(byte_view), data, cfile.current_frame,
		NULL, len);
}

void collapse_all_cb(GtkWidget *widget, gpointer data) {
  if (cfile.edt->tree)
    collapse_all_tree(cfile.edt->tree, tree_view);
}

void expand_all_cb(GtkWidget *widget, gpointer data) {
  if (cfile.edt->tree)
    expand_all_tree(cfile.edt->tree, tree_view);
}

void resolve_name_cb(GtkWidget *widget, gpointer data) {
  if (cfile.edt->tree) {
    guint32 tmp = g_resolv_flags;
    g_resolv_flags = RESOLV_ALL;
    gtk_clist_clear ( GTK_CLIST(tree_view) );
    proto_tree_draw(cfile.edt->tree, tree_view);
    g_resolv_flags = tmp;
  }
}

/* Set the selection mode of the packet list window. */
void
set_plist_sel_browse(gboolean val)
{
	gboolean old_val;

	old_val =
	    (GTK_CLIST(packet_list)->selection_mode == GTK_SELECTION_SINGLE);

	if (val == old_val) {
		/*
		 * The mode isn't changing, so don't do anything.
		 * In particular, don't gratuitiously unselect the
		 * current packet.
		 *
		 * XXX - why do we have to unselect the current packet
		 * ourselves?  The documentation for the GtkCList at
		 *
		 *	http://developer.gnome.org/doc/API/gtk/gtkclist.html
		 *
		 * says "Note that setting the widget's selection mode to
		 * one of GTK_SELECTION_BROWSE or GTK_SELECTION_SINGLE will
		 * cause all the items in the GtkCList to become deselected."
		 */
		return;
	}

	if (finfo_selected)
		unselect_packet(&cfile);

	/* Yeah, GTK uses "browse" in the case where we do not, but oh well. I think
	 * "browse" in Ethereal makes more sense than "SINGLE" in GTK+ */
	if (val) {
		gtk_clist_set_selection_mode(GTK_CLIST(packet_list), GTK_SELECTION_SINGLE);
	}
	else {
		gtk_clist_set_selection_mode(GTK_CLIST(packet_list), GTK_SELECTION_BROWSE);
	}
}
	
/* Set the font of the packet list window. */
void
set_plist_font(GdkFont *font)
{
	GtkStyle *style;
	int i;

	style = gtk_style_new();
	gdk_font_unref(style->font);
	style->font = font;
	gdk_font_ref(font);

	gtk_widget_set_style(packet_list, style);

	/* Compute static column sizes to use during a "-S" capture, so that
 	   the columns don't resize during a live capture. */
	for (i = 0; i < cfile.cinfo.num_cols; i++) {
		cfile.cinfo.col_width[i] = gdk_string_width(font,
			get_column_longest_string(get_column_format(i)));
	}
}

/*
 * Push a message referring to file access onto the statusbar.
 */
void
statusbar_push_file_msg(gchar *msg)
{
	gtk_statusbar_push(GTK_STATUSBAR(info_bar), file_ctx, msg);
}

/*
 * Pop a message referring to file access off the statusbar.
 */
void
statusbar_pop_file_msg(void)
{
	gtk_statusbar_pop(GTK_STATUSBAR(info_bar), file_ctx);
}

/*
 * XXX - do we need multiple statusbar contexts?
 */

/*
 * Push a message referring to the currently-selected field onto the statusbar.
 */
void
statusbar_push_field_msg(gchar *msg)
{
	gtk_statusbar_push(GTK_STATUSBAR(info_bar), help_ctx, msg);
}

/*
 * Pop a message referring to the currently-selected field off the statusbar.
 */
void
statusbar_pop_field_msg(void)
{
	gtk_statusbar_pop(GTK_STATUSBAR(info_bar), help_ctx);
}

static gboolean
do_quit(void)
{
	/* XXX - should we check whether the capture file is an
	   unsaved temporary file for a live capture and, if so,
	   pop up a "do you want to exit without saving the capture
	   file?" dialog, and then just return, leaving said dialog
	   box to forcibly quit if the user clicks "OK"?

	   If so, note that this should be done in a subroutine that
	   returns TRUE if we do so, and FALSE otherwise, and if it
	   returns TRUE we should return TRUE without nuking anything.

	   Note that, if we do that, we might also want to check if
	   an "Update list of packets in real time" capture is in
	   progress and, if so, ask whether they want to terminate
	   the capture and discard it, and return TRUE, before nuking
	   any child capture, if they say they don't want to do so. */

#ifdef HAVE_LIBPCAP
	/* Nuke any child capture in progress. */
	kill_capture_child();
#endif

	/* Are we in the middle of reading a capture? */
	if (cfile.state == FILE_READ_IN_PROGRESS) {
		/* Yes, so we can't just close the file and quit, as
		   that may yank the rug out from under the read in
		   progress; instead, just set the state to
		   "FILE_READ_ABORTED" and return - the code doing the read
		   will check for that and, if it sees that, will clean
		   up and quit. */
		cfile.state = FILE_READ_ABORTED;

		/* Say that the window should *not* be deleted;
		   that'll be done by the code that cleans up. */
		return TRUE;
	} else {
		/* Close any capture file we have open; on some OSes, you
		   can't unlink a temporary capture file if you have it
		   open.
		   "close_cap_file()" will unlink it after closing it if
		   it's a temporary file.

		   We do this here, rather than after the main loop returns,
		   as, after the main loop returns, the main window may have
		   been destroyed (if this is called due to a "destroy"
		   even on the main window rather than due to the user
		   selecting a menu item), and there may be a crash
		   or other problem when "close_cap_file()" tries to
		   clean up stuff in the main window.

		   XXX - is there a better place to put this?
		   Or should we have a routine that *just* closes the
		   capture file, and doesn't do anything with the UI,
		   which we'd call here, and another routine that
		   calls that routine and also cleans up the UI, which
		   we'd call elsewhere? */
		close_cap_file(&cfile);

		/* Exit by leaving the main loop, so that any quit functions
		   we registered get called. */
		gtk_main_quit();

		/* Say that the window should be deleted. */
		return FALSE;
	}
}

static gboolean
main_window_delete_event_cb(GtkWidget *widget, GdkEvent *event, gpointer data)
{
	gint desk_x, desk_y;

	/* Try to grab our geometry */
	gdk_window_get_root_origin(top_level->window, &root_x, &root_y);
	if (gdk_window_get_deskrelative_origin(top_level->window,
				&desk_x, &desk_y)) {
		if (desk_x <= root_x && desk_y <= root_y) {
			root_x = desk_x;
			root_y = desk_y;
		}
	}

	/* XXX - Is this the "approved" method? */
	gdk_window_get_size(top_level->window, &top_width, &top_height);

	/* "do_quit()" indicates whether the main window should be deleted. */
	return do_quit();
}

void
file_quit_cmd_cb (GtkWidget *widget, gpointer data)
{
	do_quit();
}

static void 
print_usage(void) {

  fprintf(stderr, "This is GNU " PACKAGE " " VERSION ", compiled %s\n",
	  comp_info_str->str);
#ifdef HAVE_LIBPCAP
  fprintf(stderr, "%s [ -vh ] [ -klpQS ] [ -a <capture autostop condition> ] ...\n",
	  PACKAGE);
  fprintf(stderr, "\t[ -b <number of ringbuffer files> ] [ -B <byte view height> ]\n");
  fprintf(stderr, "\t[ -c <count> ] [ -f <capture filter> ] [ -i <interface> ]\n");
  fprintf(stderr, "\t[ -m <medium font> ] [ -n ] [ -N <resolving> ]\n");
  fprintf(stderr, "\t[ -o <preference setting> ] ... [ -P <packet list height> ]\n");
  fprintf(stderr, "\t[ -r <infile> ] [ -R <read filter> ] [ -s <snaplen> ] \n");
  fprintf(stderr, "\t[ -t <time stamp format> ] [ -T <tree view height> ]\n");
  fprintf(stderr, "\t[ -w <savefile> ] [ <infile> ]\n");
#else
  fprintf(stderr, "%s [ -vh ] [ -B <byte view height> ] [ -m <medium font> ]\n",
	  PACKAGE);
  fprintf(stderr, "\t[ -n ] [ -N <resolving> ]\n");
  fprintf(stderr, "\t[ -o <preference setting> ... [ -P <packet list height> ]\n");
  fprintf(stderr, "\t[ -r <infile> ] [ -R <read filter> ] [ -t <time stamp format> ]\n");
  fprintf(stderr, "\t[ -T <tree view height> ] [ <infile> ]\n");
#endif
}

static void 
show_version(void)
{
#ifdef WIN32
  create_console();
#endif

  printf("%s %s, %s\n", PACKAGE, VERSION, comp_info_str->str);
}

static int
get_positive_int(const char *string, const char *name)
{
  long number;
  char *p;

  number = strtol(string, &p, 10);
  if (p == string || *p != '\0') {
    fprintf(stderr, "ethereal: The specified %s \"%s\" is not a decimal number\n",
	    name, string);
    exit(1);
  }
  if (number < 0) {
    fprintf(stderr, "ethereal: The specified %s \"%s\" is a negative number\n",
	    name, string);
    exit(1);
  }
  if (number > INT_MAX) {
    fprintf(stderr, "ethereal: The specified %s \"%s\" is too large (greater than %d)\n",
	    name, string, INT_MAX);
    exit(1);
  }
  return number;
}

#ifdef HAVE_LIBPCAP
/*
 * Given a string of the form "<autostop criterion>:<value>", as might appear
 * as an argument to a "-a" option, parse it and set the criterion in
 * question.  Return an indication of whether it succeeded or failed
 * in some fashion.
 */
static gboolean
set_autostop_criterion(const char *autostoparg)
{
  u_char *p, *colonp;

  colonp = strchr(autostoparg, ':');
  if (colonp == NULL)
    return FALSE;

  p = colonp;
  *p++ = '\0';

  /*
   * Skip over any white space (there probably won't be any, but
   * as we allow it in the preferences file, we might as well
   * allow it here).
   */
  while (isspace(*p))
    p++;
  if (*p == '\0') {
    /*
     * Put the colon back, so if our caller uses, in an
     * error message, the string they passed us, the message
     * looks correct.
     */
    *colonp = ':';
    return FALSE;
  }
  if (strcmp(autostoparg,"duration") == 0) {
    cfile.autostop_duration = get_positive_int(p,"autostop duration");
  } else if (strcmp(autostoparg,"filesize") == 0) {
    cfile.autostop_filesize = get_positive_int(p,"autostop filesize");
  } else {
    return FALSE;
  }
  *colonp = ':'; /* put the colon back */
  return TRUE;
}
#endif

/* And now our feature presentation... [ fade to music ] */
int
main(int argc, char *argv[])
{
#ifdef HAVE_LIBPCAP
  char                *command_name;
#endif
  char                *s;
  int                  i;
  int                  opt;
  extern char         *optarg;
  gboolean             arg_error = FALSE;
#ifdef HAVE_LIBPCAP
#ifdef HAVE_PCAP_VERSION
  extern char          pcap_version[];
#endif /* HAVE_PCAP_VERSION */
#endif /* HAVE_LIBPCAP */
  
#ifdef WIN32
  WSADATA 	       wsaData; 
#endif

  char                *gpf_path, *cf_path, *df_path;
  const char          *pf_path;
  int                  gpf_open_errno, pf_open_errno, cf_open_errno, df_open_errno;
  int                  err;
#ifdef HAVE_LIBPCAP
  gboolean             start_capture = FALSE;
  gchar               *save_file = NULL;
  GList               *if_list;
  gchar                err_str[PCAP_ERRBUF_SIZE];
  gboolean             stats_known;
  struct pcap_stat     stats;
#else
  gboolean             capture_option_specified = FALSE;
#endif
  gint                 pl_size = 280, tv_size = 95, bv_size = 75;
  gchar               *rc_file, *cf_name = NULL, *rfilter = NULL;
  dfilter_t           *rfcode = NULL;
  gboolean             rfilter_parse_failed = FALSE;
  e_prefs             *prefs;
  char                 badopt;
  char                *bold_font_name;
  gint                 desk_x, desk_y;
  gboolean             prefs_write_needed = FALSE;


  ethereal_path = argv[0];

#ifdef WIN32
  /* Arrange that if we have no console window, and a GLib message logging
     routine is called to log a message, we pop up a console window.

     We do that by inserting our own handler for all messages logged
     to the default domain; that handler pops up a console if necessary,
     and then calls the default handler. */
  g_log_set_handler(NULL,
		    G_LOG_LEVEL_ERROR|
		    G_LOG_LEVEL_CRITICAL|
		    G_LOG_LEVEL_WARNING|
		    G_LOG_LEVEL_MESSAGE|
		    G_LOG_LEVEL_INFO|
		    G_LOG_LEVEL_DEBUG|
		    G_LOG_FLAG_FATAL|G_LOG_FLAG_RECURSION,
		    console_log_handler, NULL);
#endif

#ifdef HAVE_LIBPCAP
  command_name = get_basename(ethereal_path);
  /* Set "capture_child" to indicate whether this is going to be a child
     process for a "-S" capture. */
  capture_child = (strcmp(command_name, CHILD_NAME) == 0);
#endif

  /* Register all dissectors; we must do this before checking for the
     "-G" flag, as the "-G" flag dumps a list of fields registered
     by the dissectors, and we must do it before we read the preferences,
     in case any dissectors register preferences. */
  epan_init(PLUGIN_DIR,register_all_protocols,register_all_protocol_handoffs);

  /* Now register the preferences for any non-dissector modules.
     We must do that before we read the preferences as well. */
  prefs_register_modules();

  /* If invoked with the "-G" flag, we dump out a glossary of
     display filter symbols.

     We must do this before calling "gtk_init()", because "gtk_init()"
     tries to open an X display, and we don't want to have to do any X
     stuff just to do a build.

     Given that we call "gtk_init()" before doing the regular argument
     list processing, so that it can handle X and GTK+ arguments and
     remove them from the list at which we look, this means we must do
     this before doing the regular argument list processing, as well.

     This means that:

	you must give the "-G" flag as the first flag on the command line;

	you must give it as "-G", nothing more, nothing less;

	any arguments after the "-G" flag will not be used. */
  if (argc >= 2 && strcmp(argv[1], "-G") == 0) {
    proto_registrar_dump();
    exit(0);
  }

  /* Set the current locale according to the program environment. 
   * We haven't localized anything, but some GTK widgets are localized
   * (the file selection dialogue, for example).
   * This also sets the C-language locale to the native environment. */
  gtk_set_locale();

  /* Let GTK get its args */
  gtk_init (&argc, &argv);
  
  /* Read the preference files. */
  prefs = read_prefs(&gpf_open_errno, &gpf_path, &pf_open_errno, &pf_path);

#ifdef HAVE_LIBPCAP
  has_snaplen = FALSE;
  snaplen = MIN_PACKET_SIZE;

  /* If this is a capture child process, it should pay no attention
     to the "prefs.capture_prom_mode" setting in the preferences file;
     it should do what the parent process tells it to do, and if
     the parent process wants it not to run in promiscuous mode, it'll
     tell it so with a "-p" flag.

     Otherwise, set promiscuous mode from the preferences setting. */
  if (capture_child)
    promisc_mode = TRUE;
  else
    promisc_mode = prefs->capture_prom_mode;

  /* Set "Update list of packets in real time" mode from the preferences
     setting. */
  sync_mode = prefs->capture_real_time;

  /* And do the same for "Automatic scrolling in live capture" mode. */
  auto_scroll_live = prefs->capture_auto_scroll;
#endif

  /* Set the name resolution code's flags from the preferences. */
  g_resolv_flags = prefs->name_resolve;

  /* Read the capture filter file. */
  read_filter_list(CFILTER_LIST, &cf_path, &cf_open_errno);

  /* Read the display filter file. */
  read_filter_list(DFILTER_LIST, &df_path, &df_open_errno);

  /* Initialize the capture file struct */
  cfile.plist		= NULL;
  cfile.plist_end	= NULL;
  cfile.wth		= NULL;
  cfile.filename	= NULL;
  cfile.user_saved	= FALSE;
  cfile.is_tempfile	= FALSE;
  cfile.rfcode		= NULL;
  cfile.dfilter		= NULL;
  cfile.dfcode		= NULL;
#ifdef HAVE_LIBPCAP
  cfile.cfilter		= g_strdup(EMPTY_FILTER);
#endif
  cfile.iface		= NULL;
  cfile.save_file	= NULL;
  cfile.save_file_fd	= -1;
  cfile.has_snap	= FALSE;
  cfile.snap		= WTAP_MAX_PACKET_SIZE;
  cfile.count		= 0;
#ifdef HAVE_LIBPCAP
  cfile.autostop_duration = 0;
  cfile.autostop_filesize = 0;
  cfile.ringbuffer_on = FALSE;
  cfile.ringbuffer_num_files = RINGBUFFER_MIN_NUM_FILES;
#endif
  col_init(&cfile.cinfo, prefs->num_cols);

  /* Assemble the compile-time options */
  comp_info_str = g_string_new("");

  g_string_append(comp_info_str, "with ");
  g_string_sprintfa(comp_info_str,
#ifdef GTK_MAJOR_VERSION
    "GTK+ %d.%d.%d", GTK_MAJOR_VERSION, GTK_MINOR_VERSION,
    GTK_MICRO_VERSION);
#else
    "GTK+ (version unknown)");
#endif

  g_string_append(comp_info_str, ", with ");
  g_string_sprintfa(comp_info_str,
#ifdef GLIB_MAJOR_VERSION
    "GLib %d.%d.%d", GLIB_MAJOR_VERSION, GLIB_MINOR_VERSION,
    GLIB_MICRO_VERSION);
#else
    "GLib (version unknown)");
#endif

#ifdef HAVE_LIBPCAP
  g_string_append(comp_info_str, ", with libpcap ");
#ifdef HAVE_PCAP_VERSION
  g_string_append(comp_info_str, pcap_version);
#else /* HAVE_PCAP_VERSION */
  g_string_append(comp_info_str, "(version unknown)");
#endif /* HAVE_PCAP_VERSION */
#else /* HAVE_LIBPCAP */
  g_string_append(comp_info_str, ", without libpcap");
#endif /* HAVE_LIBPCAP */

#ifdef HAVE_LIBZ
  g_string_append(comp_info_str, ", with libz ");
#ifdef ZLIB_VERSION
  g_string_append(comp_info_str, ZLIB_VERSION);
#else /* ZLIB_VERSION */
  g_string_append(comp_info_str, "(version unknown)");
#endif /* ZLIB_VERSION */
#else /* HAVE_LIBZ */
  g_string_append(comp_info_str, ", without libz");
#endif /* HAVE_LIBZ */

/* Oh, this is pretty */
#if defined(HAVE_UCD_SNMP_SNMP_H)
  g_string_append(comp_info_str, ", with UCD SNMP ");
#ifdef HAVE_UCD_SNMP_VERSION_H
  g_string_append(comp_info_str, VersionInfo);
#else /* HAVE_UCD_SNMP_VERSION_H */
  g_string_append(comp_info_str, "(version unknown)");
#endif /* HAVE_UCD_SNMP_VERSION_H */
#elif defined(HAVE_SNMP_SNMP_H)
  g_string_append(comp_info_str, ", with CMU SNMP ");
#ifdef HAVE_SNMP_VERSION_H
  g_string_append(comp_info_str, snmp_Version());
#else /* HAVE_SNMP_VERSION_H */
  g_string_append(comp_info_str, "(version unknown)");
#endif /* HAVE_SNMP_VERSION_H */
#else /* no SNMP */
  g_string_append(comp_info_str, ", without SNMP");
#endif

  /* Now get our args */
  while ((opt = getopt(argc, argv, "a:b:B:c:f:hi:klm:nN:o:pP:Qr:R:Ss:t:T:w:W:vZ:")) !=  EOF) {
    switch (opt) {
      case 'a':        /* autostop criteria */
#ifdef HAVE_LIBPCAP
        if (set_autostop_criterion(optarg) == FALSE) {
          fprintf(stderr, "ethereal: Invalid or unknown -a flag \"%s\"\n", optarg);
          exit(1);          
        }
#else
        capture_option_specified = TRUE;
        arg_error = TRUE;
#endif
        break;
      case 'b':        /* Ringbuffer option */
#ifdef HAVE_LIBPCAP
        cfile.ringbuffer_on = TRUE;
        cfile.ringbuffer_num_files = get_positive_int(optarg, "number of ring buffer files");
#else
        capture_option_specified = TRUE;
        arg_error = TRUE;
#endif
        break;
      case 'B':        /* Byte view pane height */
        bv_size = get_positive_int(optarg, "byte view pane height");
        break;
      case 'c':        /* Capture xxx packets */
#ifdef HAVE_LIBPCAP
        cfile.count = get_positive_int(optarg, "packet count");
#else
        capture_option_specified = TRUE;
        arg_error = TRUE;
#endif
        break;
      case 'f':
#ifdef HAVE_LIBPCAP
	if (cfile.cfilter)
		g_free(cfile.cfilter);
	cfile.cfilter = g_strdup(optarg);
#else
        capture_option_specified = TRUE;
        arg_error = TRUE;
#endif
	break;
      case 'h':        /* Print help and exit */
	print_usage();
	exit(0);
        break;
      case 'i':        /* Use interface xxx */
#ifdef HAVE_LIBPCAP
        cfile.iface = g_strdup(optarg);
#else
        capture_option_specified = TRUE;
        arg_error = TRUE;
#endif
        break;
      case 'k':        /* Start capture immediately */
#ifdef HAVE_LIBPCAP
        start_capture = TRUE;
#else
        capture_option_specified = TRUE;
        arg_error = TRUE;
#endif
        break;
      case 'l':        /* Automatic scrolling in live capture mode */
#ifdef HAVE_LIBPCAP
        auto_scroll_live = TRUE;
#else
        capture_option_specified = TRUE;
        arg_error = TRUE;
#endif
        break;
      case 'm':        /* Fixed-width font for the display */
        if (prefs->gui_font_name != NULL)
          g_free(prefs->gui_font_name);
        prefs->gui_font_name = g_strdup(optarg);
        break;
      case 'n':        /* No name resolution */
        g_resolv_flags = RESOLV_NONE;
        break;
      case 'N':        /* Select what types of addresses/port #s to resolve */
        if (g_resolv_flags == RESOLV_ALL)
          g_resolv_flags = RESOLV_NONE;
        badopt = string_to_name_resolve(optarg, &g_resolv_flags);
        if (badopt != '\0') {
          fprintf(stderr, "ethereal: -N specifies unknown resolving option '%c'; valid options are 'm', 'n', and 't'\n",
			badopt);
          exit(1);
        }
        break;
      case 'o':        /* Override preference from command line */
        switch (prefs_set_pref(optarg)) {

	case PREFS_SET_SYNTAX_ERR:
          fprintf(stderr, "ethereal: Invalid -o flag \"%s\"\n", optarg);
          exit(1);
          break;

        case PREFS_SET_NO_SUCH_PREF:
        case PREFS_SET_OBSOLETE:
          fprintf(stderr, "ethereal: -o flag \"%s\" specifies unknown preference\n",
			optarg);
          exit(1);
          break;
        }
        break;
      case 'p':        /* Don't capture in promiscuous mode */
#ifdef HAVE_LIBPCAP
	promisc_mode = FALSE;
#else
        capture_option_specified = TRUE;
        arg_error = TRUE;
#endif
	break;
      case 'P':        /* Packet list pane height */
        pl_size = get_positive_int(optarg, "packet list pane height");
        break;
      case 'Q':        /* Quit after capture (just capture to file) */
#ifdef HAVE_LIBPCAP
        quit_after_cap = 1;
        start_capture = TRUE;  /*** -Q implies -k !! ***/
#else
        capture_option_specified = TRUE;
        arg_error = TRUE;
#endif
        break;
      case 'r':        /* Read capture file xxx */
	/* We may set "last_open_dir" to "cf_name", and if we change
	   "last_open_dir" later, we free the old value, so we have to
	   set "cf_name" to something that's been allocated. */
        cf_name = g_strdup(optarg);
        break;
      case 'R':        /* Read file filter */
        rfilter = optarg;
        break;
      case 's':        /* Set the snapshot (capture) length */
#ifdef HAVE_LIBPCAP
        has_snaplen = TRUE;
        snaplen = get_positive_int(optarg, "snapshot length");
#else
        capture_option_specified = TRUE;
        arg_error = TRUE;
#endif
        break;
      case 'S':        /* "Sync" mode: used for following file ala tail -f */
#ifdef HAVE_LIBPCAP
        sync_mode = TRUE;
#else
        capture_option_specified = TRUE;
        arg_error = TRUE;
#endif
        break;
      case 't':        /* Time stamp type */
        if (strcmp(optarg, "r") == 0)
          timestamp_type = RELATIVE;
        else if (strcmp(optarg, "a") == 0)
          timestamp_type = ABSOLUTE;
        else if (strcmp(optarg, "ad") == 0)
          timestamp_type = ABSOLUTE_WITH_DATE;
        else if (strcmp(optarg, "d") == 0)
          timestamp_type = DELTA;
        else {
          fprintf(stderr, "ethereal: Invalid time stamp type \"%s\"\n",
            optarg);
          fprintf(stderr, "It must be \"r\" for relative, \"a\" for absolute,\n");
          fprintf(stderr, "\"ad\" for absolute with date, or \"d\" for delta.\n");
          exit(1);
        }
        break;
      case 'T':        /* Tree view pane height */
        tv_size = get_positive_int(optarg, "tree view pane height");
        break;
      case 'v':        /* Show version and exit */
        show_version();
#ifdef WIN32
        if (console_was_created)
          destroy_console();
#endif
        exit(0);
        break;
      case 'w':        /* Write to capture file xxx */
#ifdef HAVE_LIBPCAP
        save_file = g_strdup(optarg);
#else
        capture_option_specified = TRUE;
        arg_error = TRUE;
#endif
	break;
      case 'W':        /* Write to capture file FD xxx */
#ifdef HAVE_LIBPCAP
        cfile.save_file_fd = atoi(optarg);
#else
        capture_option_specified = TRUE;
        arg_error = TRUE;
#endif
	break;

#ifdef _WIN32
      case 'Z':        /* Write to pipe FD XXX */
#ifdef HAVE_LIBPCAP
        /* associate stdout with pipe */
        i = atoi(optarg);
        if (dup2(i, 1) < 0) {
          fprintf(stderr, "Unable to dup pipe handle\n");
          exit(1);
        }
#else
        capture_option_specified = TRUE;
        arg_error = TRUE;
#endif /* HAVE_LIBPCAP */
        break;
#endif /* _WIN32 */

      default:
      case '?':        /* Bad flag - print usage message */
        arg_error = TRUE;
        break;
    }
  }
  argc -= optind;
  argv += optind;
  if (argc >= 1) {
    if (cf_name != NULL) {
      /*
       * Input file name specified with "-r" *and* specified as a regular
       * command-line argument.
       */
      arg_error = TRUE;
    } else {
      /*
       * Input file name not specified with "-r", and a command-line argument
       * was specified; treat it as the input file name.
       *
       * Yes, this is different from tethereal, where non-flag command-line
       * arguments are a filter, but this works better on GUI desktops
       * where a command can be specified to be run to open a particular
       * file - yes, you could have "-r" as the last part of the command,
       * but that's a bit ugly.
       */
      cf_name = g_strdup(argv[0]);
    }
    argc--;
    argv++;
  }

  if (argc != 0) {
    /*
     * Extra command line arguments were specified; complain.
     */
    arg_error = TRUE;
  }

#ifdef HAVE_LIBPCAP
  if (cfile.ringbuffer_on) {
    /* Ring buffer works only under certain conditions:
       a) ring buffer does not work with temporary files;
       b) sync_mode and cfile.ringbuffer_on are mutually exclusive -
          sync_mode takes precedence;
       c) it makes no sense to enable the ring buffer if the maximum
          file size is set to "infinite". */
    if (cfile.save_file == NULL) {
      fprintf(stderr, "ethereal: Ring buffer requested, but capture isn't being saved to a permanent file.\n");
      cfile.ringbuffer_on = FALSE;
    }
    if (sync_mode) {
      fprintf(stderr, "ethereal: Ring buffer requested, but an \"Update list of packets in real time\" capture is being done.\n");
      cfile.ringbuffer_on = FALSE;
    }
    if (cfile.autostop_filesize == 0) {
      fprintf(stderr, "ethereal: Ring buffer requested, but no maximum capture file size was specified.\n");
      cfile.ringbuffer_on = FALSE;
    }
  }
#endif

#ifdef WIN32
  /* Load wpcap if possible */
  load_wpcap();

  /* Start windows sockets */
  WSAStartup( MAKEWORD( 1, 1 ), &wsaData );
#endif

  /* Notify all registered modules that have had any of their preferences
     changed either from one of the preferences file or from the command
     line that its preferences have changed. */
  prefs_apply_all();

#ifndef HAVE_LIBPCAP
  if (capture_option_specified)
    fprintf(stderr, "This version of Ethereal was not built with support for capturing packets.\n");
#endif
  if (arg_error)
    print_usage();
#ifdef HAVE_LIBPCAP
  if (start_capture) {
    /* We're supposed to do a live capture; did the user specify an interface
       to use? */
    if (cfile.iface == NULL) {
      /* No - pick the first one from the list of interfaces. */
      if_list = get_interface_list(&err, err_str);
      if (if_list == NULL) {
        switch (err) {

        case CANT_GET_INTERFACE_LIST:
            fprintf(stderr, "ethereal: Can't get list of interfaces: %s\n",
			err_str);
            break;

        case NO_INTERFACES_FOUND:
            fprintf(stderr, "ethereal: There are no interfaces on which a capture can be done\n");
            break;
        }
        exit(2);
      }
      cfile.iface = g_strdup(if_list->data);	/* first interface */
      free_interface_list(if_list);
    }
  }
  if (capture_child) {
    if (cfile.save_file_fd == -1) {
      /* XXX - send this to the standard output as something our parent
         should put in an error message box? */
      fprintf(stderr, "%s: \"-W\" flag not specified\n", CHILD_NAME);
      exit(1);
    }
  }
#endif

  /* Build the column format array */  
  for (i = 0; i < cfile.cinfo.num_cols; i++) {
    cfile.cinfo.col_fmt[i] = get_column_format(i);
    cfile.cinfo.col_title[i] = g_strdup(get_column_title(i));
    cfile.cinfo.fmt_matx[i] = (gboolean *) g_malloc0(sizeof(gboolean) *
      NUM_COL_FMTS);
    get_column_format_matches(cfile.cinfo.fmt_matx[i], cfile.cinfo.col_fmt[i]);
    cfile.cinfo.col_data[i] = NULL;
    if (cfile.cinfo.col_fmt[i] == COL_INFO)
      cfile.cinfo.col_buf[i] = (gchar *) g_malloc(sizeof(gchar) * COL_MAX_INFO_LEN);
    else
      cfile.cinfo.col_buf[i] = (gchar *) g_malloc(sizeof(gchar) * COL_MAX_LEN);
    cfile.cinfo.col_expr[i] = (gchar *) g_malloc(sizeof(gchar) * COL_MAX_LEN);
    cfile.cinfo.col_expr_val[i] = (gchar *) g_malloc(sizeof(gchar) * COL_MAX_LEN);
  }

#ifdef HAVE_LIBPCAP
  if (has_snaplen) {
    if (snaplen < 1)
      snaplen = WTAP_MAX_PACKET_SIZE;
    else if (snaplen < MIN_PACKET_SIZE)
      snaplen = MIN_PACKET_SIZE;
  }
  
  /* Check the value range of the ringbuffer_num_files parameter */
  if (cfile.ringbuffer_num_files < RINGBUFFER_MIN_NUM_FILES)
    cfile.ringbuffer_num_files = RINGBUFFER_MIN_NUM_FILES;
  else if (cfile.ringbuffer_num_files > RINGBUFFER_MAX_NUM_FILES)
    cfile.ringbuffer_num_files = RINGBUFFER_MAX_NUM_FILES;
#endif
  
  rc_file = get_persconffile_path(RC_FILE, FALSE);
  gtk_rc_parse(rc_file);

  /* Try to load the regular and boldface fixed-width fonts */
  bold_font_name = boldify(prefs->gui_font_name);
  m_r_font = gdk_font_load(prefs->gui_font_name);
  m_b_font = gdk_font_load(bold_font_name);
  if (m_r_font == NULL || m_b_font == NULL) {
    /* XXX - pop this up as a dialog box? no */
    if (m_r_font == NULL) {
#ifdef HAVE_LIBPCAP
      if (!capture_child)
#endif
	fprintf(stderr, "ethereal: Warning: font %s not found - defaulting to 6x13 and 6x13bold\n",
		prefs->gui_font_name);
    } else {
      gdk_font_unref(m_r_font);
    }
    if (m_b_font == NULL) {
#ifdef HAVE_LIBPCAP
      if (!capture_child)
#endif
	fprintf(stderr, "ethereal: Warning: font %s not found - defaulting to 6x13 and 6x13bold\n",
		bold_font_name);
    } else {
      gdk_font_unref(m_b_font);
    }
    g_free(bold_font_name);
    if ((m_r_font = gdk_font_load("6x13")) == NULL) {
      fprintf(stderr, "ethereal: Error: font 6x13 not found\n");
      exit(1);
    }
    if ((m_b_font = gdk_font_load("6x13bold")) == NULL) {
      fprintf(stderr, "ethereal: Error: font 6x13bold not found\n");
      exit(1);
    }
    g_free(prefs->gui_font_name);
    prefs->gui_font_name = g_strdup("6x13");
  }

  /* Call this for the side-effects that set_fonts() produces */
  set_fonts(m_r_font, m_b_font);


#ifdef HAVE_LIBPCAP
  /* Is this a "child" ethereal, which is only supposed to pop up a
     capture box to let us stop the capture, and run a capture
     to a file that our parent will read? */
  if (!capture_child) {
#endif
    /* No.  Pop up the main window, and read in a capture file if
       we were told to. */

    create_main_window(pl_size, tv_size, bv_size, prefs);
    set_menus_for_capture_file(FALSE);

    cfile.colors = colfilter_new();

    /* If we were given the name of a capture file, read it in now;
       we defer it until now, so that, if we can't open it, and pop
       up an alert box, the alert box is more likely to come up on
       top of the main window - but before the preference-file-error
       alert box, so, if we get one of those, it's more likely to come
       up on top of us. */
    if (cf_name) {
      if (rfilter != NULL) {
        if (!dfilter_compile(rfilter, &rfcode)) {
          simple_dialog(ESD_TYPE_CRIT, NULL, dfilter_error_msg);
          rfilter_parse_failed = TRUE;
        }
      }
      if (!rfilter_parse_failed) {
        if ((err = open_cap_file(cf_name, FALSE, &cfile)) == 0) {
          /* "open_cap_file()" succeeded, so it closed the previous
	     capture file, and thus destroyed any previous read filter
	     attached to "cf". */
          cfile.rfcode = rfcode;
          switch (read_cap_file(&cfile, &err)) {

          case READ_SUCCESS:
          case READ_ERROR:
            /* Just because we got an error, that doesn't mean we were unable
               to read any of the file; we handle what we could get from the
               file. */
            break;

          case READ_ABORTED:
            /* Exit now. */
            gtk_exit(0);
            break;
          }
          /* Save the name of the containing directory specified in the
	     path name, if any; we can write over cf_name, which is a
             good thing, given that "get_dirname()" does write over its
             argument. */
          s = get_dirname(cf_name);
	  set_last_open_dir(s);
        } else {
          if (rfcode != NULL)
            dfilter_free(rfcode);
          cfile.rfcode = NULL;
        }
      }
    }
#ifdef HAVE_LIBPCAP
  }
#endif

  /* If the global preferences file exists but we failed to open it,
     pop up an alert box; we defer that until now, so that the alert
     box is more likely to come up on top of the main window. */
  if (gpf_path != NULL) {
      simple_dialog(ESD_TYPE_WARN, NULL,
        "Could not open global preferences file\n\"%s\": %s.", gpf_path,
        strerror(gpf_open_errno));
  }

  /* If the user's preferences file exists but we failed to open it,
     pop up an alert box; we defer that until now, so that the alert
     box is more likely to come up on top of the main window. */
  if (pf_path != NULL) {
      simple_dialog(ESD_TYPE_WARN, NULL,
        "Could not open your preferences file\n\"%s\": %s.", pf_path,
        strerror(pf_open_errno));
  }

  /* If the user's capture filter file exists but we failed to open it,
     pop up an alert box; we defer that until now, so that the alert
     box is more likely to come up on top of the main window. */
  if (cf_path != NULL) {
      simple_dialog(ESD_TYPE_WARN, NULL,
        "Could not open your capture filter file\n\"%s\": %s.", cf_path,
        strerror(cf_open_errno));
      g_free(cf_path);
  }

  /* If the user's display filter file exists but we failed to open it,
     pop up an alert box; we defer that until now, so that the alert
     box is more likely to come up on top of the main window. */
  if (df_path != NULL) {
      simple_dialog(ESD_TYPE_WARN, NULL,
        "Could not open your display filter file\n\"%s\": %s.", df_path,
        strerror(df_open_errno));
      g_free(df_path);
  }

#ifdef HAVE_LIBPCAP
  if (capture_child) {
    /* This is the child process for a sync mode or fork mode capture,
       so just do the low-level work of a capture - don't create
       a temporary file and fork off *another* child process (so don't
       call "do_capture()"). */

       /* XXX - hand these stats to the parent process */
       capture(&stats_known, &stats);

       /* The capture is done; there's nothing more for us to do. */
       gtk_exit(0);
  } else {
    if (start_capture) {
      /* "-k" was specified; start a capture. */
      do_capture(save_file);
    }
    else {
      set_menus_for_capture_in_progress(FALSE);
    }
  }
#else
  set_menus_for_capture_in_progress(FALSE);
#endif

  gtk_main();

	/* Try to save our geometry.  GTK+ provides two routines to get a
		 window's position relative to the X root window.  If I understand the
		 documentation correctly, gdk_window_get_deskrelative_origin applies
		 mainly to Enlightenment and gdk_window_get_root_origin applies for
		 all other WMs.
	   
	   The code below tries both routines, and picks the one that returns
	   the upper-left-most coordinates.
	   
	   More info at:

	   http://mail.gnome.org/archives/gtk-devel-list/2001-March/msg00289.html
	   http://www.gtk.org/faq/#AEN600 */

	/* Re-read our saved preferences. */
	/* XXX - Move all of this into a separate function? */
	prefs = read_prefs(&gpf_open_errno, &gpf_path, &pf_open_errno, &pf_path);

	if (pf_path == NULL) {
 		if (prefs->gui_geometry_save_position) {
			if (top_level->window != NULL) {
				gdk_window_get_root_origin(top_level->window, &root_x, &root_y);
				if (gdk_window_get_deskrelative_origin(top_level->window,
							&desk_x, &desk_y)) {
					if (desk_x <= root_x && desk_y <= root_y) {
						root_x = desk_x;
						root_y = desk_y;
					}
				}
			}
			if (prefs->gui_geometry_main_x != root_x) {
				prefs->gui_geometry_main_x = root_x;
				prefs_write_needed = TRUE;
			}
			if (prefs->gui_geometry_main_y != root_y) {
				prefs->gui_geometry_main_y = root_y;
				prefs_write_needed = TRUE;
			}
		}
		
		if (prefs->gui_geometry_save_size) {
			if (top_level->window != NULL) {
				/* XXX - Is this the "approved" method? */
				gdk_window_get_size(top_level->window, &top_width, &top_height);
			}
			if (prefs->gui_geometry_main_width != top_width) {
				prefs->gui_geometry_main_width = top_width;
				prefs_write_needed = TRUE;
			}
			if (prefs->gui_geometry_main_height != top_height) {
				prefs->gui_geometry_main_height = top_height;
				prefs_write_needed = TRUE;
			}
		}
		
		if (prefs_write_needed) {
			write_prefs(&pf_path);
		}
	}
	
  epan_cleanup();
  g_free(rc_file);

#ifdef WIN32
  /* Shutdown windows sockets */
  WSACleanup();

  /* For some unknown reason, the "atexit()" call in "create_console()"
     doesn't arrange that "destroy_console()" be called when we exit,
     so we call it here if a console was created. */
  if (console_was_created)
    destroy_console();
#endif

  gtk_exit(0);

  /* This isn't reached, but we need it to keep GCC from complaining
     that "main()" returns without returning a value - it knows that
     "exit()" never returns, but it doesn't know that "gtk_exit()"
     doesn't, as GTK+ doesn't declare it with the attribute
     "noreturn". */
  return 0;	/* not reached */
}

#ifdef WIN32

/* We build this as a GUI subsystem application on Win32, so
   "WinMain()", not "main()", gets called.

   Hack shamelessly stolen from the Win32 port of the GIMP. */
#ifdef __GNUC__
#define _stdcall  __attribute__((stdcall))
#endif

int _stdcall
WinMain (struct HINSTANCE__ *hInstance,
	 struct HINSTANCE__ *hPrevInstance,
	 char               *lpszCmdLine,
	 int                 nCmdShow)
{
  has_no_console = TRUE;
  return main (__argc, __argv);
}

/*
 * If this application has no console window to which its standard output
 * would go, create one.
 */
static void
create_console(void)
{
  if (has_no_console) {
    /* We have no console to which to print the version string, so
       create one and make it the standard input, output, and error. */
    if (!AllocConsole())
      return;   /* couldn't create console */
    freopen("CONIN$", "r", stdin);
    freopen("CONOUT$", "w", stdout);
    freopen("CONOUT$", "w", stderr);

    /* Well, we have a console now. */
    has_no_console = FALSE;
    console_was_created = TRUE;

    /* Now register "destroy_console()" as a routine to be called just
       before the application exits, so that we can destroy the console
       after the user has typed a key (so that the console doesn't just
       disappear out from under them, giving the user no chance to see
       the message(s) we put in there). */
    atexit(destroy_console);
  }
}

static void
destroy_console(void)
{
  printf("\n\nPress any key to exit\n");
  _getch();
  FreeConsole();
}

/* This routine should not be necessary, at least as I read the GLib
   source code, as it looks as if GLib is, on Win32, *supposed* to
   create a console window into which to display its output.

   That doesn't happen, however.  I suspect there's something completely
   broken about that code in GLib-for-Win32, and that it may be related
   to the breakage that forces us to just call "printf()" on the message
   rather than passing the message on to "g_log_default_handler()"
   (which is the routine that does the aforementioned non-functional
   console window creation). */
static void
console_log_handler(const char *log_domain, GLogLevelFlags log_level,
		    const char *message, gpointer user_data)
{
  create_console();
  if (console_was_created) {
    /* For some unknown reason, the above doesn't appear to actually cause
       anything to be sent to the standard output, so we'll just splat the
       message out directly, just to make sure it gets out. */
    printf("%s\n", message);
  } else
    g_log_default_handler(log_domain, log_level, message, user_data);
}
#endif

/* Given a font name, construct the name of the next heavier version of
   that font. */

#define	XLFD_WEIGHT	3	/* index of the "weight" field */

/* Map from a given weight to the appropriate weight for the "bold"
   version of a font.
   XXX - the XLFD says these strings shouldn't be used for font matching;
   can we get the weight, as a number, from GDK, and ask GDK to find us
   a font just like the given font, but with the appropriate higher
   weight? */
static const struct {
	char	*light;
	char	*heavier;
} weight_map[] = {
	{ "ultralight", "light" },
	{ "extralight", "semilight" },
	{ "light",      "medium" },
	{ "semilight",  "semibold" },
	{ "medium",     "bold" },
	{ "normal",     "bold" },
	{ "semibold",   "extrabold" },
	{ "bold",       "ultrabold" }
};
#define	N_WEIGHTS	(sizeof weight_map / sizeof weight_map[0])
	
char *
boldify(const char *font_name)
{
	char *bold_font_name;
	gchar **xlfd_tokens;
	unsigned int i;

	/* Is this an XLFD font?  If it begins with "-", yes, otherwise no. */
	if (font_name[0] == '-') {
		xlfd_tokens = g_strsplit(font_name, "-", XLFD_WEIGHT+1);
		for (i = 0; i < N_WEIGHTS; i++) {
			if (strcmp(xlfd_tokens[XLFD_WEIGHT],
			    weight_map[i].light) == 0) {
				g_free(xlfd_tokens[XLFD_WEIGHT]);
				xlfd_tokens[XLFD_WEIGHT] =
				    g_strdup(weight_map[i].heavier);
				break;
			}
		}
		bold_font_name = g_strjoinv("-", xlfd_tokens);
		g_strfreev(xlfd_tokens);
	} else {
		/* Append "bold" to the name of the font. */
		bold_font_name = g_strconcat(font_name, "bold", NULL);
	}
	return bold_font_name;
}


static void
create_main_window (gint pl_size, gint tv_size, gint bv_size, e_prefs *prefs)
{
  GtkWidget           *main_vbox, *menubar, *u_pane, *l_pane,
                      *stat_hbox, *column_lb,
                      *filter_bt, *filter_cm, *filter_te,
                      *filter_apply,
                      *filter_reset;
  GList               *filter_list = NULL;
  GtkAccelGroup       *accel;
  GtkStyle            *win_style;
  GdkBitmap           *ascend_bm, *descend_bm;
  GdkPixmap           *ascend_pm, *descend_pm;
  column_arrows       *col_arrows;
  int			i;
  /* Display filter construct dialog has an Apply button, and "OK" not
     only sets our text widget, it activates it (i.e., it causes us to
     filter the capture). */
  static construct_args_t args = {
  	"Ethereal: Display Filter",
  	TRUE,
  	TRUE
  };
  
  /* Main window */  
  top_level = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  gtk_widget_set_name(top_level, "main window");
  gtk_signal_connect(GTK_OBJECT(top_level), "delete_event", 
    GTK_SIGNAL_FUNC(main_window_delete_event_cb), NULL);
  gtk_signal_connect (GTK_OBJECT (top_level), "realize",
    GTK_SIGNAL_FUNC (window_icon_realize_cb), NULL);
  gtk_window_set_title(GTK_WINDOW(top_level), "The Ethereal Network Analyzer");
  if (prefs->gui_geometry_save_position) {
    gtk_widget_set_uposition(GTK_WIDGET(top_level),
      prefs->gui_geometry_main_x, prefs->gui_geometry_main_y);
  }
  if (prefs->gui_geometry_save_size) {
    gtk_widget_set_usize(GTK_WIDGET(top_level),
      prefs->gui_geometry_main_width, prefs->gui_geometry_main_height);
  } else {
    gtk_widget_set_usize(GTK_WIDGET(top_level), DEF_WIDTH, -1);
  }
  gtk_window_set_policy(GTK_WINDOW(top_level), TRUE, TRUE, FALSE);

  /* Container for menu bar, paned windows and progress/info box */
  main_vbox = gtk_vbox_new(FALSE, 1);
  gtk_container_border_width(GTK_CONTAINER(main_vbox), 1);
  gtk_container_add(GTK_CONTAINER(top_level), main_vbox);
  gtk_widget_show(main_vbox);

  /* Menu bar */
  get_main_menu(&menubar, &accel);
  gtk_window_add_accel_group(GTK_WINDOW(top_level), accel);
  gtk_box_pack_start(GTK_BOX(main_vbox), menubar, FALSE, TRUE, 0);
  gtk_widget_show(menubar);

  /* Panes for the packet list, tree, and byte view */
  u_pane = gtk_vpaned_new();
  gtk_paned_gutter_size(GTK_PANED(u_pane), (GTK_PANED(u_pane))->handle_size);
  l_pane = gtk_vpaned_new();
  gtk_paned_gutter_size(GTK_PANED(l_pane), (GTK_PANED(l_pane))->handle_size);
  gtk_container_add(GTK_CONTAINER(main_vbox), u_pane);
  gtk_widget_show(l_pane);
  gtk_paned_add2(GTK_PANED(u_pane), l_pane);
  gtk_widget_show(u_pane);

  /* Packet list */
  pkt_scrollw = scrolled_window_new(NULL, NULL);
  gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW(pkt_scrollw),
    GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
  gtk_widget_show(pkt_scrollw);
  gtk_paned_add1(GTK_PANED(u_pane), pkt_scrollw);

  packet_list = gtk_clist_new(cfile.cinfo.num_cols);
  /* Column titles are filled in below */
  gtk_container_add(GTK_CONTAINER(pkt_scrollw), packet_list);

  col_arrows = (column_arrows *) g_malloc(sizeof(column_arrows) * cfile.cinfo.num_cols);
  
  set_plist_sel_browse(prefs->gui_plist_sel_browse);
  set_plist_font(m_r_font);
  gtk_widget_set_name(packet_list, "packet list");
  gtk_signal_connect (GTK_OBJECT (packet_list), "click_column",
    GTK_SIGNAL_FUNC(packet_list_click_column_cb), col_arrows);
  gtk_signal_connect(GTK_OBJECT(packet_list), "select_row",
    GTK_SIGNAL_FUNC(packet_list_select_cb), NULL);
  gtk_signal_connect(GTK_OBJECT(packet_list), "unselect_row",
    GTK_SIGNAL_FUNC(packet_list_unselect_cb), NULL);
  for (i = 0; i < cfile.cinfo.num_cols; i++) {
    if (get_column_resize_type(cfile.cinfo.col_fmt[i]) != RESIZE_MANUAL)
      gtk_clist_set_column_auto_resize(GTK_CLIST(packet_list), i, TRUE);

    /* Right-justify the packet number column. */
    if (cfile.cinfo.col_fmt[i] == COL_NUMBER)
      gtk_clist_set_column_justification(GTK_CLIST(packet_list), i, 
        GTK_JUSTIFY_RIGHT);
  }
  gtk_widget_set_usize(packet_list, -1, pl_size);
  gtk_signal_connect(GTK_OBJECT(packet_list), "button_press_event",
		     GTK_SIGNAL_FUNC(popup_menu_handler), 
		     gtk_object_get_data(GTK_OBJECT(popup_menu_object), PM_PACKET_LIST_KEY));
  gtk_signal_connect(GTK_OBJECT(packet_list), "button_press_event",
		     GTK_SIGNAL_FUNC(packet_list_button_pressed_cb), NULL);
  gtk_clist_set_compare_func(GTK_CLIST(packet_list), packet_list_compare);
  gtk_widget_show(packet_list);

  /* Tree view */
  item_style = gtk_style_new();
  gdk_font_unref(item_style->font);
  item_style->font = m_r_font;
  create_tree_view(tv_size, prefs, l_pane, &tv_scrollw, &tree_view,
			prefs->gui_scrollbar_on_right);
  gtk_signal_connect(GTK_OBJECT(tree_view), "tree-select-row",
    GTK_SIGNAL_FUNC(tree_view_select_row_cb), NULL);
  gtk_signal_connect(GTK_OBJECT(tree_view), "tree-unselect-row",
    GTK_SIGNAL_FUNC(tree_view_unselect_row_cb), NULL);
  gtk_signal_connect(GTK_OBJECT(tree_view), "button_press_event",
		     GTK_SIGNAL_FUNC(popup_menu_handler),
		     gtk_object_get_data(GTK_OBJECT(popup_menu_object), PM_TREE_VIEW_KEY));
  gtk_widget_show(tree_view);

  /* Byte view. */
  create_byte_view(bv_size, l_pane, &byte_nb_ptr, &bv_scrollw,
			prefs->gui_scrollbar_on_right);

  gtk_signal_connect(GTK_OBJECT(byte_nb_ptr), "button_press_event",
		     GTK_SIGNAL_FUNC(popup_menu_handler),
		     gtk_object_get_data(GTK_OBJECT(popup_menu_object), PM_HEXDUMP_KEY));

  /* Filter/info box */
  stat_hbox = gtk_hbox_new(FALSE, 1);
  gtk_container_border_width(GTK_CONTAINER(stat_hbox), 0);
  gtk_box_pack_start(GTK_BOX(main_vbox), stat_hbox, FALSE, TRUE, 0);
  gtk_widget_show(stat_hbox);

  filter_bt = gtk_button_new_with_label("Filter:");
  gtk_signal_connect(GTK_OBJECT(filter_bt), "clicked",
    GTK_SIGNAL_FUNC(display_filter_construct_cb), &args);
  gtk_box_pack_start(GTK_BOX(stat_hbox), filter_bt, FALSE, TRUE, 0);
  gtk_widget_show(filter_bt);
  
  filter_cm = gtk_combo_new();
  filter_list = g_list_append (filter_list, "");
  gtk_combo_set_popdown_strings(GTK_COMBO(filter_cm), filter_list);
  gtk_combo_disable_activate(GTK_COMBO(filter_cm));
  filter_te = GTK_COMBO(filter_cm)->entry;
  gtk_object_set_data(GTK_OBJECT(filter_bt), E_FILT_TE_PTR_KEY, filter_te);
  gtk_object_set_data(GTK_OBJECT(filter_te), E_DFILTER_CM_KEY, filter_cm);
  gtk_object_set_data(GTK_OBJECT(filter_te), E_DFILTER_FL_KEY, filter_list);
  gtk_box_pack_start(GTK_BOX(stat_hbox), filter_cm, TRUE, TRUE, 3);
  gtk_signal_connect(GTK_OBJECT(filter_te), "activate",
    GTK_SIGNAL_FUNC(filter_activate_cb), filter_te);
  gtk_widget_show(filter_cm);

  filter_reset = gtk_button_new_with_label("Reset");
  gtk_object_set_data(GTK_OBJECT(filter_reset), E_DFILTER_TE_KEY, filter_te);
  gtk_signal_connect(GTK_OBJECT(filter_reset), "clicked",
		     GTK_SIGNAL_FUNC(filter_reset_cb), NULL);
  gtk_box_pack_start(GTK_BOX(stat_hbox), filter_reset, FALSE, TRUE, 1);
  gtk_widget_show(filter_reset);

  filter_apply = gtk_button_new_with_label("Apply");
  gtk_object_set_data(GTK_OBJECT(filter_apply), E_DFILTER_CM_KEY, filter_cm);
  gtk_object_set_data(GTK_OBJECT(filter_apply), E_DFILTER_FL_KEY, filter_list);
  gtk_signal_connect(GTK_OBJECT(filter_apply), "clicked",
                     GTK_SIGNAL_FUNC(filter_activate_cb), filter_te);
  gtk_box_pack_start(GTK_BOX(stat_hbox), filter_apply, FALSE, TRUE, 1);
  gtk_widget_show(filter_apply);

  /* Sets the text entry widget pointer as the E_DILTER_TE_KEY data
   * of any widget that ends up calling a callback which needs
   * that text entry pointer */
  set_menu_object_data("/File/Open...", E_DFILTER_TE_KEY, filter_te);
  set_menu_object_data("/File/Reload", E_DFILTER_TE_KEY, filter_te);
  set_menu_object_data("/Edit/Filters...", E_FILT_TE_PTR_KEY, filter_te);
  set_menu_object_data("/Tools/Follow TCP Stream", E_DFILTER_TE_KEY, filter_te);
  set_menu_object_data("/Display/Match/Selected", E_DFILTER_TE_KEY, filter_te);
  set_menu_object_data("/Display/Match/Not Selected", E_DFILTER_TE_KEY, filter_te);
  set_menu_object_data("/Display/Match/And Selected", E_DFILTER_TE_KEY, filter_te);
  set_menu_object_data("/Display/Match/Or Selected", E_DFILTER_TE_KEY, filter_te);
  set_menu_object_data("/Display/Match/And Not Selected", E_DFILTER_TE_KEY, filter_te);
  set_menu_object_data("/Display/Match/Or Not Selected", E_DFILTER_TE_KEY, filter_te);
  set_menu_object_data("/Display/Prepare/Selected", E_DFILTER_TE_KEY, filter_te);
  set_menu_object_data("/Display/Prepare/Not Selected", E_DFILTER_TE_KEY, filter_te);
  set_menu_object_data("/Display/Prepare/And Selected", E_DFILTER_TE_KEY, filter_te);
  set_menu_object_data("/Display/Prepare/Or Selected", E_DFILTER_TE_KEY, filter_te);
  set_menu_object_data("/Display/Prepare/And Not Selected", E_DFILTER_TE_KEY, filter_te);
  set_menu_object_data("/Display/Prepare/Or Not Selected", E_DFILTER_TE_KEY, filter_te);
  gtk_object_set_data(GTK_OBJECT(popup_menu_object), E_DFILTER_TE_KEY, filter_te);
  gtk_object_set_data(GTK_OBJECT(popup_menu_object), E_MPACKET_LIST_KEY, packet_list);

  info_bar = gtk_statusbar_new();
  main_ctx = gtk_statusbar_get_context_id(GTK_STATUSBAR(info_bar), "main");
  file_ctx = gtk_statusbar_get_context_id(GTK_STATUSBAR(info_bar), "file");
  help_ctx = gtk_statusbar_get_context_id(GTK_STATUSBAR(info_bar), "help");
  gtk_statusbar_push(GTK_STATUSBAR(info_bar), main_ctx, DEF_READY_MESSAGE);
  gtk_box_pack_start(GTK_BOX(stat_hbox), info_bar, TRUE, TRUE, 0);
  gtk_widget_show(info_bar);

  gtk_widget_show(top_level);

  /* Fill in column titles.  This must be done after the top level window
     is displayed. */
  win_style = gtk_widget_get_style(top_level);
  ascend_pm = gdk_pixmap_create_from_xpm_d(top_level->window, &ascend_bm,
  	&win_style->bg[GTK_STATE_NORMAL], (gchar **)clist_ascend_xpm);
  descend_pm = gdk_pixmap_create_from_xpm_d(top_level->window, &descend_bm,
  	&win_style->bg[GTK_STATE_NORMAL], (gchar **)clist_descend_xpm);
  for (i = 0; i < cfile.cinfo.num_cols; i++) {
    col_arrows[i].table = gtk_table_new(2, 2, FALSE);
    gtk_table_set_col_spacings(GTK_TABLE(col_arrows[i].table), 5);
    column_lb = gtk_label_new(cfile.cinfo.col_title[i]);
    gtk_table_attach(GTK_TABLE(col_arrows[i].table), column_lb, 0, 1, 0, 2,
    	GTK_SHRINK, GTK_SHRINK, 0, 0);
    gtk_widget_show(column_lb);
    col_arrows[i].ascend_pm = gtk_pixmap_new(ascend_pm, ascend_bm);
    gtk_table_attach(GTK_TABLE(col_arrows[i].table), col_arrows[i].ascend_pm, 
    	1, 2, 1, 2, GTK_SHRINK, GTK_SHRINK, 0, 0);
    if (i == 0) {
      gtk_widget_show(col_arrows[i].ascend_pm);
    }
    col_arrows[i].descend_pm = gtk_pixmap_new(descend_pm, descend_bm);
    gtk_table_attach(GTK_TABLE(col_arrows[i].table), col_arrows[i].descend_pm,
    	1, 2, 0, 1, GTK_SHRINK, GTK_SHRINK, 0, 0);
    gtk_clist_set_column_widget(GTK_CLIST(packet_list), i, col_arrows[i].table);
    gtk_widget_show(col_arrows[i].table);
  }
  gtk_clist_column_titles_show(GTK_CLIST(packet_list));
}


void
set_last_open_dir(char *dirname)
{
	int len;

	if (last_open_dir) {
		g_free(last_open_dir);
	}

	if (dirname) {
		len = strlen(dirname);
		if (dirname[len-1] != G_DIR_SEPARATOR) {
			last_open_dir = g_strconcat(dirname, G_DIR_SEPARATOR_S,
				NULL);
		}
	}
	else {
		last_open_dir = NULL;
	}
}
