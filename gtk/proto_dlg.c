/* proto_dlg.c
 *
 * $Id: proto_dlg.c,v 1.9 2002/01/11 07:40:31 guy Exp $
 *
 * Laurent Deniel <deniel@worldnet.fr>
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 2000 Gerald Combs
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

#include <gtk/gtk.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include "prefs.h"
#include "globals.h"
#include "main.h"
#include "util.h"
#include "ui_util.h"
#include "dlg_utils.h"
#include "proto_dlg.h"

static gboolean proto_delete_cb(GtkWidget *, gpointer);
static void proto_ok_cb(GtkWidget *, gpointer);
static void proto_apply_cb(GtkWidget *, gpointer);
static void proto_cancel_cb(GtkWidget *, gpointer);
static void proto_destroy_cb(GtkWidget *, gpointer);

static void show_proto_selection(GtkWidget *main, GtkWidget *container);
static gboolean set_proto_selection(GtkWidget *);
static gboolean revert_proto_selection(void);

static void toggle_all_cb(GtkWidget *button, gpointer parent_w);
static void enable_all_cb(GtkWidget *button, gpointer parent_w);
static void disable_all_cb(GtkWidget *button, gpointer parent_w);

static GtkWidget *proto_w = NULL;

/* list of protocols */
static GSList *protocol_list = NULL;

typedef struct protocol_data {
  char     *name;
  char 	   *abbrev;
  int  	   hfinfo_index;
  gboolean was_enabled;
} protocol_data_t;

void proto_cb(GtkWidget *w, gpointer data)
{

  GtkWidget *main_vb, *bbox, *proto_nb, *apply_bt, *cancel_bt, *ok_bt, 
    *label, *scrolled_w, *selection_vb, *button;
  
  if (proto_w != NULL) {
    reactivate_window(proto_w);
    return;
  }

  proto_w = dlg_window_new("Ethereal: Protocol");
  gtk_signal_connect(GTK_OBJECT(proto_w), "delete_event",
		     GTK_SIGNAL_FUNC(proto_delete_cb), NULL);
  gtk_signal_connect(GTK_OBJECT(proto_w), "destroy",
		     GTK_SIGNAL_FUNC(proto_destroy_cb), NULL);
  gtk_widget_set_usize(GTK_WIDGET(proto_w), DEF_WIDTH * 2/3, DEF_HEIGHT * 2/3);

  /* Container for each row of widgets */

  main_vb = gtk_vbox_new(FALSE, 0);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 1);
  gtk_container_add(GTK_CONTAINER(proto_w), main_vb);
  gtk_widget_show(main_vb);

  /* Protocol topics container */
  
  proto_nb = gtk_notebook_new();
  gtk_container_add(GTK_CONTAINER(main_vb), proto_nb);
  /* XXX do not know why I need this to fill all space around buttons */
  gtk_widget_set_usize(GTK_WIDGET(proto_nb), DEF_WIDTH * 2/3 - 50,
		       DEF_HEIGHT * 2/3 - 50);

  /* Protocol selection panel ("enable/disable" protocols) */

  selection_vb = gtk_vbox_new(FALSE, 0);
  gtk_container_border_width(GTK_CONTAINER(selection_vb), 1);  
  label = gtk_label_new("Button pressed: protocol decoding is enabled");
  gtk_widget_show(label);
  gtk_box_pack_start(GTK_BOX(selection_vb), label, FALSE, FALSE, 0);
  scrolled_w = scrolled_window_new(NULL, NULL);         
  gtk_container_set_border_width(GTK_CONTAINER(scrolled_w), 1);           
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_w),
				 GTK_POLICY_AUTOMATIC,
				 GTK_POLICY_ALWAYS);
  gtk_box_pack_start(GTK_BOX(selection_vb), scrolled_w, TRUE, TRUE, 0);
  show_proto_selection(proto_w, scrolled_w);
  gtk_widget_show(scrolled_w);
  gtk_widget_show(selection_vb);
  label = gtk_label_new("Decoding");
  gtk_notebook_append_page(GTK_NOTEBOOK(proto_nb), selection_vb, label);
  label = gtk_label_new("Note that when a protocol is disabled, "
			"all linked sub-protocols are as well");
  gtk_widget_show(label);
  gtk_box_pack_start(GTK_BOX(selection_vb), label, FALSE, FALSE, 0);


  bbox = gtk_hbutton_box_new();
  gtk_button_box_set_layout(GTK_BUTTON_BOX(bbox), GTK_BUTTONBOX_END);
  gtk_button_box_set_spacing(GTK_BUTTON_BOX(bbox), 5);
  gtk_box_pack_start(GTK_BOX(selection_vb), bbox, FALSE, FALSE, 0);
  gtk_widget_show(bbox);

  /* Toggle All */
  button = gtk_button_new_with_label("Toggle All");
  gtk_signal_connect(GTK_OBJECT(button), "clicked",
		  GTK_SIGNAL_FUNC(toggle_all_cb), GTK_OBJECT(proto_w));
  gtk_box_pack_start(GTK_BOX(bbox), button, TRUE, TRUE, 0);
  gtk_widget_show(button);

  /* Enable All */
  button = gtk_button_new_with_label("Enable All");
  gtk_signal_connect(GTK_OBJECT(button), "clicked",
		  GTK_SIGNAL_FUNC(enable_all_cb), GTK_OBJECT(proto_w));
  gtk_box_pack_start(GTK_BOX(bbox), button, TRUE, TRUE, 0);
  gtk_widget_show(button);

  /* Disable All */
  button = gtk_button_new_with_label("Disable All");
  gtk_signal_connect(GTK_OBJECT(button), "clicked",
		  GTK_SIGNAL_FUNC(disable_all_cb), GTK_OBJECT(proto_w));
  gtk_box_pack_start(GTK_BOX(bbox), button, TRUE, TRUE, 0);
  gtk_widget_show(button);


  /* XXX add other protocol-related panels here ... */

  gtk_widget_show(proto_nb);

  /* Ok, Apply, Cancel Buttons */  

  bbox = gtk_hbutton_box_new();
  gtk_button_box_set_layout(GTK_BUTTON_BOX(bbox), GTK_BUTTONBOX_END);
  gtk_button_box_set_spacing(GTK_BUTTON_BOX(bbox), 5);
  gtk_container_add(GTK_CONTAINER(main_vb), bbox);
  gtk_widget_show(bbox);

  ok_bt = gtk_button_new_with_label ("OK");
  gtk_signal_connect(GTK_OBJECT(ok_bt), "clicked",
		     GTK_SIGNAL_FUNC(proto_ok_cb), GTK_OBJECT(proto_w));
  GTK_WIDGET_SET_FLAGS(ok_bt, GTK_CAN_DEFAULT);
  gtk_box_pack_start(GTK_BOX (bbox), ok_bt, TRUE, TRUE, 0);
  gtk_widget_grab_default(ok_bt);
  gtk_widget_show(ok_bt);

  apply_bt = gtk_button_new_with_label ("Apply");
  gtk_signal_connect(GTK_OBJECT(apply_bt), "clicked",
		     GTK_SIGNAL_FUNC(proto_apply_cb), GTK_OBJECT(proto_w));
  GTK_WIDGET_SET_FLAGS(apply_bt, GTK_CAN_DEFAULT);
  gtk_box_pack_start(GTK_BOX (bbox), apply_bt, TRUE, TRUE, 0);
  gtk_widget_show(apply_bt);

  cancel_bt = gtk_button_new_with_label ("Cancel");
  gtk_signal_connect(GTK_OBJECT(cancel_bt), "clicked",
		     GTK_SIGNAL_FUNC(proto_cancel_cb), GTK_OBJECT(proto_w));
  GTK_WIDGET_SET_FLAGS(cancel_bt, GTK_CAN_DEFAULT);
  gtk_box_pack_start(GTK_BOX (bbox), cancel_bt, TRUE, TRUE, 0);
  gtk_widget_show(cancel_bt);

  dlg_set_cancel(proto_w, cancel_bt);

  gtk_quit_add_destroy(gtk_main_level(), GTK_OBJECT(proto_w));
  gtk_widget_show(proto_w);

} /* proto_cb */


/* Toggle All */
static void
toggle_all_cb(GtkWidget *button, gpointer parent_w)
{

  GSList *entry;

  for (entry = protocol_list; entry != NULL; entry = g_slist_next(entry)) {
    GtkWidget *button;
    protocol_data_t *p = entry->data;

    button = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(parent_w),
					       p->abbrev);
    /* gtk_toggle_button_toggled() didn't work for me... */
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(button),
		    !gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(button)));
  }
}

/* Enable/Disable All Helper */
static void
set_active_all(GtkWidget *button, gpointer parent_w, gboolean new_state)
{

  GSList *entry;

  for (entry = protocol_list; entry != NULL; entry = g_slist_next(entry)) {
    GtkWidget *button;
    protocol_data_t *p = entry->data;

    button = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(parent_w),
					       p->abbrev);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(button), new_state);
  }
}

/* Enable All */
static void
enable_all_cb(GtkWidget *button, gpointer parent_w)
{
	set_active_all(button, parent_w, TRUE);
}

/* Disable All */
static void
disable_all_cb(GtkWidget *button, gpointer parent_w)
{
	set_active_all(button, parent_w, FALSE);
}

static void proto_destroy_cb(GtkWidget *w, gpointer data)
{
  GSList *entry;

  if (proto_w)
    gtk_widget_destroy(proto_w);
  proto_w = NULL;
  
  /* remove protocol list */
  if (protocol_list) {
    for (entry = protocol_list; entry != NULL; entry = g_slist_next(entry)) {
      g_free(entry->data);
    }
    g_slist_free(protocol_list);
    protocol_list = NULL;    
  }
}

/* Treat this as a cancel, by calling "proto_cancel_cb()".
   XXX - that'll destroy the Protocols dialog; will that upset
   a higher-level handler that says "OK, we've been asked to delete
   this, so destroy it"? */
static gboolean proto_delete_cb(GtkWidget *proto_w, gpointer dummy)
{
  proto_cancel_cb(NULL, proto_w);
  return FALSE;
}

static void proto_ok_cb(GtkWidget *ok_bt, gpointer parent_w) 
{
  gboolean redissect;

  redissect = set_proto_selection(GTK_WIDGET(parent_w));
  gtk_widget_destroy(GTK_WIDGET(parent_w));
  if (redissect)
    redissect_packets(&cfile);
}

static void proto_apply_cb(GtkWidget *apply_bt, gpointer parent_w) 
{
  if (set_proto_selection(GTK_WIDGET(parent_w)))
    redissect_packets(&cfile);
}

static void proto_cancel_cb(GtkWidget *cancel_bt, gpointer parent_w) 
{
  gboolean redissect;

  redissect = revert_proto_selection();
  gtk_widget_destroy(GTK_WIDGET(parent_w));
  if (redissect)
    redissect_packets(&cfile);
}

static gboolean set_proto_selection(GtkWidget *parent_w)
{
  GSList *entry;
  gboolean need_redissect = FALSE;

  for (entry = protocol_list; entry != NULL; entry = g_slist_next(entry)) {
    GtkWidget *button;
    protocol_data_t *p = entry->data;

    button = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(parent_w),
					       p->abbrev);
    if (proto_is_protocol_enabled(p->hfinfo_index) != GTK_TOGGLE_BUTTON (button)->active) {
      proto_set_decoding(p->hfinfo_index, GTK_TOGGLE_BUTTON (button)->active);
      need_redissect = TRUE;
    }  
  }

  return need_redissect;

} /* set_proto_selection */

static gboolean revert_proto_selection(void)
{
  GSList *entry;
  gboolean need_redissect = FALSE;

  /*
   * Undo all the changes we've made to protocol enable flags.
   */
  for (entry = protocol_list; entry != NULL; entry = g_slist_next(entry)) {
    protocol_data_t *p = entry->data;

    if (proto_is_protocol_enabled(p->hfinfo_index) != p->was_enabled) {
      proto_set_decoding(p->hfinfo_index, p->was_enabled);
      need_redissect = TRUE;
    }  
  }

  return need_redissect;

} /* revert_proto_selection */

gint protocol_data_compare(gconstpointer a, gconstpointer b)
{
  return strcmp(((protocol_data_t *)a)->abbrev, 
		((protocol_data_t *)b)->abbrev);
}

static void show_proto_selection(GtkWidget *main, GtkWidget *container)
{

#define NB_COL	7

  GSList *entry;
  GtkTooltips *tooltips;
  GtkWidget *table;
  int i, t = 0, l = 0, nb_line, nb_proto = 0;
  void *cookie;
  protocol_data_t *p;

  /* Iterate over all the protocols */

  for (i = proto_get_first_protocol(&cookie); i != -1;
       i = proto_get_next_protocol(&cookie)) {
      if (proto_can_disable_protocol(i)) {
        p = g_malloc(sizeof(protocol_data_t));
        p->name = proto_get_protocol_name(i);
        p->abbrev = proto_get_protocol_filter_name(i);
        p->hfinfo_index = i;
        p->was_enabled = proto_is_protocol_enabled(i);
        protocol_list = g_slist_insert_sorted(protocol_list, 
					    p, protocol_data_compare);     
        nb_proto ++;
      }
  }

  /* create a table (n x NB_COL) of buttons */

  nb_line = (nb_proto % NB_COL) ? nb_proto / NB_COL + 1 : nb_proto / NB_COL;
  table = gtk_table_new (nb_line, NB_COL, FALSE);
  gtk_table_set_row_spacings(GTK_TABLE (table), 1);
  gtk_table_set_col_spacings(GTK_TABLE (table), 1);
  gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(container), table);
  gtk_widget_show(table);

  tooltips = gtk_tooltips_new();

  nb_proto = 0;

  for (entry = protocol_list; entry != NULL; entry = g_slist_next(entry)) {
    GtkWidget *button;

    p = entry->data;
    /* button label is the protocol abbrev */
    button = gtk_toggle_button_new_with_label(p->abbrev);
    /* tip is the complete protocol name */
    gtk_tooltips_set_tip(tooltips, button, p->name, NULL);
    gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(button),
				proto_is_protocol_enabled(p->hfinfo_index));
    gtk_object_set_data(GTK_OBJECT(main), p->abbrev, button);
    gtk_table_attach_defaults (GTK_TABLE (table), button, l, l+1, t, t+1);
    gtk_widget_show (button);
    if (++nb_proto % NB_COL) {
      l++;
    }
    else {
      l = 0;
      t++;
    }
  }

} /* show_proto_selection */
