/* prefs_dlg.c
 * Routines for handling preferences
 *
 * $Id: prefs_dlg.c,v 1.42 2002/02/14 10:58:49 gram Exp $
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

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <gtk/gtk.h>

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#include <epan/filesystem.h>

#include "main.h"
#include <epan/packet.h>
#include "file.h"
#include "prefs.h"
#include "column_prefs.h"
#include "print.h"
#include "prefs_dlg.h"
#include "print_prefs.h"
#include "stream_prefs.h"
#include "gui_prefs.h"
#include "capture_prefs.h"
#include "nameres_prefs.h"
#include "ui_util.h"
#include "dlg_utils.h"
#include "simple_dialog.h"

#include "prefs-int.h"

static void     prefs_main_ok_cb(GtkWidget *, gpointer);
static void     prefs_main_apply_cb(GtkWidget *, gpointer);
static void     prefs_main_save_cb(GtkWidget *, gpointer);
static void     prefs_main_cancel_cb(GtkWidget *, gpointer);
static gboolean prefs_main_delete_cb(GtkWidget *, gpointer);
static void     prefs_main_destroy_cb(GtkWidget *, gpointer);
static void	prefs_tree_select_cb(GtkCTree *, GtkCTreeNode *, gint, gpointer);

#define E_PRINT_PAGE_KEY   "printer_options_page"
#define E_COLUMN_PAGE_KEY  "column_options_page"
#define E_STREAM_PAGE_KEY  "tcp_stream_options_page"
#define E_GUI_PAGE_KEY	   "gui_options_page"
#define E_CAPTURE_PAGE_KEY "capture_options_page"
#define E_NAMERES_PAGE_KEY "nameres_options_page"
#define E_TOOLTIPS_KEY     "tooltips"

#define FIRST_PROTO_PREFS_PAGE	6

/* 
 * Keep a static pointer to the notebook to be able to choose the 
 * displayed page.
 */
static GtkWidget *notebook;

/*
 * Keep a static pointer to the current "Preferences" window, if any, so that
 * if somebody tries to do "Edit:Preferences" while there's already a
 * "Preferences" window up, we just pop up the existing one, rather than
 * creating a new one.
 */
static GtkWidget *prefs_w;

/*
 * Save the value of the preferences as of when the preferences dialog
 * box was first popped up, so we can revert to those values if the
 * user selects "Cancel".
 */
static e_prefs saved_prefs;

struct ct_struct {
  GtkWidget    *notebook;
  GtkWidget    *ctree;
  GtkCTreeNode *node;
  GtkTooltips  *tooltips;
  gint         page;
};

static void
pref_show(pref_t *pref, gpointer user_data)
{
  GtkWidget *main_tb = user_data;
  const char *title;
  char *label_string;
  char uint_str[10+1];

  /* Give this preference a label which is its title, followed by a colon,
     and left-align it. */
  title = pref->title;
  label_string = g_malloc(strlen(title) + 2);
  strcpy(label_string, title);
  strcat(label_string, ":");

  /* Save the current value of the preference, so that we can revert it if
     the user does "Apply" and then "Cancel", and create the control for
     editing the preference. */
  switch (pref->type) {

  case PREF_UINT:
    pref->saved_val.uint = *pref->varp.uint;

    /* XXX - there are no uint spinbuttons, so we can't use a spinbutton.
       Even more annoyingly, even if there were, GLib doesn't define
       G_MAXUINT - but I think ANSI C may define UINT_MAX, so we could
       use that. */
    switch (pref->info.base) {

    case 10:
      sprintf(uint_str, "%u", pref->saved_val.uint);
      break;

    case 8:
      sprintf(uint_str, "%o", pref->saved_val.uint);
      break;

    case 16:
      sprintf(uint_str, "%x", pref->saved_val.uint);
      break;
    }
    pref->control = create_preference_entry(main_tb, pref->ordinal,
					    label_string, pref->description,
					    uint_str);
    break;

  case PREF_BOOL:
    pref->saved_val.bool = *pref->varp.bool;
    pref->control = create_preference_check_button(main_tb, pref->ordinal,
					       label_string, pref->description,
					       pref->saved_val.bool);
    break;

  case PREF_ENUM:
    pref->saved_val.enumval = *pref->varp.enump;
    if (pref->info.enum_info.radio_buttons) {
      /* Show it as radio buttons. */
      pref->control = create_preference_radio_buttons(main_tb, pref->ordinal,
						  label_string, pref->description,
						  pref->info.enum_info.enumvals,
						  pref->saved_val.enumval);
    } else {
      /* Show it as an option menu. */
      pref->control = create_preference_option_menu(main_tb, pref->ordinal,
					 label_string, pref->description,
					 pref->info.enum_info.enumvals,
					 pref->saved_val.enumval);
    }
    break;

  case PREF_STRING:
    if (pref->saved_val.string != NULL)
      g_free(pref->saved_val.string);
    pref->saved_val.string = g_strdup(*pref->varp.string);
    pref->control = create_preference_entry(main_tb, pref->ordinal,
					    label_string, pref->description,
					    pref->saved_val.string);
    break;

  case PREF_OBSOLETE:
    g_assert_not_reached();
    break;
  }
  g_free(label_string);
}

#define MAX_TREE_NODE_NAME_LEN 64
static void
module_prefs_show(module_t *module, gpointer user_data)
{
  struct ct_struct *cts = user_data;
  GtkWidget        *main_vb, *main_tb, *frame;
  gchar            label_str[MAX_TREE_NODE_NAME_LEN], *label_ptr = label_str;
  GtkCTreeNode     *ct_node;

  /* Frame */
  frame = gtk_frame_new(module->title);
  gtk_widget_show(frame);

  /* Main vertical box */
  main_vb = gtk_vbox_new(FALSE, 5);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_container_add(GTK_CONTAINER(frame), main_vb);

  /* Main table */
  main_tb = gtk_table_new(module->numprefs, 2, FALSE);
  gtk_box_pack_start(GTK_BOX(main_vb), main_tb, FALSE, FALSE, 0);
  gtk_table_set_row_spacings(GTK_TABLE(main_tb), 10);
  gtk_table_set_col_spacings(GTK_TABLE(main_tb), 15);
  gtk_object_set_data(GTK_OBJECT(main_tb), E_TOOLTIPS_KEY, cts->tooltips);

  /* Add items for each of the preferences */
  prefs_pref_foreach(module, pref_show, main_tb);

  gtk_notebook_append_page(GTK_NOTEBOOK(cts->notebook), frame, NULL);
  strcpy(label_str, module->title);
  ct_node = gtk_ctree_insert_node(GTK_CTREE(cts->ctree), cts->node, NULL, 
  		&label_ptr, 5, NULL, NULL, NULL, NULL, TRUE, TRUE);
  gtk_ctree_node_set_row_data(GTK_CTREE(cts->ctree), ct_node,
  		GINT_TO_POINTER(cts->page));
  cts->page++;

  /* Show 'em what we got */
  gtk_widget_show_all(main_vb);
}

void
prefs_cb(GtkWidget *w, gpointer dummy)
{
  GtkWidget        *main_vb, *top_hb, *bbox, *prefs_nb, *ct_sb, *frame,
                   *ok_bt, *apply_bt, *save_bt, *cancel_bt;
  GtkWidget        *print_pg, *column_pg, *stream_pg, *gui_pg, *capture_pg;
  GtkWidget        *nameres_pg;
  gchar            label_str[MAX_TREE_NODE_NAME_LEN], *label_ptr = label_str;
  GtkCTreeNode     *ct_node;
  struct ct_struct cts;

  if (prefs_w != NULL) {
    /* There's already a "Preferences" dialog box; reactivate it. */
    reactivate_window(prefs_w);
    return;
  }

  /* Save the current preferences, so we can revert to those values
     if the user presses "Cancel". */
  copy_prefs(&saved_prefs, &prefs);

  prefs_w = dlg_window_new("Ethereal: Preferences");
  gtk_signal_connect(GTK_OBJECT(prefs_w), "delete_event",
    GTK_SIGNAL_FUNC(prefs_main_delete_cb), NULL);
  gtk_signal_connect(GTK_OBJECT(prefs_w), "destroy",
	GTK_SIGNAL_FUNC(prefs_main_destroy_cb), NULL);
  
  /*
   * Unfortunately, we can't arrange that a GtkTable widget wrap an event box
   * around a table row, so the spacing between the preference item's label
   * and its control widgets is inactive and the tooltip doesn't pop up when
   * the mouse is over it.
   */
  cts.tooltips = gtk_tooltips_new();

  /* Container for each row of widgets */
  main_vb = gtk_vbox_new(FALSE, 5);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_container_add(GTK_CONTAINER(prefs_w), main_vb);
  gtk_widget_show(main_vb);
  
  /* Top row: Preferences tree and notebook */
  top_hb = gtk_hbox_new(FALSE, 10);
  gtk_container_add(GTK_CONTAINER(main_vb), top_hb);
  gtk_widget_show(top_hb);

  /* Place a Ctree on the left for preference categories */
  ct_sb = scrolled_window_new(NULL, NULL);
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(ct_sb),
  	GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
  gtk_container_add(GTK_CONTAINER(top_hb), ct_sb);
  gtk_widget_show(ct_sb);

  cts.ctree = ctree_new(1, 0);
  cts.page  = 0;
  gtk_container_add(GTK_CONTAINER(ct_sb), cts.ctree);

  gtk_clist_set_column_auto_resize(GTK_CLIST(cts.ctree), 0, TRUE);
  gtk_signal_connect(GTK_OBJECT(cts.ctree), "tree-select-row",
    GTK_SIGNAL_FUNC(prefs_tree_select_cb), NULL);
  gtk_widget_show(cts.ctree);
  
  /* A notebook widget sans tabs is used to flip between prefs */
  notebook = prefs_nb = gtk_notebook_new();
  gtk_notebook_set_show_tabs(GTK_NOTEBOOK(notebook), FALSE);
  gtk_notebook_set_show_border(GTK_NOTEBOOK(notebook), FALSE);
  gtk_container_add(GTK_CONTAINER(top_hb), prefs_nb);
  gtk_widget_show(prefs_nb);
  
  /* Printing prefs */
  frame = gtk_frame_new("Printing");
  gtk_widget_show(GTK_WIDGET(frame));
  print_pg = printer_prefs_show();
  gtk_container_add(GTK_CONTAINER(frame), print_pg);
  gtk_object_set_data(GTK_OBJECT(prefs_w), E_PRINT_PAGE_KEY, print_pg);
  gtk_notebook_append_page (GTK_NOTEBOOK(prefs_nb), frame, NULL);
  strcpy(label_str, "Printing");
  ct_node = gtk_ctree_insert_node(GTK_CTREE(cts.ctree), NULL, NULL, 
  		&label_ptr, 5, NULL, NULL, NULL, NULL, TRUE, TRUE);
  gtk_ctree_node_set_row_data(GTK_CTREE(cts.ctree), ct_node,
  		GINT_TO_POINTER(cts.page));
  cts.page++;
    
  /* Column prefs */
  frame = gtk_frame_new("Columns");
  gtk_widget_show(GTK_WIDGET(frame));
  column_pg = column_prefs_show();
  gtk_container_add(GTK_CONTAINER(frame), column_pg);
  gtk_object_set_data(GTK_OBJECT(prefs_w), E_COLUMN_PAGE_KEY, column_pg);
  gtk_notebook_append_page (GTK_NOTEBOOK(prefs_nb), frame, NULL);
  strcpy(label_str, "Columns");
  ct_node = gtk_ctree_insert_node(GTK_CTREE(cts.ctree), NULL, NULL, 
  		&label_ptr, 5, NULL, NULL, NULL, NULL, TRUE, TRUE);
  gtk_ctree_node_set_row_data(GTK_CTREE(cts.ctree), ct_node,
  		GINT_TO_POINTER(cts.page));
  cts.page++;
  
  /* TCP Streams prefs */
  frame = gtk_frame_new("TCP Streams");
  gtk_widget_show(GTK_WIDGET(frame));
  stream_pg = stream_prefs_show();
  gtk_container_add(GTK_CONTAINER(frame), stream_pg);
  gtk_object_set_data(GTK_OBJECT(prefs_w), E_STREAM_PAGE_KEY, stream_pg);
  gtk_notebook_append_page (GTK_NOTEBOOK(prefs_nb), frame, NULL);
  strcpy(label_str, "TCP Streams");
  ct_node = gtk_ctree_insert_node(GTK_CTREE(cts.ctree), NULL, NULL, 
  		&label_ptr, 5, NULL, NULL, NULL, NULL, TRUE, TRUE);
  gtk_ctree_node_set_row_data(GTK_CTREE(cts.ctree), ct_node,
  		GINT_TO_POINTER(cts.page));
  cts.page++;

  /* GUI prefs */
  frame = gtk_frame_new("User Interface");
  gtk_widget_show(GTK_WIDGET(frame));
  gui_pg = gui_prefs_show();
  gtk_container_add(GTK_CONTAINER(frame), gui_pg);
  gtk_object_set_data(GTK_OBJECT(prefs_w), E_GUI_PAGE_KEY, gui_pg);
  gtk_notebook_append_page (GTK_NOTEBOOK(prefs_nb), frame, NULL);
  strcpy(label_str, "User Interface");
  ct_node = gtk_ctree_insert_node(GTK_CTREE(cts.ctree), NULL, NULL, 
  		&label_ptr, 5, NULL, NULL, NULL, NULL, TRUE, TRUE);
  gtk_ctree_node_set_row_data(GTK_CTREE(cts.ctree), ct_node,
  		GINT_TO_POINTER(cts.page));
  cts.page++;

#ifdef HAVE_LIBPCAP
  /* capture prefs */
  frame = gtk_frame_new("Capture");
  gtk_widget_show(GTK_WIDGET(frame));
  capture_pg = capture_prefs_show();
  gtk_container_add(GTK_CONTAINER(frame), capture_pg);
  gtk_object_set_data(GTK_OBJECT(prefs_w), E_CAPTURE_PAGE_KEY, capture_pg);
  gtk_notebook_append_page (GTK_NOTEBOOK(prefs_nb), frame, NULL);
  strcpy(label_str, "Capture");
  ct_node = gtk_ctree_insert_node(GTK_CTREE(cts.ctree), NULL, NULL, 
  		&label_ptr, 5, NULL, NULL, NULL, NULL, TRUE, TRUE);
  gtk_ctree_node_set_row_data(GTK_CTREE(cts.ctree), ct_node,
  		GINT_TO_POINTER(cts.page));
  cts.page++;
#endif

  /* Name resolution prefs */
  frame = gtk_frame_new("Name resolution");
  gtk_widget_show(GTK_WIDGET(frame));
  nameres_pg = nameres_prefs_show();
  gtk_container_add(GTK_CONTAINER(frame), nameres_pg);
  gtk_object_set_data(GTK_OBJECT(prefs_w), E_NAMERES_PAGE_KEY, nameres_pg);
  gtk_notebook_append_page (GTK_NOTEBOOK(prefs_nb), frame, NULL);
  strcpy(label_str, "Name resolution");
  ct_node = gtk_ctree_insert_node(GTK_CTREE(cts.ctree), NULL, NULL, 
  		&label_ptr, 5, NULL, NULL, NULL, NULL, TRUE, TRUE);
  gtk_ctree_node_set_row_data(GTK_CTREE(cts.ctree), ct_node,
  		GINT_TO_POINTER(cts.page));
  cts.page++;

  /* Registered prefs */
  cts.notebook = prefs_nb;
  strcpy(label_str, "Protocols");
  cts.node = gtk_ctree_insert_node(GTK_CTREE(cts.ctree), NULL, NULL,
  		&label_ptr, 5, NULL, NULL, NULL, NULL, FALSE, FALSE);
  gtk_ctree_node_set_row_data(GTK_CTREE(cts.ctree), cts.node,
  		GINT_TO_POINTER(-1));
  gtk_ctree_node_set_selectable(GTK_CTREE(cts.ctree), cts.node, FALSE);

  prefs_module_foreach(module_prefs_show, &cts);


  /* Button row: OK and cancel buttons */
  bbox = gtk_hbutton_box_new();
  gtk_button_box_set_layout (GTK_BUTTON_BOX (bbox), GTK_BUTTONBOX_END);
  gtk_button_box_set_spacing(GTK_BUTTON_BOX(bbox), 5);
  gtk_container_add(GTK_CONTAINER(main_vb), bbox);
  gtk_widget_show(bbox);
  
  ok_bt = gtk_button_new_with_label ("OK");
  gtk_signal_connect(GTK_OBJECT(ok_bt), "clicked",
    GTK_SIGNAL_FUNC(prefs_main_ok_cb), GTK_OBJECT(prefs_w));
  GTK_WIDGET_SET_FLAGS(ok_bt, GTK_CAN_DEFAULT);
  gtk_box_pack_start (GTK_BOX (bbox), ok_bt, TRUE, TRUE, 0);
  gtk_widget_grab_default(ok_bt);
  gtk_widget_show(ok_bt);

  apply_bt = gtk_button_new_with_label ("Apply");
  gtk_signal_connect(GTK_OBJECT(apply_bt), "clicked",
    GTK_SIGNAL_FUNC(prefs_main_apply_cb), GTK_OBJECT(prefs_w));
  GTK_WIDGET_SET_FLAGS(apply_bt, GTK_CAN_DEFAULT);
  gtk_box_pack_start(GTK_BOX (bbox), apply_bt, TRUE, TRUE, 0);
  gtk_widget_show(apply_bt);

  save_bt = gtk_button_new_with_label ("Save");
  gtk_signal_connect(GTK_OBJECT(save_bt), "clicked",
    GTK_SIGNAL_FUNC(prefs_main_save_cb), GTK_OBJECT(prefs_w));
  GTK_WIDGET_SET_FLAGS(save_bt, GTK_CAN_DEFAULT);
  gtk_box_pack_start (GTK_BOX (bbox), save_bt, TRUE, TRUE, 0);
  gtk_widget_show(save_bt);
  
  cancel_bt = gtk_button_new_with_label ("Cancel");
  gtk_signal_connect(GTK_OBJECT(cancel_bt), "clicked",
    GTK_SIGNAL_FUNC(prefs_main_cancel_cb), GTK_OBJECT(prefs_w));
  GTK_WIDGET_SET_FLAGS(cancel_bt, GTK_CAN_DEFAULT);
  gtk_box_pack_start (GTK_BOX (bbox), cancel_bt, TRUE, TRUE, 0);
  gtk_widget_show(cancel_bt);

  /* Catch the "key_press_event" signal in the window, so that we can catch
     the ESC key being pressed and act as if the "Cancel" button had
     been selected. */
  dlg_set_cancel(prefs_w, cancel_bt);

  gtk_widget_show(prefs_w);
}

static void
set_option_label(GtkWidget *main_tb, int table_position,
    const gchar *label_text, const gchar *tooltip_text, GtkTooltips *tooltips)
{
	GtkWidget *label;
	GtkWidget *event_box;

	label = gtk_label_new(label_text);
	gtk_misc_set_alignment(GTK_MISC(label), 1.0, 0.5);
	gtk_widget_show(label);

	event_box = gtk_event_box_new();
	gtk_table_attach_defaults(GTK_TABLE(main_tb), event_box, 0, 1,
	    table_position, table_position + 1);
	if (tooltip_text != NULL && tooltips != NULL)
		gtk_tooltips_set_tip(tooltips, event_box, tooltip_text, NULL);
	gtk_container_add(GTK_CONTAINER(event_box), label);
	gtk_widget_show(event_box);
}

GtkWidget *
create_preference_check_button(GtkWidget *main_tb, int table_position,
    const gchar *label_text, const gchar *tooltip_text, gboolean active)
{
	GtkTooltips *tooltips;
	GtkWidget *check_box;

	tooltips = gtk_object_get_data(GTK_OBJECT(main_tb), E_TOOLTIPS_KEY);

	set_option_label(main_tb, table_position, label_text, tooltip_text,
	    tooltips);

	check_box = gtk_check_button_new();
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(check_box), active);
	gtk_table_attach_defaults(GTK_TABLE(main_tb), check_box, 1, 2,
	    table_position, table_position + 1);
	if (tooltip_text != NULL && tooltips != NULL)
		gtk_tooltips_set_tip(tooltips, check_box, tooltip_text, NULL);

	return check_box;
}

GtkWidget *
create_preference_radio_buttons(GtkWidget *main_tb, int table_position,
    const gchar *label_text, const gchar *tooltip_text,
    const enum_val_t *enumvals, gint current_val)
{
	GtkTooltips *tooltips;
	GtkWidget *radio_button_hbox, *button = NULL;
	GSList *rb_group;
	int index;
	const enum_val_t *enum_valp;
	GtkWidget *event_box;

	tooltips = gtk_object_get_data(GTK_OBJECT(main_tb), E_TOOLTIPS_KEY);

	set_option_label(main_tb, table_position, label_text, tooltip_text,
	    tooltips);

	radio_button_hbox = gtk_hbox_new(FALSE, 0);
	rb_group = NULL;
	for (enum_valp = enumvals, index = 0; enum_valp->name != NULL;
	    enum_valp++, index++) {
		button = gtk_radio_button_new_with_label(rb_group,
		    enum_valp->name);
		gtk_widget_show(button);
		if (rb_group == NULL)
			rb_group = gtk_radio_button_group(GTK_RADIO_BUTTON(button));
		gtk_box_pack_start(GTK_BOX(radio_button_hbox), button, FALSE,
		    FALSE, 10);
		if (enum_valp->value == current_val) {
			gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(button),
			    TRUE);
		}
	}
	gtk_widget_show(radio_button_hbox);

	event_box = gtk_event_box_new();
	gtk_container_add(GTK_CONTAINER(event_box), radio_button_hbox);
	gtk_table_attach_defaults(GTK_TABLE(main_tb), event_box, 1, 2,
	    table_position, table_position+1);
	if (tooltip_text != NULL && tooltips != NULL)
		gtk_tooltips_set_tip(tooltips, event_box, tooltip_text, NULL);
	gtk_widget_show(event_box);

	/*
	 * It doesn't matter which of the buttons we return - we fetch
	 * the value by looking at the entire radio button group to
	 * which it belongs, and we can get that from any button.
	 */
	return button;
}

static gint
label_to_enum_val(GtkWidget *label, const enum_val_t *enumvals)
{
	char *label_string;
	gint enumval;

	/* Get the label's text, and translate it to a value. */
	gtk_label_get(GTK_LABEL(label), &label_string);
	enumval = find_val_for_string(label_string, enumvals, 1);

	return enumval;
}

gint
fetch_preference_radio_buttons_val(GtkWidget *button,
    const enum_val_t *enumvals)
{
	GSList *rb_group;
	GSList *rb_entry;

	/*
	 * Go through the list of of radio buttons in the button's group,
	 * and find the first one that's active.
	 */
	rb_group = gtk_radio_button_group(GTK_RADIO_BUTTON(button));
	button = NULL;
	for (rb_entry = rb_group; rb_entry != NULL;
	    rb_entry = g_slist_next(rb_entry)) {
		button = rb_entry->data;
		if (GTK_TOGGLE_BUTTON(button)->active)
			break;
	}

	/* OK, now return the value corresponding to that button's label. */
	return label_to_enum_val(GTK_BIN(button)->child, enumvals);
}

GtkWidget *
create_preference_option_menu(GtkWidget *main_tb, int table_position,
    const gchar *label_text, const gchar *tooltip_text,
    const enum_val_t *enumvals, gint current_val)
{
	GtkTooltips *tooltips;
	GtkWidget *label, *menu_box, *menu, *menu_item, *option_menu;
	int menu_index, index;
	const enum_val_t *enum_valp;
	GtkWidget *event_box;

	tooltips = gtk_object_get_data(GTK_OBJECT(main_tb), E_TOOLTIPS_KEY);

	set_option_label(main_tb, table_position, label_text, tooltip_text,
	    tooltips);

	/* Create a menu from the enumvals */
	menu = gtk_menu_new();
	if (tooltip_text != NULL && tooltips != NULL)
		gtk_tooltips_set_tip(tooltips, menu, tooltip_text, NULL);
	menu_index = -1;
	for (enum_valp = enumvals, index = 0; enum_valp->name != NULL;
	    enum_valp++, index++) {
		menu_item = gtk_menu_item_new_with_label(enum_valp->name);
		gtk_menu_append(GTK_MENU(menu), menu_item);
		if (enum_valp->value == current_val)
			menu_index = index;
		gtk_widget_show(menu_item);
	}

	/* Create the option menu from the menu */
	option_menu = gtk_option_menu_new();
	gtk_option_menu_set_menu(GTK_OPTION_MENU(option_menu), menu);

	/* Set its current value to the variable's current value */
	if (menu_index != -1)
		gtk_option_menu_set_history(GTK_OPTION_MENU(option_menu),
		    menu_index);

	/*
	 * Put the option menu in an hbox, so that it's only as wide
	 * as the widest entry, rather than being as wide as the table
	 * space.
	 */
	menu_box = gtk_hbox_new(FALSE, 0);
	gtk_box_pack_start(GTK_BOX(menu_box), option_menu, FALSE, FALSE, 0);

	event_box = gtk_event_box_new();
	gtk_table_attach_defaults(GTK_TABLE(main_tb), event_box,
	    1, 2, table_position, table_position + 1);
	if (tooltip_text != NULL && tooltips != NULL)
		gtk_tooltips_set_tip(tooltips, event_box, tooltip_text, NULL);
	gtk_container_add(GTK_CONTAINER(event_box), menu_box);

	return option_menu;
}

gint
fetch_preference_option_menu_val(GtkWidget *optmenu, const enum_val_t *enumvals)
{
	/*
	 * OK, now return the value corresponding to the label for the
	 * currently active entry in the option menu.
	 *
	 * Yes, this is how you get the label for that entry.  See FAQ
	 * 6.8 in the GTK+ FAQ.
	 */
	return label_to_enum_val(GTK_BIN(optmenu)->child, enumvals);
}

GtkWidget *
create_preference_entry(GtkWidget *main_tb, int table_position,
    const gchar *label_text, const gchar *tooltip_text, char *value)
{
	GtkTooltips *tooltips;
	GtkWidget *entry;

	tooltips = gtk_object_get_data(GTK_OBJECT(main_tb), E_TOOLTIPS_KEY);

	set_option_label(main_tb, table_position, label_text, tooltip_text,
	    tooltips);

	entry = gtk_entry_new();
	if (value != NULL)
		gtk_entry_set_text(GTK_ENTRY(entry), value);
	gtk_table_attach_defaults(GTK_TABLE(main_tb), entry, 1, 2,
	    table_position, table_position + 1);
	if (tooltip_text != NULL && tooltips != NULL)
		gtk_tooltips_set_tip(tooltips, entry, tooltip_text, NULL);
	gtk_widget_show(entry);

	return entry;
}

static void
pref_fetch(pref_t *pref, gpointer user_data)
{
  GtkWidget *label;
  char *label_string;
  char *str_val;
  char *p;
  guint uval;
  gboolean bval;
  GSList *rb_entry;
  GtkWidget *button;
  gint enumval;
  gboolean *pref_changed_p = user_data;

  /* Fetch the value of the preference, and set the appropriate variable
     to it. */
  switch (pref->type) {

  case PREF_UINT:
    str_val = gtk_entry_get_text(GTK_ENTRY(pref->control));
    uval = strtoul(str_val, &p, pref->info.base);
#if 0
    if (p == value || *p != '\0')
      return PREFS_SET_SYNTAX_ERR;	/* number was bad */
#endif
    if (*pref->varp.uint != uval) {
      *pref_changed_p = TRUE;
      *pref->varp.uint = uval;
    }
    break;

  case PREF_BOOL:
    bval = GTK_TOGGLE_BUTTON(pref->control)->active;
    if (*pref->varp.bool != bval) {
      *pref_changed_p = TRUE;
      *pref->varp.bool = bval;
    }
    break;

  case PREF_ENUM:
    if (pref->info.enum_info.radio_buttons) {
      enumval = fetch_preference_radio_buttons_val(pref->control,
          pref->info.enum_info.enumvals);
    } else {
      enumval = fetch_preference_option_menu_val(pref->control,
          pref->info.enum_info.enumvals);
    }

    if (*pref->varp.enump != enumval) {
      *pref_changed_p = TRUE;
      *pref->varp.enump = enumval;
    }
    break;

  case PREF_STRING:
    str_val = gtk_entry_get_text(GTK_ENTRY(pref->control));
    if (*pref->varp.string == NULL || strcmp(*pref->varp.string, str_val) != 0) {
      *pref_changed_p = TRUE;
      if (*pref->varp.string != NULL)
        g_free(*pref->varp.string);
      *pref->varp.string = g_strdup(str_val);
    }
    break;

  case PREF_OBSOLETE:
    g_assert_not_reached();
    break;
  }
}

static void
module_prefs_fetch(module_t *module, gpointer user_data)
{
  gboolean *must_redissect_p = user_data;

  /* For all preferences in this module, fetch its value from this
     module's notebook page.  Find out whether any of them changed. */
  module->prefs_changed = FALSE;	/* assume none of them changed */
  prefs_pref_foreach(module, pref_fetch, &module->prefs_changed);

  /* If any of them changed, indicate that we must redissect and refilter
     the current capture (if we have one), as the preference change
     could cause packets to be dissected differently. */
  if (module->prefs_changed)
    *must_redissect_p = TRUE;
}

static void
pref_clean(pref_t *pref, gpointer user_data)
{
  switch (pref->type) {

  case PREF_UINT:
    break;

  case PREF_BOOL:
    break;

  case PREF_ENUM:
    break;

  case PREF_STRING:
    if (pref->saved_val.string != NULL) {
      g_free(pref->saved_val.string);
      pref->saved_val.string = NULL;
    }
    break;

  case PREF_OBSOLETE:
    g_assert_not_reached();
    break;
  }
}

static void
module_prefs_clean(module_t *module, gpointer user_data)
{
  /* For all preferences in this module, clean up any cruft allocated for
     use by the GUI code. */
  prefs_pref_foreach(module, pref_clean, NULL);
}

static void
prefs_main_ok_cb(GtkWidget *ok_bt, gpointer parent_w)
{
  gboolean must_redissect = FALSE;

  /* Fetch the preferences (i.e., make sure all the values set in all of
     the preferences panes have been copied to "prefs" and the registered
     preferences). */
  printer_prefs_fetch(gtk_object_get_data(GTK_OBJECT(parent_w), E_PRINT_PAGE_KEY));
  column_prefs_fetch(gtk_object_get_data(GTK_OBJECT(parent_w), E_COLUMN_PAGE_KEY));
  stream_prefs_fetch(gtk_object_get_data(GTK_OBJECT(parent_w), E_STREAM_PAGE_KEY));
  gui_prefs_fetch(gtk_object_get_data(GTK_OBJECT(parent_w), E_GUI_PAGE_KEY));
  capture_prefs_fetch(gtk_object_get_data(GTK_OBJECT(parent_w), E_CAPTURE_PAGE_KEY));
  nameres_prefs_fetch(gtk_object_get_data(GTK_OBJECT(parent_w), E_NAMERES_PAGE_KEY));
  prefs_module_foreach(module_prefs_fetch, &must_redissect);

  /* Now apply those preferences. */
  printer_prefs_apply(gtk_object_get_data(GTK_OBJECT(parent_w), E_PRINT_PAGE_KEY));
  column_prefs_apply(gtk_object_get_data(GTK_OBJECT(parent_w), E_COLUMN_PAGE_KEY));
  stream_prefs_apply(gtk_object_get_data(GTK_OBJECT(parent_w), E_STREAM_PAGE_KEY));
  gui_prefs_apply(gtk_object_get_data(GTK_OBJECT(parent_w), E_GUI_PAGE_KEY));
  capture_prefs_apply(gtk_object_get_data(GTK_OBJECT(parent_w), E_CAPTURE_PAGE_KEY));
  nameres_prefs_apply(gtk_object_get_data(GTK_OBJECT(parent_w), E_NAMERES_PAGE_KEY));
  prefs_apply_all();

  /* Now destroy the "Preferences" dialog. */
  gtk_widget_destroy(GTK_WIDGET(parent_w));

  if (must_redissect) {
    /* Redissect all the packets, and re-evaluate the display filter. */
    redissect_packets(&cfile);
  }
}

static void
prefs_main_apply_cb(GtkWidget *apply_bt, gpointer parent_w)
{
  gboolean must_redissect = FALSE;

  /* Fetch the preferences (i.e., make sure all the values set in all of
     the preferences panes have been copied to "prefs" and the registered
     preferences). */
  printer_prefs_fetch(gtk_object_get_data(GTK_OBJECT(parent_w), E_PRINT_PAGE_KEY));
  column_prefs_fetch(gtk_object_get_data(GTK_OBJECT(parent_w), E_COLUMN_PAGE_KEY));
  stream_prefs_fetch(gtk_object_get_data(GTK_OBJECT(parent_w), E_STREAM_PAGE_KEY));
  gui_prefs_fetch(gtk_object_get_data(GTK_OBJECT(parent_w), E_GUI_PAGE_KEY));
  capture_prefs_fetch(gtk_object_get_data(GTK_OBJECT(parent_w), E_CAPTURE_PAGE_KEY));
  nameres_prefs_fetch(gtk_object_get_data(GTK_OBJECT(parent_w), E_NAMERES_PAGE_KEY));
  prefs_module_foreach(module_prefs_fetch, &must_redissect);

  /* Now apply those preferences. */
  printer_prefs_apply(gtk_object_get_data(GTK_OBJECT(parent_w), E_PRINT_PAGE_KEY));
  column_prefs_apply(gtk_object_get_data(GTK_OBJECT(parent_w), E_COLUMN_PAGE_KEY));
  stream_prefs_apply(gtk_object_get_data(GTK_OBJECT(parent_w), E_STREAM_PAGE_KEY));
  gui_prefs_apply(gtk_object_get_data(GTK_OBJECT(parent_w), E_GUI_PAGE_KEY));
  capture_prefs_apply(gtk_object_get_data(GTK_OBJECT(parent_w), E_CAPTURE_PAGE_KEY));
  nameres_prefs_apply(gtk_object_get_data(GTK_OBJECT(parent_w), E_NAMERES_PAGE_KEY));
  prefs_apply_all();

  if (must_redissect) {
    /* Redissect all the packets, and re-evaluate the display filter. */
    redissect_packets(&cfile);
  }
}

static void
prefs_main_save_cb(GtkWidget *save_bt, gpointer parent_w)
{
  gboolean must_redissect = FALSE;
  int err;
  char *pf_dir_path;
  const char *pf_path;

  /* Fetch the preferences (i.e., make sure all the values set in all of
     the preferences panes have been copied to "prefs" and the registered
     preferences). */
  printer_prefs_fetch(gtk_object_get_data(GTK_OBJECT(parent_w), E_PRINT_PAGE_KEY));
  column_prefs_fetch(gtk_object_get_data(GTK_OBJECT(parent_w), E_COLUMN_PAGE_KEY));
  stream_prefs_fetch(gtk_object_get_data(GTK_OBJECT(parent_w), E_STREAM_PAGE_KEY));
  gui_prefs_fetch(gtk_object_get_data(GTK_OBJECT(parent_w), E_GUI_PAGE_KEY));
  capture_prefs_fetch(gtk_object_get_data(GTK_OBJECT(parent_w), E_CAPTURE_PAGE_KEY));
  nameres_prefs_fetch(gtk_object_get_data(GTK_OBJECT(parent_w), E_NAMERES_PAGE_KEY));
  prefs_module_foreach(module_prefs_fetch, &must_redissect);

  /* Create the directory that holds personal configuration files, if
     necessary.  */
  if (create_persconffile_dir(&pf_dir_path) == -1) {
     simple_dialog(ESD_TYPE_WARN, NULL,
      "Can't create directory\n\"%s\"\nfor preferences file: %s.", pf_dir_path,
      strerror(errno));
     g_free(pf_dir_path);
  } else {
    /* Write the preferencs out. */
    err = write_prefs(&pf_path);
    if (err != 0) {
       simple_dialog(ESD_TYPE_WARN, NULL,
        "Can't open preferences file\n\"%s\": %s.", pf_path,
        strerror(err));
    }
  }

  /* Now apply those preferences.
     XXX - should we do this?  The user didn't click "OK" or "Apply".
     However:

	1) by saving the preferences they presumably indicate that they
	   like them;

	2) the next time they fire Ethereal up, those preferences will
	   apply;

	3) we'd have to buffer "must_redissect" so that if they do
	   "Apply" after this, we know we have to redissect;

	4) we did apply the protocol preferences, at least, in the past. */
  printer_prefs_apply(gtk_object_get_data(GTK_OBJECT(parent_w), E_PRINT_PAGE_KEY));
  column_prefs_apply(gtk_object_get_data(GTK_OBJECT(parent_w), E_COLUMN_PAGE_KEY));
  stream_prefs_apply(gtk_object_get_data(GTK_OBJECT(parent_w), E_STREAM_PAGE_KEY));
  gui_prefs_apply(gtk_object_get_data(GTK_OBJECT(parent_w), E_GUI_PAGE_KEY));
  capture_prefs_apply(gtk_object_get_data(GTK_OBJECT(parent_w), E_CAPTURE_PAGE_KEY));
  nameres_prefs_apply(gtk_object_get_data(GTK_OBJECT(parent_w), E_NAMERES_PAGE_KEY));
  prefs_apply_all();

  if (must_redissect) {
    /* Redissect all the packets, and re-evaluate the display filter. */
    redissect_packets(&cfile);
  }
}

static void
pref_revert(pref_t *pref, gpointer user_data)
{
  gboolean *pref_changed_p = user_data;

  /* Revert the preference to its saved value. */
  switch (pref->type) {

  case PREF_UINT:
    if (*pref->varp.uint != pref->saved_val.uint) {
      *pref_changed_p = TRUE;
      *pref->varp.uint = pref->saved_val.uint;
    }
    break;

  case PREF_BOOL:
    if (*pref->varp.bool != pref->saved_val.bool) {
      *pref_changed_p = TRUE;
      *pref->varp.bool = pref->saved_val.bool;
    }
    break;

  case PREF_ENUM:
    if (*pref->varp.enump != pref->saved_val.enumval) {
      *pref_changed_p = TRUE;
      *pref->varp.enump = pref->saved_val.enumval;
    }
    break;

  case PREF_STRING:
    if (*pref->varp.string != pref->saved_val.string &&
	(*pref->varp.string == NULL ||
	 pref->saved_val.string == NULL ||
	 strcmp(*pref->varp.string, pref->saved_val.string) != 0)) {
      *pref_changed_p = TRUE;
      if (*pref->varp.string != NULL)
        g_free(*pref->varp.string);
      *pref->varp.string = g_strdup(pref->saved_val.string);
    }
    break;

  case PREF_OBSOLETE:
    g_assert_not_reached();
    break;
  }
}

static void
module_prefs_revert(module_t *module, gpointer user_data)
{
  gboolean *must_redissect_p = user_data;

  /* For all preferences in this module, revert its value to the value
     it had when we popped up the Preferences dialog.  Find out whether
     this changes any of them. */
  module->prefs_changed = FALSE;	/* assume none of them changed */
  prefs_pref_foreach(module, pref_revert, &module->prefs_changed);

  /* If any of them changed, indicate that we must redissect and refilter
     the current capture (if we have one), as the preference change
     could cause packets to be dissected differently. */
  if (module->prefs_changed)
    *must_redissect_p = TRUE;
}

static void
prefs_main_cancel_cb(GtkWidget *cancel_bt, gpointer parent_w)
{
  gboolean must_redissect = FALSE;

  /* Free up the current preferences and copy the saved preferences to the
     current preferences. */
  free_prefs(&prefs);
  copy_prefs(&prefs, &saved_prefs);

  /* Now revert the registered preferences. */
  prefs_module_foreach(module_prefs_revert, &must_redissect);

  /* Now apply the reverted-to preferences. */
  printer_prefs_apply(gtk_object_get_data(GTK_OBJECT(parent_w), E_PRINT_PAGE_KEY));
  column_prefs_apply(gtk_object_get_data(GTK_OBJECT(parent_w), E_COLUMN_PAGE_KEY));
  stream_prefs_apply(gtk_object_get_data(GTK_OBJECT(parent_w), E_STREAM_PAGE_KEY));
  gui_prefs_apply(gtk_object_get_data(GTK_OBJECT(parent_w), E_GUI_PAGE_KEY));
  nameres_prefs_apply(gtk_object_get_data(GTK_OBJECT(parent_w), E_NAMERES_PAGE_KEY));
  prefs_apply_all();

  gtk_widget_destroy(GTK_WIDGET(parent_w));

  if (must_redissect) {
    /* Redissect all the packets, and re-evaluate the display filter. */
    redissect_packets(&cfile);
  }
}

/* Treat this as a cancel, by calling "prefs_main_cancel_cb()".
   XXX - that'll destroy the Preferences dialog; will that upset
   a higher-level handler that says "OK, we've been asked to delete
   this, so destroy it"? */
static gboolean
prefs_main_delete_cb(GtkWidget *prefs_w, gpointer dummy)
{
  prefs_main_cancel_cb(NULL, prefs_w);
  return FALSE;
}

static void
prefs_main_destroy_cb(GtkWidget *win, gpointer user_data)
{
  /* Let the preference tabs clean up anything they've done. */
  printer_prefs_destroy(gtk_object_get_data(GTK_OBJECT(prefs_w), E_PRINT_PAGE_KEY));
  column_prefs_destroy(gtk_object_get_data(GTK_OBJECT(prefs_w), E_COLUMN_PAGE_KEY));
  stream_prefs_destroy(gtk_object_get_data(GTK_OBJECT(prefs_w), E_STREAM_PAGE_KEY));
  gui_prefs_destroy(gtk_object_get_data(GTK_OBJECT(prefs_w), E_GUI_PAGE_KEY));
  capture_prefs_destroy(gtk_object_get_data(GTK_OBJECT(prefs_w), E_CAPTURE_PAGE_KEY));
  nameres_prefs_destroy(gtk_object_get_data(GTK_OBJECT(prefs_w), E_NAMERES_PAGE_KEY));

  /* Free up the saved preferences (both for "prefs" and for registered
     preferences). */
  free_prefs(&saved_prefs);
  prefs_module_foreach(module_prefs_clean, NULL);

  /* Note that we no longer have a "Preferences" dialog box. */
  prefs_w = NULL;
}

struct properties_data {
  GtkWidget *w;
  int page_num;
  char *title;
};

/* XXX this way of searching the correct page number is really ugly ... */
static void
module_search_properties(module_t *module, gpointer user_data)
{
  struct properties_data *p = (struct properties_data *)user_data;

  if (p->title == NULL) return;
  if (strcmp(module->title, p->title) == 0) {
    /* found it */
    gtk_notebook_set_page(GTK_NOTEBOOK(p->w), p->page_num);
    p->title = NULL;
  } else {
    p->page_num++;
  }
}

void
properties_cb(GtkWidget *w, gpointer dummy) 
{
  gchar *title = NULL;
  struct properties_data p;

  if (finfo_selected) {
    header_field_info *hfinfo = finfo_selected->hfinfo;
    if (hfinfo->parent == -1) {
      title = (gchar *)prefs_get_title_by_name(hfinfo->abbrev);
    } else {
      title = (gchar *)
	prefs_get_title_by_name(proto_registrar_get_abbrev(hfinfo->parent));
    }
  } else {
    return;
  }
  
  if (!title) return;
  
  if (prefs_w != NULL) {
    reactivate_window(prefs_w);
  } else {
    prefs_cb(w, dummy);
  }

  p.w = notebook;
  p.page_num = FIRST_PROTO_PREFS_PAGE;
  p.title = title;

  prefs_module_foreach(module_search_properties, &p);

}

/* Prefs tree selection callback.  The node data has been loaded with 
   the proper notebook page to load. */
static void
prefs_tree_select_cb(GtkCTree *ct, GtkCTreeNode *node, gint col, gpointer dummy)
{
  gint page = GPOINTER_TO_INT(gtk_ctree_node_get_row_data(ct, node));
  
  if (page >= 0) 
    gtk_notebook_set_page(GTK_NOTEBOOK(notebook), page);
}
