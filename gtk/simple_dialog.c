/* simple_dialog.c
 * Simple message dialog box routines.
 *
 * $Id: simple_dialog.c,v 1.8 2001/12/12 21:38:59 gerald Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
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
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <gtk/gtk.h>

#include <stdarg.h>
#include <stdio.h>

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include "gtkglobals.h"
#include "simple_dialog.h"
#include "dlg_utils.h"

#include "image/eexcl3d64.xpm"
#include "image/eicon3d64.xpm"

static void simple_dialog_cancel_cb(GtkWidget *, gpointer);

static const gchar bm_key[] = "button mask";

/* Simple dialog function - Displays a dialog box with the supplied message
 * text.
 * 
 * Args:
 * type       : One of ESD_TYPE_*.
 * btn_mask   : The address of a gint.  The value passed in determines if
 *              the 'Cancel' button is displayed.  The button pressed by the 
 *              user is passed back.
 * msg_format : Sprintf-style format of the text displayed in the dialog.
 * ...        : Argument list for msg_format
 *
 */
 
#define ESD_MAX_MSG_LEN 2048
void
simple_dialog(gint type, gint *btn_mask, gchar *msg_format, ...) {
  GtkWidget   *win, *main_vb, *top_hb, *type_pm, *msg_label,
              *bbox, *ok_btn, *cancel_btn;
  GdkPixmap   *pixmap;
  GdkBitmap   *mask;
  GtkStyle    *style;
  GdkColormap *cmap;
  va_list      ap;
  gchar        message[ESD_MAX_MSG_LEN];
  gchar      **icon;

  /* Main window */
  switch (type & ~ESD_TYPE_MODAL) {
  case ESD_TYPE_WARN :
    icon = eexcl3d64_xpm;
    win = dlg_window_new("Ethereal: Warning");
    break;
  case ESD_TYPE_CRIT :
    icon = eexcl3d64_xpm;
    win = dlg_window_new("Ethereal: Error");
    break;
  case ESD_TYPE_INFO :
  default :
    icon = eicon3d64_xpm;
    win = dlg_window_new("Ethereal: Information");
    break;
  }

  if (type & ESD_TYPE_MODAL)
    gtk_window_set_modal(GTK_WINDOW(win), TRUE);

  gtk_container_border_width(GTK_CONTAINER(win), 7);

  gtk_object_set_data(GTK_OBJECT(win), bm_key, btn_mask);

  /* Container for our rows */
  main_vb = gtk_vbox_new(FALSE, 5);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_container_add(GTK_CONTAINER(win), main_vb);
  gtk_widget_show(main_vb);

  /* Top row: Icon and message text */
  top_hb = gtk_hbox_new(FALSE, 10);
  gtk_container_add(GTK_CONTAINER(main_vb), top_hb);
  gtk_widget_show(top_hb);
  
  style = gtk_widget_get_style(win);
  cmap  = gdk_colormap_get_system();
  pixmap = gdk_pixmap_colormap_create_from_xpm_d(NULL, cmap,  &mask,
    &style->bg[GTK_STATE_NORMAL], icon);
  type_pm = gtk_pixmap_new(pixmap, mask);
  gtk_misc_set_alignment (GTK_MISC (type_pm), 0.5, 0.0);
  gtk_container_add(GTK_CONTAINER(top_hb), type_pm);
  gtk_widget_show(type_pm);

  /* Load our vararg list into the message string */
  va_start(ap, msg_format);
  vsnprintf(message, ESD_MAX_MSG_LEN, msg_format, ap);

  msg_label = gtk_label_new(message);
  gtk_label_set_justify(GTK_LABEL(msg_label), GTK_JUSTIFY_FILL);
  gtk_container_add(GTK_CONTAINER(top_hb), msg_label);
  gtk_widget_show(msg_label);
  
  /* Button row */
  bbox = gtk_hbutton_box_new();
  gtk_button_box_set_layout (GTK_BUTTON_BOX (bbox), GTK_BUTTONBOX_END);
  gtk_container_add(GTK_CONTAINER(main_vb), bbox);
  gtk_widget_show(bbox);

  ok_btn = gtk_button_new_with_label ("OK");
  gtk_signal_connect_object(GTK_OBJECT(ok_btn), "clicked",
    GTK_SIGNAL_FUNC(gtk_widget_destroy), GTK_OBJECT (win)); 
  gtk_container_add(GTK_CONTAINER(bbox), ok_btn);
  GTK_WIDGET_SET_FLAGS(ok_btn, GTK_CAN_DEFAULT);
  gtk_widget_grab_default(ok_btn);
  gtk_widget_show(ok_btn);

  if (btn_mask && *btn_mask == ESD_BTN_CANCEL) {
    cancel_btn = gtk_button_new_with_label("Cancel");
    gtk_signal_connect(GTK_OBJECT(cancel_btn), "clicked",
      GTK_SIGNAL_FUNC(simple_dialog_cancel_cb), (gpointer) win);
    gtk_container_add(GTK_CONTAINER(bbox), cancel_btn);
    GTK_WIDGET_SET_FLAGS(cancel_btn, GTK_CAN_DEFAULT);
    gtk_widget_show(cancel_btn);

    /* Catch the "key_press_event" signal in the window, so that we can catch
       the ESC key being pressed and act as if the "Cancel" button had
       been selected. */
    dlg_set_cancel(win, cancel_btn);
  } else {
    /* Catch the "key_press_event" signal in the window, so that we can catch
       the ESC key being pressed and act as if the "OK" button had
       been selected. */
    dlg_set_cancel(win, ok_btn);
  }

  if (btn_mask)
    *btn_mask = ESD_BTN_OK;

  gtk_widget_show(win);
}

static void
simple_dialog_cancel_cb(GtkWidget *w, gpointer win) {
  gint *btn_mask = (gint *) gtk_object_get_data(win, bm_key);
  
  if (btn_mask)
    *btn_mask = ESD_BTN_CANCEL;
  gtk_widget_destroy(GTK_WIDGET(win));
}
