/* tcp_graph.c
 * TCP graph drawing code
 * By Pavel Mores <pvl@uh.cz>
 * Win32 port:  rwh@unifiedtech.com
 *
 * $Id: tcp_graph.c,v 1.14 2002/01/30 23:08:27 guy Exp $
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

#include <gtk/gtk.h>
#include <gdk/gdkkeysyms.h>
#include <stdio.h>
#include <string.h>
#include <math.h>		/* rint() */

#include <sys/types.h>		/* freebsd requires this */

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#ifndef WIN32
# include <netinet/in.h>	/* ntohs(), IPPROTO_TCP */
# include <arpa/inet.h>		/* inet_ntoa() */
#else /* WIN32 */
# include <stdlib.h>
#endif /* WIN32 */

#include "globals.h" 		/* cfile */
#include <epan/packet.h>		/* frame_data */
#include "gtkglobals.h"		/* packet_list */
#include "simple_dialog.h"
#include "ui_util.h"
#include "tcp_graph.h"

/* from <net/ethernet.h> */
struct ether_header {
	guint8 ether_dhost[6];	/* destination eth addr */
	guint8 ether_shost[6];	/* source ether addr */
	guint16 ether_type;	/* packet type ID field */
};
#define ETHERTYPE_IP	0x0800


/* reverse engineered from capture file, not too difficult :) */
struct ppp_header {
	guint8 ppp_type;	/* Protocol on PPP connection */
};
#define PPPTYPE_IP 0x21


/* from <netinet/ip.h> */
struct iphdr {
	guint8 version_ihl;
	guint8 tos;
	guint16 tot_len;
	guint16 id;
	guint16 frag_off;
	guint8 ttl;
	guint8 protocol;
	guint16 check;
	guint32 saddr;
	guint32 daddr;
};

#define IPHDR_IHL_SHIFT		0
#define IPHDR_IHL_MASK		(0xf << IPHDR_IHL_SHIFT)
#define IHL(iphdrptr)		( ((iphdrptr)->version_ihl & IPHDR_IHL_MASK) >> IPHDR_IHL_SHIFT )

/* from <netinet/tcp.h> */
struct tcphdr {
	guint16 source;
	guint16 dest;
	guint32 seq;
	guint32 ack_seq;
	guint16 flags;
#define TH_FIN    0x01
#define TH_SYN    0x02
#define TH_RST    0x04
#define TH_PUSH   0x08
#define TH_ACK    0x10
#define TH_URG    0x20
	guint16 window;
	guint16 check;
	guint16 urg_ptr;
};

#define TCP_SYN(tcphdr)		( ntohs ((tcphdr).flags) & TH_SYN )
#define TCP_ACK(tcphdr)		( ntohs ((tcphdr).flags) & TH_ACK )
#define TCP_DOFF_SHIFT		12
#define TCP_DOFF_MASK		(0xf << TCP_DOFF_SHIFT)
#define DOFF(tcphdr)		( ( ntohs ((tcphdr).flags) & TCP_DOFF_MASK) >> TCP_DOFF_SHIFT )

#define TXT_WIDTH	850
#define TXT_HEIGHT	550

/* for compare_headers() */
/* segment went the same direction as the currently selected one */
#define COMPARE_CURR_DIR	0
#define COMPARE_ANY_DIR		1

/* initalize_axis() */
#define AXIS_HORIZONTAL		0
#define AXIS_VERTICAL		1

struct segment {
	struct segment *next;
	guint32 num;
	guint32 rel_secs;
	guint32 rel_usecs;
	guint32 abs_secs;
	guint32 abs_usecs;
	struct iphdr iphdr;
	struct tcphdr tcphdr;
	int data;				/* amount of data in this segment */
};

struct rect {
	double x, y, width, height;
};

struct line {
	double x1, y1, x2, y2;
};

struct irect {
	int x, y, width, height;
};

struct ipoint {
	int x, y;
};

typedef enum {
	ELMT_NONE=0,
	ELMT_RECT=1,
	ELMT_LINE=2,
	ELMT_ARC=3
} ElementType;

struct rect_params {
	struct rect dim;
	gint filled;
};

struct line_params {
	struct line dim;
};

struct arc_params {
	struct rect dim;
	gint filled;
	gint angle1, angle2;
};

struct element {
	ElementType type;
	GdkGC *gc;
	struct segment *parent;
	union {
		struct arc_params arc;
		struct rect_params rect;
		struct line_params line;
	} p;
};

struct element_list {
	struct element_list *next;
	struct element *elements;
};

struct axis {
	struct graph *g;			/* which graph we belong to */
	GtkWidget *drawing_area;
	GdkPixmap *pixmap[2];
	int displayed;
#define AXIS_ORIENTATION	1 << 0
	int flags;
	/* dim and orig (relative to origin of window) of axis' pixmap */
	struct irect p;
	/* dim and orig (relative to origin of axis' pixmap) of scale itself */
	struct irect s;
	gdouble min, max;
	gdouble major, minor;		/* major and minor ticks */
	char **label;
};

#define HAXIS_INIT_HEIGHT	70
#define VAXIS_INIT_WIDTH	100
#define TITLEBAR_HEIGHT		50
#define RMARGIN_WIDTH	30

struct style_tseq_tcptrace {
	GdkGC *gc_seq;
	GdkGC *gc_ack[2];
	int flags;
};

struct style_tseq_stevens {
	int seq_width;
	int seq_height;
	int flags;
};

struct style_tput {
	int width, height;
	int nsegs;
	int flags;
};

struct style_rtt {
	int width, height;
	int flags;
};

/* style flags */
#define SEQ_ORIGIN			0x1
/* show absolute sequence numbers (not differences from isn) */
#define SEQ_ORIGIN_ZERO		0x1
#define SEQ_ORIGIN_ISN		0x0
#define TIME_ORIGIN			0x10
/* show time from beginning of capture as opposed to time from beginning
 * of the connection */
#define TIME_ORIGIN_CAP		0x10
#define TIME_ORIGIN_CONN	0x0

/* this is used by rtt module only */
struct unack {
	struct unack *next;
	double time;
	unsigned int seqno;
};

struct cross {
	int x, y;
	int draw;			/* indicates whether we should draw cross at all */
	int erase_needed;
	GtkToggleButton *on_toggle;
	GtkToggleButton *off_toggle;
};

struct bounds {
	double x0, y0, width, height;
};

struct zoom {
	double x, y;
};

struct zooms {
	double x, y;
	double step_x, step_y;
	struct zoom initial;
#define ZOOM_OUT				(1 << 0)
#define ZOOM_HLOCK				(1 << 1)
#define ZOOM_VLOCK				(1 << 2)
#define ZOOM_STEPS_SAME			(1 << 3)
#define ZOOM_STEPS_KEEP_RATIO	(1 << 4)
	int flags;
	/* unfortunately, we need them both because gtk_toggle_button_set_active ()
	 * with second argument FALSE doesn't do anything, somehow */
	struct {
		GtkToggleButton *in_toggle;
		GtkToggleButton *out_toggle;
		GtkEntry *h_zoom;
		GtkEntry *v_zoom;
		GtkSpinButton *h_step;
		GtkSpinButton *v_step;
	} widget;
};

struct grab {
	int grabbed;
	int x, y;
};

struct magnify {
	int active;
	int x, y;
	struct ipoint offset;
	int width, height;
	struct zoom zoom;
	struct graph *g;
#define MAGZOOMS_SAME		(1 << 0)
#define MAGZOOMS_SAME_RATIO	(1 << 1)
#define MAGZOOMS_IGNORE		(1 << 31)
	int flags;
	struct {
		GtkSpinButton *h_zoom, *v_zoom;
	} widget;
};

struct graph {
	struct graph *next;
#define GRAPH_TSEQ_STEVENS	0
#define GRAPH_TSEQ_TCPTRACE	1
#define GRAPH_THROUGHPUT	2
#define GRAPH_RTT			3
	int type;
#define GRAPH_DESTROYED				(1 << 0)
#define GRAPH_INIT_ON_TYPE_CHANGE	(1 << 1)
	int flags;
	GtkWidget *toplevel;	/* keypress handler needs this */
	GtkWidget *drawing_area;
	GtkWidget *text;		/* text widget for seg list - probably temporary */
	GdkFont *font;			/* font used for annotations etc. */
	GdkGC *fg_gc;
	GdkGC *bg_gc;
	GdkPixmap *title_pixmap;
	GdkPixmap *pixmap[2];
	int displayed;			/* which of both pixmaps is on screen right now */
	struct {
		GtkWidget *control_panel;
		/* this belongs to style structs of graph types that make use of it */
		GtkToggleButton *time_orig_conn, *seq_orig_isn;
	} gui;
	char **title;
	/* Next 4 attribs describe the graph in natural units, before any scaling.
	 * For example, if we want to display graph of TCP conversation that
	 * started 112.309845 s after beginning of the capture and ran until
	 * 479.093582 s, 237019 B went through the connection (in one direction)
	 * starting with isn 31934022, then (bounds.x0, bounds.y0)=(112.309845,
	 * 31934022) and (bounds.width, bounds.height)=(366.783737, 237019). */
	struct bounds bounds;
	/* dimensions and position of the graph, both expressed already in pixels.
	 * x and y give the position of upper left corner of the graph relative
	 * to origin of the graph window, size is basically bounds*zoom */
	struct irect geom;
	/* viewport (=graph window area which is reserved for graph itself), its
	 * size and position relative to origin of the graph window */
	struct irect wp;
	struct grab grab;
	/* If we need to display 237019 sequence numbers (=bytes) onto say 500
	 * pixels, we have to scale the graph down by factor of 0.002109. This
	 * number would be zoom.y. Obviously, both directions have separate zooms.*/
	struct zooms zoom;
	struct cross cross;
	struct magnify magnify;
	struct axis *x_axis, *y_axis;
	struct segment *segments;
	struct segment *current;
	struct element_list *elists;		/* element lists */
	union {
		struct style_tseq_stevens tseq_stevens;
		struct style_tseq_tcptrace tseq_tcptrace;
		struct style_tput tput;
		struct style_rtt rtt;
	} s;
};

static struct graph *graphs = NULL;
static GdkGC *xor_gc = NULL;
static int refnum=0;

#define debug(section) if (debugging & section)
/* print function entry points */
#define DBS_FENTRY			(1 << 0)
#define DBS_AXES_TICKS		(1 << 1)
#define DBS_AXES_DRAWING	(1 << 2)
#define DBS_GRAPH_DRAWING	(1 << 3)
#define DBS_TPUT_ELMTS		(1 << 4)
/*int debugging = DBS_FENTRY;*/
int debugging = 0;
/*int debugging = DBS_AXES_TICKS;*/
/*int debugging = DBS_AXES_DRAWING;*/
/*int debugging = DBS_GRAPH_DRAWING;*/
/*int debugging = DBS_TPUT_ELMTS;*/

static void create_gui (struct graph * );
static void create_text_widget (struct graph * );
static void display_text (struct graph * );
static void create_drawing_area (struct graph * );
static void control_panel_create (struct graph * );
static GtkWidget *control_panel_create_zoom_group (struct graph * );
static GtkWidget *control_panel_create_magnify_group (struct graph * );
static GtkWidget *control_panel_create_cross_group (struct graph * );
static GtkWidget *control_panel_create_zoomlock_group (struct graph * );
static GtkWidget *control_panel_create_graph_type_group (struct graph * );
static void control_panel_add_zoom_page (struct graph * , GtkWidget * );
static void control_panel_add_magnify_page (struct graph * , GtkWidget * );
static void control_panel_add_origin_page (struct graph * , GtkWidget * );
static void control_panel_add_cross_page (struct graph * , GtkWidget * );
static void control_panel_add_graph_type_page (struct graph * , GtkWidget * );
static void callback_toplevel_destroy (GtkWidget * , gpointer );
static void callback_close (GtkWidget * , gpointer );
static void callback_time_origin (GtkWidget * , gpointer );
static void callback_seq_origin (GtkWidget * , gpointer );
static void callback_zoomlock_h (GtkWidget * , gpointer );
static void callback_zoomlock_v (GtkWidget * , gpointer );
static void callback_zoom_inout (GtkWidget * , gpointer );
static void callback_zoom_step (GtkWidget * , gpointer );
static void callback_zoom_flags (GtkWidget * , gpointer );
static void callback_cross_on_off (GtkWidget * , gpointer );
static void callback_mag_width (GtkWidget * , gpointer );
static void callback_mag_height (GtkWidget * , gpointer );
static void callback_mag_x (GtkWidget * , gpointer );
static void callback_mag_y (GtkWidget * , gpointer );
static void callback_mag_zoom (GtkWidget * , gpointer );
static void callback_mag_flags (GtkWidget * , gpointer );
static void callback_graph_type (GtkWidget * , gpointer );
static void callback_graph_init_on_typechg (GtkWidget * , gpointer );
static void callback_create_help (GtkWidget * , gpointer );
static void callback_close_help (GtkWidget * , gpointer );
static void update_zoom_spins (struct graph * );
static int get_headers (frame_data *, char * , struct segment * );
static int compare_headers (struct segment * , struct segment * , int );
static int get_num_dsegs (struct graph * );
static int get_num_acks (struct graph * );
static void graph_type_dependent_initialize (struct graph * );
static void graph_put (struct graph * );
static struct graph *graph_new (void);
static void graph_destroy (struct graph * );
static void graph_initialize_values (struct graph * );
static void graph_init_sequence (struct graph * );
static void draw_element_line (struct graph * , struct element * );
static void draw_element_arc (struct graph * , struct element * );
static void graph_display (struct graph * );
static void graph_pixmaps_create (struct graph * );
static void graph_pixmaps_switch (struct graph * );
static void graph_pixmap_draw (struct graph * );
static void graph_pixmap_display (struct graph * );
static void graph_element_lists_make (struct graph * );
static void graph_element_lists_free (struct graph * );
static void graph_element_lists_initialize (struct graph * );
static void graph_title_pixmap_create (struct graph * );
static void graph_title_pixmap_draw (struct graph * );
static void graph_title_pixmap_display (struct graph * );
static void graph_segment_list_get (struct graph * );
static void graph_segment_list_free (struct graph * );
static void graph_select_segment (struct graph * , int , int );
static int line_detect_collision (struct element * , int , int );
static int arc_detect_collision (struct element * , int , int );
static void update_packet_list (int );
static void axis_pixmaps_create (struct axis * );
static void axis_pixmaps_switch (struct axis * );
static void axis_display (struct axis * );
static void v_axis_pixmap_draw (struct axis * );
static void h_axis_pixmap_draw (struct axis * );
static void axis_pixmap_display (struct axis * );
static void axis_compute_ticks (struct axis * , double , double , int );
static double axis_zoom_get (struct axis * , int );
static void axis_ticks_up (int * , int * );
static void axis_ticks_down (int * , int * );
static void axis_destroy (struct axis * );
static int get_label_dim (struct axis * , int , double );
static void toggle_time_origin (struct graph * );
static void toggle_seq_origin (struct graph * );
static void cross_xor (struct graph * , int , int );
static void cross_draw (struct graph * , int , int );
static void cross_erase (struct graph * );
static void magnify_create (struct graph * , int , int );
static void magnify_move (struct graph * , int , int );
static void magnify_destroy (struct graph * );
static void magnify_draw (struct graph * );
static void magnify_get_geom (struct graph * , int , int );
static gint configure_event (GtkWidget * , GdkEventConfigure * );
static gint expose_event (GtkWidget * , GdkEventExpose * );
static gint button_press_event (GtkWidget * , GdkEventButton * );
static gint button_release_event (GtkWidget * , GdkEventButton * );
static gint motion_notify_event (GtkWidget * , GdkEventMotion * );
static gint key_press_event (GtkWidget * , GdkEventKey * );
static gint key_release_event (GtkWidget * , GdkEventKey * );
static gint leave_notify_event (GtkWidget * , GdkEventCrossing * );
static gint enter_notify_event (GtkWidget * , GdkEventCrossing * );
static void tseq_stevens_initialize (struct graph * );
static void tseq_stevens_get_bounds (struct graph * );
static void tseq_stevens_read_config (struct graph * );
static void tseq_stevens_make_elmtlist (struct graph * );
static void tseq_stevens_toggle_seq_origin (struct graph * );
static void tseq_stevens_toggle_time_origin (struct graph * );
static void tseq_tcptrace_read_config (struct graph * );
static void tseq_tcptrace_make_elmtlist (struct graph * );
static void tseq_tcptrace_toggle_seq_origin (struct graph * );
static void tseq_tcptrace_toggle_time_origin (struct graph * );
static void tput_initialize (struct graph * );
static void tput_read_config (struct graph * );
static void tput_make_elmtlist (struct graph * );
static void tput_toggle_time_origin (struct graph * );
static void rtt_read_config (struct graph * );
static void rtt_initialize (struct graph * );
static int rtt_is_retrans (struct unack * , unsigned int );
static struct unack *rtt_get_new_unack (double , unsigned int );
static void rtt_put_unack_on_list (struct unack ** , struct unack * );
static void rtt_delete_unack_from_list (struct unack ** , struct unack * );
static void rtt_make_elmtlist (struct graph * );
static void rtt_toggle_seq_origin (struct graph * );
#ifdef WIN32
static int rint (double );	/* compiler template for Windows */
#endif

static char helptext[] =
#ifndef WIN32
"Here's what you can do:\n\
- Left Mouse Button selects segment in ethereal's packet list\n\
- Middle Mouse Button zooms in\n\
- <shift>-Middle Button zooms out\n\
- Right Mouse Button moves the graph (if zoomed in)\n\
- <ctrl>-Right Mouse Button displays a portion of graph magnified\n\
- Space toggles crosshairs\n\
- 's' toggles relative/absolute sequence numbers\n\
- 't' toggles time origin\n\
";
#else /* WIN32 */
"Here's what you can do:\n\
- <ctrl>-Left  Mouse Button selects segment in ethereal's packet list\n\
- Left         Mouse Button zooms in\n\
- <shift>-Left Mouse Button zooms out\n\
- Right        Mouse Button moves the graph (if zoomed in)\n\
- <ctrl>-Right Mouse Button displays a portion of graph magnified\n\
\n\
- Space bar toggles crosshairs\n\
- 's' - Toggles relative/absolute sequence numbers\n\
- 't' - Toggles time origin\n\
";
#endif

void tcp_graph_cb (GtkWidget *w, gpointer data, guint graph_type)
{
	struct segment current;
	struct graph *g;

	debug(DBS_FENTRY) puts ("tcp_graph_cb()");

	if (! (g = graph_new()))
		return;

	refnum++;
	graph_initialize_values (g);
	graph_put (g);

	g->type = graph_type;
	if (!get_headers (cfile.current_frame, cfile.pd, &current)) {
		/* currently selected packet is neither TCP over IP over Ethernet II/PPP
		 * nor TCP over IP alone - should display some
		 * kind of warning dialog */
		simple_dialog(ESD_TYPE_WARN, NULL,
		    "Selected packet is not a TCP segment");
		return;
	}

	graph_segment_list_get(g);
	create_gui(g);
	/* display_text(g); */
	graph_init_sequence(g);
}

static void create_gui (struct graph *g)
{
	debug(DBS_FENTRY) puts ("create_gui()");
	/* create_text_widget(g); */
	control_panel_create (g);
	create_drawing_area(g);
}

static void create_text_widget (struct graph *g)
{
	GtkWidget *streamwindow, *txt_scrollw, *box;

	debug(DBS_FENTRY) puts ("create_text_widget()");
	streamwindow = gtk_window_new (GTK_WINDOW_TOPLEVEL);
	gtk_widget_set_name (streamwindow, "Packet chain");
	gtk_widget_set_usize (GTK_WIDGET (streamwindow), TXT_WIDTH, TXT_HEIGHT);
	gtk_container_border_width (GTK_CONTAINER(streamwindow), 2);
	gtk_signal_connect (GTK_OBJECT (streamwindow), "realize",
		GTK_SIGNAL_FUNC (window_icon_realize_cb), NULL);

	box = gtk_vbox_new (FALSE, 0);
	gtk_container_add (GTK_CONTAINER (streamwindow), box);
	gtk_widget_show (box);

	txt_scrollw = scrolled_window_new (NULL, NULL);
	gtk_box_pack_start (GTK_BOX (box), txt_scrollw, TRUE, TRUE, 0);
	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (txt_scrollw),
					GTK_POLICY_NEVER, GTK_POLICY_ALWAYS);
	gtk_widget_show (txt_scrollw);

	g->text = gtk_text_new (NULL, NULL);
	gtk_text_set_editable (GTK_TEXT (g->text), FALSE);
	gtk_container_add (GTK_CONTAINER (txt_scrollw), g->text);
	gtk_widget_show (g->text);
	gtk_widget_show (streamwindow);
}

static void display_text (struct graph *g)
{
	char *line[256];
	struct segment *ptr;
	double first_time, prev_time;
	unsigned int isn_this=0, isn_opposite=0, seq_this_prev, seq_opposite_prev;
	GdkColor color, *c;

	debug(DBS_FENTRY) puts ("display_text()");
	gdk_color_parse ("SlateGray", &color);
	gtk_text_freeze (GTK_TEXT (g->text));
	snprintf ((char * )line, 256, "%10s%15s%15s%15s%15s%15s%15s%10s\n",
					"pkt num", "time", "delta first", "delta prev",
					"seqno", "delta first", "delta prev", "data (B)");
	gtk_text_insert (GTK_TEXT (g->text), g->font, NULL, NULL,
							(const char *)line, -1);

	first_time = g->segments->rel_secs + g->segments->rel_usecs/1000000.0;
	prev_time = first_time;
	/* we have to find Initial Sequence Number for both ends of connection */
	for (ptr=g->segments; ptr; ptr=ptr->next) {
		if (compare_headers (g->current, ptr, COMPARE_CURR_DIR)) {
			isn_this = ntohl (ptr->tcphdr.seq);
			break;
		}
	}
	for (ptr=g->segments; ptr; ptr=ptr->next) {
		if (!compare_headers (g->current, ptr, COMPARE_CURR_DIR)) {
			isn_opposite = ntohl (ptr->tcphdr.seq);
			break;
		}
	}
	seq_this_prev = isn_this;
	seq_opposite_prev = isn_opposite;
	for (ptr=g->segments; ptr; ptr=ptr->next) {
		double time=ptr->rel_secs + ptr->rel_usecs/1000000.0;
		unsigned int seq = ntohl (ptr->tcphdr.seq);
		int seq_delta_isn, seq_delta_prev;

		if (compare_headers (g->current, ptr, COMPARE_CURR_DIR)) {
			seq_delta_isn = seq - isn_this;
			seq_delta_prev = seq - seq_this_prev;
			seq_this_prev = seq;
			c = NULL;
		} else {
			seq_delta_isn = seq - isn_opposite;
			seq_delta_prev = seq - seq_opposite_prev;
			seq_opposite_prev = seq;
			c = &color;
		}
		snprintf ((char *)line, 256, "%10d%15.6f%15.6f%15.6f%15u%15d%15d%10u\n",
						ptr->num, time, time-first_time, time-prev_time,
						seq, seq_delta_isn, seq_delta_prev,
						ntohs (ptr->iphdr.tot_len) - 4*IHL(&(ptr->iphdr)) -
						4*DOFF(ptr->tcphdr));
		gtk_text_insert (GTK_TEXT (g->text), g->font, c, NULL,
						(const char * )line, -1);
		prev_time = time;
	}
	gtk_text_thaw (GTK_TEXT (g->text));
}

static void create_drawing_area (struct graph *g)
{
	GdkColormap *colormap;
	GdkColor color;
	GtkWidget *frame, *box;
#define WINDOW_TITLE_LENGTH 64
	char window_title[WINDOW_TITLE_LENGTH];

	debug(DBS_FENTRY) puts ("create_drawing_area()");
#if 0
	g->font = gdk_font_load ("-sony-fixed-medium-r-normal--16-150-75-75"
							"-c-80-iso8859-2");
	g->font = gdk_font_load ("-biznet-fotinostypewriter-medium-r-normal-*-*-120"
							"-*-*-m-*-iso8859-2");
#endif
	g->toplevel = gtk_window_new (GTK_WINDOW_TOPLEVEL);
	gtk_widget_set_name (g->toplevel, "Test Graph");
	gtk_signal_connect (GTK_OBJECT (g->toplevel), "realize",
		GTK_SIGNAL_FUNC (window_icon_realize_cb), NULL);

	/* Create the drawing area */
	g->drawing_area = gtk_drawing_area_new ();
	g->x_axis->drawing_area = g->y_axis->drawing_area = g->drawing_area;
	gtk_drawing_area_size (GTK_DRAWING_AREA (g->drawing_area),
					g->wp.width + g->wp.x + RMARGIN_WIDTH,
					g->wp.height + g->wp.y + g->x_axis->s.height);
	gtk_widget_show (g->drawing_area);

	gtk_signal_connect (GTK_OBJECT (g->drawing_area), "expose_event",
							(GtkSignalFunc )expose_event, NULL);
	/* this has to be done later, after the widget has been shown */
	/*
	gtk_signal_connect (GTK_OBJECT(g->drawing_area),"configure_event",
							(GtkSignalFunc )configure_event, NULL);
	 */
	gtk_signal_connect (GTK_OBJECT (g->drawing_area), "motion_notify_event",
                      	(GtkSignalFunc )motion_notify_event, NULL);
	gtk_signal_connect (GTK_OBJECT (g->drawing_area), "button_press_event",
                    	(GtkSignalFunc )button_press_event, NULL);
	gtk_signal_connect (GTK_OBJECT (g->drawing_area), "button_release_event",
                    	(GtkSignalFunc )button_release_event, NULL);
	gtk_signal_connect (GTK_OBJECT (g->drawing_area), "leave_notify_event",
                    	(GtkSignalFunc )leave_notify_event, NULL);
	gtk_signal_connect (GTK_OBJECT (g->drawing_area), "enter_notify_event",
                    	(GtkSignalFunc )enter_notify_event, NULL);
	gtk_signal_connect (GTK_OBJECT (g->toplevel), "destroy",
                    	(GtkSignalFunc )callback_toplevel_destroy, g);
	/* why doesn't drawing area send key_press_signals? */
	gtk_signal_connect (GTK_OBJECT (g->toplevel), "key_press_event",
                    	(GtkSignalFunc )key_press_event, NULL);
	gtk_signal_connect (GTK_OBJECT (g->toplevel), "key_release_event",
                    	(GtkSignalFunc )key_release_event, NULL);
	gtk_widget_set_events (g->toplevel,GDK_KEY_PRESS_MASK|GDK_KEY_RELEASE_MASK);

	gtk_widget_set_events (g->drawing_area, GDK_EXPOSURE_MASK
									| GDK_LEAVE_NOTIFY_MASK
									| GDK_ENTER_NOTIFY_MASK
									| GDK_BUTTON_PRESS_MASK
									| GDK_BUTTON_RELEASE_MASK
									| GDK_POINTER_MOTION_MASK
									| GDK_POINTER_MOTION_HINT_MASK);

#if 0
	frame = gtk_frame_new (NULL);
	gtk_frame_set_shadow_type (GTK_FRAME (frame), GTK_SHADOW_ETCHED_IN);
	gtk_container_add (GTK_CONTAINER (frame), g->drawing_area);

	box = gtk_hbox_new (FALSE, 0);
	gtk_box_pack_start (GTK_BOX (box), g->gui.control_panel, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (box), frame, TRUE, TRUE, 0);
	gtk_container_add (GTK_CONTAINER (g->toplevel), box);
	gtk_container_set_border_width (GTK_CONTAINER (g->toplevel), 5);
	gtk_widget_show (frame);
	gtk_widget_show (box);
#endif

	gtk_container_add (GTK_CONTAINER (g->toplevel), g->drawing_area);
	gtk_widget_show (g->toplevel);
	snprintf (window_title, WINDOW_TITLE_LENGTH, "TCP Graph %d - Ethereal",
					refnum);
	gtk_window_set_title (GTK_WINDOW (g->toplevel), window_title);

	/* in case we didn't get what we asked for */
	g->wp.width = GTK_WIDGET (g->drawing_area)->allocation.width -
						g->wp.x - RMARGIN_WIDTH;
	g->wp.height = GTK_WIDGET (g->drawing_area)->allocation.height -
						g->wp.y - g->x_axis->s.height;

	g->font = g->drawing_area->style->font;
	gdk_font_ref (g->font);

	colormap = gdk_window_get_colormap (g->drawing_area->window);
	if (!xor_gc) {
		xor_gc = gdk_gc_new (g->drawing_area->window);
		gdk_gc_set_function (xor_gc, GDK_XOR);
		gdk_color_parse ("gray15", &color);
		gdk_colormap_alloc_color (colormap, &color, FALSE, TRUE);
		gdk_gc_set_foreground (xor_gc, &color);
	}
	g->fg_gc = gdk_gc_new (g->drawing_area->window);
	g->bg_gc = gdk_gc_new (g->drawing_area->window);
	gdk_color_parse ("white", &color);
	gdk_colormap_alloc_color (colormap, &color, FALSE, TRUE);
	gdk_gc_set_foreground (g->bg_gc, &color);

	/* this is probably quite an ugly way to get rid of the first configure
	 * event
	 * immediatelly after gtk_widget_show (window) drawing_area gets a configure
	 * event which is handled during the next return to gtk_main which is
	 * probably the gdk_gc_new() call. configure handler calls
	 * graph_element_lists_make() which is not good because the graph struct is
	 * not fully set up yet - namely we're not sure about actual geometry
	 * and we don't have the GC's at all. so we just postpone installation
	 * of configure handler until we're ready to deal with it.
	 *
	 * !!! NEM�LO BY TO B�T NA KONCI graph_init_sequence()? !!! 
	 *
	 */
	gtk_signal_connect (GTK_OBJECT(g->drawing_area),"configure_event",
							(GtkSignalFunc )configure_event, NULL);

	/* puts ("exiting create_drawing_area()"); */
}

static void callback_toplevel_destroy (GtkWidget *widget, gpointer data)
{
	struct graph *g = (struct graph * )data;

	if (!(g->flags & GRAPH_DESTROYED)) {
		g->flags |= GRAPH_DESTROYED;
		graph_destroy ((struct graph * )data);
	}
}

static void control_panel_create (struct graph *g)
{
	GtkWidget *toplevel, *notebook;
	GtkWidget *table;
	GtkWidget *help, *close, *button_box;
#define WINDOW_TITLE_LENGTH 64
	char window_title[WINDOW_TITLE_LENGTH];

	debug(DBS_FENTRY) puts ("control_panel_create()");

	notebook = gtk_notebook_new ();
	control_panel_add_zoom_page (g, notebook);
	control_panel_add_magnify_page (g, notebook);
	control_panel_add_origin_page (g, notebook);
	control_panel_add_cross_page (g, notebook);
	control_panel_add_graph_type_page (g, notebook);

	/* bottom buttons group */
	help = gtk_button_new_with_label ("Help");
	close = gtk_button_new_with_label ("Close");
	button_box = gtk_hbox_new (TRUE, 0);
	gtk_box_pack_start (GTK_BOX (button_box), help, TRUE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (button_box), close, TRUE, TRUE, 0);

	toplevel = gtk_window_new (GTK_WINDOW_TOPLEVEL);
	gtk_signal_connect (GTK_OBJECT (toplevel), "realize",
		GTK_SIGNAL_FUNC (window_icon_realize_cb), NULL);

	table = gtk_table_new (2, 1,  FALSE);
	gtk_container_add (GTK_CONTAINER (toplevel), table);

	gtk_table_attach (GTK_TABLE (table), notebook, 0, 1, 0, 1,
						GTK_FILL|GTK_EXPAND, GTK_FILL, 5, 5);
	gtk_table_attach (GTK_TABLE (table), button_box, 0, 1, 1, 2,
						GTK_FILL|GTK_EXPAND, GTK_FILL, 5, 5);

	gtk_signal_connect (GTK_OBJECT (close), "clicked",
                    	(GtkSignalFunc )callback_close, g);
	gtk_signal_connect (GTK_OBJECT (help), "clicked",
                    	(GtkSignalFunc )callback_create_help, g);

	/* gtk_widget_show_all (table); */
	/* g->gui.control_panel = table; */
	gtk_widget_show_all (toplevel);
	snprintf (window_title, WINDOW_TITLE_LENGTH,
				"Graph %d - Control - Ethereal", refnum);
	gtk_window_set_title (GTK_WINDOW (toplevel), window_title);
	g->gui.control_panel = toplevel;
}

static void control_panel_add_zoom_page (struct graph *g, GtkWidget *n)
{
	GtkWidget *zoom_frame;
	GtkWidget *zoom_lock_frame;
	GtkWidget *label;
	GtkWidget *box;

	zoom_frame = control_panel_create_zoom_group (g);
	gtk_container_set_border_width (GTK_CONTAINER (zoom_frame), 5);
	zoom_lock_frame = control_panel_create_zoomlock_group (g);
	gtk_container_set_border_width (GTK_CONTAINER (zoom_lock_frame), 5);
	box = gtk_vbox_new (FALSE, 0);
	gtk_box_pack_start (GTK_BOX (box), zoom_frame, TRUE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (box), zoom_lock_frame, TRUE, TRUE, 0);
	gtk_widget_show (box);
	label = gtk_label_new ("Zoom");
	gtk_notebook_append_page (GTK_NOTEBOOK (n), box, label);
}

static void control_panel_add_magnify_page (struct graph *g, GtkWidget *n)
{
	GtkWidget *mag_frame, *label;

	mag_frame = control_panel_create_magnify_group (g);
	gtk_container_set_border_width (GTK_CONTAINER (mag_frame), 5);
	label = gtk_label_new ("Magnify");
	gtk_notebook_append_page (GTK_NOTEBOOK (n), mag_frame, label);
}

static void control_panel_add_origin_page (struct graph *g, GtkWidget *n)
{
	GtkWidget *time_orig_cap, *time_orig_conn, *time_orig_box, *time_orig_frame;
	GtkWidget *seq_orig_isn, *seq_orig_zero, *seq_orig_box, *seq_orig_frame;
	GtkWidget *box, *label;

	/* time origin box */
	time_orig_cap =
			gtk_radio_button_new_with_label (NULL, "beginning of capture");
	time_orig_conn = gtk_radio_button_new_with_label (
			gtk_radio_button_group (GTK_RADIO_BUTTON (time_orig_cap)),
			"beginning of this TCP connection");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (time_orig_conn), TRUE);
	time_orig_box = gtk_vbox_new (TRUE, 0);
	gtk_box_pack_start (GTK_BOX (time_orig_box), time_orig_conn, TRUE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (time_orig_box), time_orig_cap, TRUE, TRUE, 0);
	time_orig_frame = gtk_frame_new ("Time origin");
	gtk_container_set_border_width (GTK_CONTAINER (time_orig_frame), 5);
	gtk_container_add (GTK_CONTAINER (time_orig_frame), time_orig_box);

	/* sequence number origin group */
	seq_orig_isn =
			gtk_radio_button_new_with_label (NULL, "initial sequence number");
	seq_orig_zero = gtk_radio_button_new_with_label (gtk_radio_button_group (
			GTK_RADIO_BUTTON (seq_orig_isn)), "0 (=absolute)");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (seq_orig_isn), TRUE);
	seq_orig_box = gtk_vbox_new (TRUE, 0);
	gtk_box_pack_start (GTK_BOX (seq_orig_box), seq_orig_isn, TRUE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (seq_orig_box), seq_orig_zero, TRUE, TRUE, 0);
	seq_orig_frame = gtk_frame_new ("Sequence number origin");
	gtk_container_set_border_width (GTK_CONTAINER (seq_orig_frame), 5);
	gtk_container_add (GTK_CONTAINER (seq_orig_frame), seq_orig_box);

	g->gui.time_orig_conn = (GtkToggleButton * )time_orig_conn;
	g->gui.seq_orig_isn = (GtkToggleButton * )seq_orig_isn;

	gtk_signal_connect (GTK_OBJECT (time_orig_conn), "toggled",
                    	(GtkSignalFunc )callback_time_origin, g);
	gtk_signal_connect (GTK_OBJECT (seq_orig_isn), "toggled",
                    	(GtkSignalFunc )callback_seq_origin, g);

	box = gtk_vbox_new (FALSE, 0);
	gtk_container_set_border_width (GTK_CONTAINER (box), 5);
	gtk_box_pack_start (GTK_BOX (box), time_orig_frame, TRUE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (box), seq_orig_frame, TRUE, TRUE, 0);
	gtk_widget_show (box);
	label = gtk_label_new ("Origin");
	gtk_notebook_append_page (GTK_NOTEBOOK (n), box, label);
}

static void control_panel_add_cross_page (struct graph *g, GtkWidget *n)
{
	GtkWidget *cross_frame, *label;

	cross_frame = control_panel_create_cross_group (g);
	gtk_container_set_border_width (GTK_CONTAINER (cross_frame), 5);
	label = gtk_label_new ("Cross");
	gtk_notebook_append_page (GTK_NOTEBOOK (n), cross_frame, label);
}

static void control_panel_add_graph_type_page (struct graph *g, GtkWidget *n)
{
	GtkWidget *frame, *label;

	frame = control_panel_create_graph_type_group (g);
	gtk_container_set_border_width (GTK_CONTAINER (frame), 5);
	label = gtk_label_new ("Graph type");
	gtk_notebook_append_page (GTK_NOTEBOOK (n), frame, label);
}

static void callback_close (GtkWidget *widget, gpointer data)
{
	struct graph *g = (struct graph * )data;

	if (!(g->flags & GRAPH_DESTROYED)) {
		g->flags |= GRAPH_DESTROYED;
		graph_destroy ((struct graph * )data);
	}
}

static void callback_create_help (GtkWidget *widget, gpointer data)
{
	struct graph *g = (struct graph * )data;
	GtkWidget *toplevel, *box, *text, *scroll, *close;

	toplevel = gtk_window_new (GTK_WINDOW_TOPLEVEL);
	gtk_window_set_title(GTK_WINDOW(toplevel), "Help for TCP graphing");
	gtk_widget_set_usize (toplevel, 500, 400);
	gtk_signal_connect (GTK_OBJECT (toplevel), "realize",
		GTK_SIGNAL_FUNC (window_icon_realize_cb), NULL);

	box = gtk_vbox_new (FALSE, 0);
	gtk_container_add (GTK_CONTAINER (toplevel), box);
	scroll = gtk_scrolled_window_new (NULL, NULL);
	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scroll),
						GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
	gtk_box_pack_start (GTK_BOX (box), scroll, TRUE, TRUE, 0);
	text = gtk_text_new (NULL, NULL);
	gtk_text_set_editable (GTK_TEXT (text), FALSE);
	gtk_text_set_line_wrap (GTK_TEXT (text), FALSE);
	gtk_text_set_word_wrap (GTK_TEXT (text), FALSE);
	gtk_text_insert (GTK_TEXT (text), g->font, NULL, NULL, helptext, -1);
	gtk_container_add (GTK_CONTAINER (scroll), text);
	close = gtk_button_new_with_label ("Close");
	gtk_box_pack_start (GTK_BOX (box), close, FALSE, FALSE, 0);
	gtk_signal_connect (GTK_OBJECT (close), "clicked",
                    	(GtkSignalFunc )callback_close_help, toplevel);
	
	gtk_widget_show_all (toplevel);
}

static void callback_close_help (GtkWidget *widget, gpointer data)
{
	gtk_widget_destroy ((GtkWidget * )data);
}

static void callback_time_origin (GtkWidget *toggle, gpointer data)
{
	toggle_time_origin ((struct graph * )data);
}

static void callback_seq_origin (GtkWidget *toggle, gpointer data)
{
	toggle_seq_origin ((struct graph * )data);
}

static GtkWidget *control_panel_create_zoom_group (struct graph *g)
{
	GtkWidget *zoom_in, *zoom_out, *zoom_box, *zoom_frame;
	GtkAdjustment *zoom_h_adj, *zoom_v_adj;
	GtkWidget *zoom_inout_box, *zoom_h_step_label, *zoom_h_step;
	GtkWidget *zoom_v_step_label, *zoom_v_step;
	GtkWidget *zoom_separator1, *zoom_separator2, *zoom_step_table, *zoom_table;
	GtkWidget *zoom_ratio_toggle, *zoom_same_toggle;
	GtkWidget *zoom_h_entry, *zoom_v_entry;
	GtkWidget *zoom_h_label, *zoom_v_label;

	zoom_in = gtk_radio_button_new_with_label (NULL, "in");
	zoom_out = gtk_radio_button_new_with_label (
					gtk_radio_button_group (GTK_RADIO_BUTTON (zoom_in)), "out");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (zoom_in), TRUE);
	zoom_inout_box = gtk_hbox_new (FALSE, 0);
	gtk_box_pack_start (GTK_BOX (zoom_inout_box), zoom_in, FALSE, FALSE, 10);
	gtk_box_pack_start (GTK_BOX (zoom_inout_box), zoom_out, FALSE, FALSE, 0);

	zoom_separator1 = gtk_hseparator_new ();

	zoom_h_entry = gtk_entry_new ();
	gtk_entry_set_text (GTK_ENTRY (zoom_h_entry), "1.000");
	gtk_editable_set_editable (GTK_EDITABLE (zoom_h_entry), FALSE);
	zoom_h_label = gtk_label_new ("Horizontal:");

	zoom_v_entry = gtk_entry_new ();
	gtk_entry_set_text (GTK_ENTRY (zoom_v_entry), "1.000");
	gtk_editable_set_editable (GTK_EDITABLE (zoom_v_entry), FALSE);
	zoom_v_label = gtk_label_new ("Vertical:");

	g->zoom.widget.h_zoom = (GtkEntry * )zoom_h_entry;
	g->zoom.widget.v_zoom = (GtkEntry * )zoom_v_entry;

	zoom_table = gtk_table_new (2, 2,  FALSE);
	gtk_table_attach (GTK_TABLE (zoom_table), zoom_h_label, 0,1,0,1,
				GTK_FILL|GTK_EXPAND, GTK_FILL|GTK_EXPAND, 5, 0);
	gtk_table_attach (GTK_TABLE (zoom_table), zoom_h_entry, 1, 2, 0, 1,
				GTK_FILL|GTK_EXPAND, GTK_FILL|GTK_EXPAND, 5, 0);
	gtk_table_attach (GTK_TABLE (zoom_table), zoom_v_label, 0,1,1,2,
				GTK_FILL|GTK_EXPAND, GTK_FILL|GTK_EXPAND, 5, 0);
	gtk_table_attach (GTK_TABLE (zoom_table), zoom_v_entry, 1, 2, 1, 2,
				GTK_FILL|GTK_EXPAND, GTK_FILL|GTK_EXPAND, 5, 0);

	zoom_separator2 = gtk_hseparator_new ();

	zoom_h_adj = (GtkAdjustment * )gtk_adjustment_new (1.2, 1.0, 5, 0.1, 1, 0);
	zoom_h_step = gtk_spin_button_new (zoom_h_adj, 0, 1);
	gtk_spin_button_set_numeric (GTK_SPIN_BUTTON (zoom_h_step), TRUE);
	zoom_h_step_label = gtk_label_new ("Horizontal step:");

	zoom_v_adj = (GtkAdjustment * )gtk_adjustment_new (1.2, 1.0, 5, 0.1, 1, 0);
	zoom_v_step = gtk_spin_button_new (zoom_v_adj, 0, 1);
	gtk_spin_button_set_numeric (GTK_SPIN_BUTTON (zoom_v_step), TRUE);
	zoom_v_step_label = gtk_label_new ("Vertical step:");

	g->zoom.widget.h_step = (GtkSpinButton * )zoom_h_step;
	g->zoom.widget.v_step = (GtkSpinButton * )zoom_v_step;

	zoom_same_toggle = gtk_check_button_new_with_label ("Keep them the same");
	zoom_ratio_toggle = gtk_check_button_new_with_label("Preserve their ratio");
	gtk_object_set_data (GTK_OBJECT (zoom_same_toggle), "flag",
						(gpointer )ZOOM_STEPS_SAME);
	gtk_object_set_data (GTK_OBJECT (zoom_ratio_toggle), "flag",
						(gpointer )ZOOM_STEPS_KEEP_RATIO);
	gtk_signal_connect (GTK_OBJECT (zoom_same_toggle), "clicked",
		               	(GtkSignalFunc )callback_zoom_flags, g);
	gtk_signal_connect (GTK_OBJECT (zoom_ratio_toggle), "clicked",
		               	(GtkSignalFunc )callback_zoom_flags, g);

	zoom_step_table = gtk_table_new (4, 2,  FALSE);
	gtk_table_attach (GTK_TABLE (zoom_step_table), zoom_h_step_label, 0,1,0,1,
				GTK_FILL|GTK_EXPAND, GTK_FILL|GTK_EXPAND, 5, 0);
	gtk_table_attach (GTK_TABLE (zoom_step_table), zoom_h_step, 1, 2, 0, 1,
				GTK_FILL|GTK_EXPAND, GTK_FILL|GTK_EXPAND, 5, 0);
	gtk_table_attach (GTK_TABLE (zoom_step_table), zoom_v_step_label, 0,1,1,2,
				GTK_FILL|GTK_EXPAND, GTK_FILL|GTK_EXPAND, 5, 0);
	gtk_table_attach (GTK_TABLE (zoom_step_table), zoom_v_step, 1, 2, 1, 2,
				GTK_FILL|GTK_EXPAND, GTK_FILL|GTK_EXPAND, 5, 0);
	gtk_table_attach (GTK_TABLE (zoom_step_table), zoom_same_toggle, 0,2,2,3,
				GTK_FILL|GTK_EXPAND, GTK_FILL|GTK_EXPAND, 5, 0);
	gtk_table_attach (GTK_TABLE (zoom_step_table), zoom_ratio_toggle, 0,2,3,4,
				GTK_FILL|GTK_EXPAND, GTK_FILL|GTK_EXPAND, 5, 0);

	zoom_box = gtk_vbox_new (FALSE, 0);
	gtk_box_pack_start (GTK_BOX (zoom_box), zoom_inout_box, TRUE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (zoom_box), zoom_separator1, TRUE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (zoom_box), zoom_table, TRUE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (zoom_box), zoom_separator2, TRUE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (zoom_box), zoom_step_table, TRUE, TRUE, 0);
	zoom_frame = gtk_frame_new ("Zoom");
	gtk_container_add (GTK_CONTAINER (zoom_frame), zoom_box);

	gtk_object_set_data (GTK_OBJECT (zoom_h_step), "direction", (gpointer )0);
	gtk_object_set_data (GTK_OBJECT (zoom_v_step), "direction", (gpointer )1);

	gtk_signal_connect (GTK_OBJECT (zoom_in), "toggled",
		               	(GtkSignalFunc )callback_zoom_inout, g);
	gtk_signal_connect (GTK_OBJECT (zoom_h_step), "changed",
		               	(GtkSignalFunc )callback_zoom_step, g);
	gtk_signal_connect (GTK_OBJECT (zoom_v_step), "changed",
		               	(GtkSignalFunc )callback_zoom_step, g);

	g->zoom.widget.in_toggle = (GtkToggleButton * )zoom_in;
	g->zoom.widget.out_toggle = (GtkToggleButton * )zoom_out;
	return zoom_frame;
}

static void callback_zoom_inout (GtkWidget *toggle, gpointer data)
{
	struct graph *g = (struct graph * )data;

	if (GTK_TOGGLE_BUTTON (toggle)->active)
		g->zoom.flags &= ~ZOOM_OUT;
	else
		g->zoom.flags |= ZOOM_OUT;
}

static void callback_zoom_step (GtkWidget *spin, gpointer data)
{
	struct graph *g = (struct graph * )data;
	float value;
	int direction;
	double *zoom_this, *zoom_other;
	GtkSpinButton *widget_this, *widget_other;
	double old_this;

	direction = (int )gtk_object_get_data (GTK_OBJECT (spin), "direction");
	value = gtk_spin_button_get_value_as_float (GTK_SPIN_BUTTON (spin));

	if (direction) {
		zoom_this = &g->zoom.step_y;
		zoom_other = &g->zoom.step_x;
		widget_this = g->zoom.widget.v_step;
		widget_other = g->zoom.widget.h_step;
	} else {
		zoom_this = &g->zoom.step_x;
		zoom_other = &g->zoom.step_y;
		widget_this = g->zoom.widget.h_step;
		widget_other = g->zoom.widget.v_step;
	}

	old_this = *zoom_this;
	*zoom_this = value;
	if (g->zoom.flags & ZOOM_STEPS_SAME) {
		*zoom_other = value;
		gtk_spin_button_set_value (widget_other, *zoom_other);
	} else if (g->zoom.flags & ZOOM_STEPS_KEEP_RATIO) {
		double old_other = *zoom_other;
		*zoom_other *= value / old_this;
		if (*zoom_other < 1.0) {
			*zoom_other = 1.0;
			*zoom_this = old_this * 1.0 / old_other;
			gtk_spin_button_set_value (widget_this, *zoom_this);
		} else if (*zoom_other > 5.0) {
			*zoom_other = 5.0;
			*zoom_this = old_this * 5.0 / old_other;
			gtk_spin_button_set_value (widget_this, *zoom_this);
		}
		gtk_spin_button_set_value (widget_other, *zoom_other);
	}
}

static void callback_zoom_flags (GtkWidget *toggle, gpointer data)
{
	struct graph *g = (struct graph * )data;
	int flag = (int )gtk_object_get_data (GTK_OBJECT (toggle), "flag");

	if (GTK_TOGGLE_BUTTON (toggle)->active)
		g->zoom.flags |= flag;	
	else
		g->zoom.flags &= ~flag;	
}

static void update_zoom_spins (struct graph *g)
{
	char s[32];

	snprintf (s, 32, "%.3f", g->zoom.x / g->zoom.initial.x);
	gtk_entry_set_text (g->zoom.widget.h_zoom, s);
	snprintf (s, 32, "%.3f", g->zoom.y / g->zoom.initial.y);
	gtk_entry_set_text (g->zoom.widget.v_zoom, s);
}

static GtkWidget *control_panel_create_magnify_group (struct graph *g)
{
	GtkWidget *mag_width_label, *mag_width;
	GtkWidget *mag_height_label, *mag_height;
	GtkWidget *mag_x_label, *mag_x;
	GtkWidget *mag_y_label, *mag_y;
	GtkWidget *mag_wh_table, *mag_zoom_frame, *mag_zoom_table;
	GtkWidget *mag_h_zoom_label, *mag_h_zoom;
	GtkWidget *mag_v_zoom_label, *mag_v_zoom;
	GtkWidget *mag_zoom_same, *mag_zoom_ratio;
	GtkAdjustment *mag_width_adj, *mag_height_adj, *mag_x_adj, *mag_y_adj;
	GtkAdjustment *mag_h_zoom_adj, *mag_v_zoom_adj;
	GtkWidget *mag_box, *mag_frame;

	mag_width_label = gtk_label_new ("Width:");
	mag_width_adj = (GtkAdjustment * )gtk_adjustment_new (250,100,600,1,10,0);
	mag_width = gtk_spin_button_new (mag_width_adj, 0, 0);

	mag_height_label = gtk_label_new ("Height:");
	mag_height_adj = (GtkAdjustment * )gtk_adjustment_new (250,100,600,1,10,0);
	mag_height = gtk_spin_button_new (mag_height_adj, 0, 0);

	mag_x_label = gtk_label_new ("X:");
	mag_x_adj = (GtkAdjustment * )gtk_adjustment_new (0,-1000,1000,1,10,0);
	mag_x = gtk_spin_button_new (mag_x_adj, 0, 0);

	mag_y_label = gtk_label_new ("Y:");
	mag_y_adj = (GtkAdjustment * )gtk_adjustment_new (0,-1000,1000,1,10,0);
	mag_y = gtk_spin_button_new (mag_y_adj, 0, 0);

	mag_wh_table = gtk_table_new (4, 2, FALSE);
	gtk_table_attach (GTK_TABLE (mag_wh_table), mag_width_label, 0,1,0,1,
				GTK_FILL|GTK_EXPAND, GTK_FILL|GTK_EXPAND, 5, 0);
	gtk_table_attach (GTK_TABLE (mag_wh_table), mag_width, 1,2,0,1,
				GTK_FILL|GTK_EXPAND, GTK_FILL|GTK_EXPAND, 5, 0);
	gtk_table_attach (GTK_TABLE (mag_wh_table), mag_height_label, 0,1,1,2,
				GTK_FILL|GTK_EXPAND, GTK_FILL|GTK_EXPAND, 5, 0);
	gtk_table_attach (GTK_TABLE (mag_wh_table), mag_height, 1,2,1,2,
				GTK_FILL|GTK_EXPAND, GTK_FILL|GTK_EXPAND, 5, 0);
	gtk_table_attach (GTK_TABLE (mag_wh_table), mag_x_label, 0,1,2,3,
				GTK_FILL|GTK_EXPAND, GTK_FILL|GTK_EXPAND, 5, 0);
	gtk_table_attach (GTK_TABLE (mag_wh_table), mag_x, 1,2,2,3,
				GTK_FILL|GTK_EXPAND, GTK_FILL|GTK_EXPAND, 5, 0);
	gtk_table_attach (GTK_TABLE (mag_wh_table), mag_y_label, 0,1,3,4,
				GTK_FILL|GTK_EXPAND, GTK_FILL|GTK_EXPAND, 5, 0);
	gtk_table_attach (GTK_TABLE (mag_wh_table), mag_y, 1,2,3,4,
				GTK_FILL|GTK_EXPAND, GTK_FILL|GTK_EXPAND, 5, 0);

	mag_h_zoom_label = gtk_label_new ("Horizontal:");
	mag_h_zoom_adj = (GtkAdjustment *)gtk_adjustment_new(10.0,1.0,25.0,0.1,1,0);
	mag_h_zoom = gtk_spin_button_new (mag_h_zoom_adj, 0, 1);

	mag_v_zoom_label = gtk_label_new ("Vertical:");
	mag_v_zoom_adj = (GtkAdjustment *)gtk_adjustment_new(10.0,1.0,25.0,0.1,1,0);
	mag_v_zoom = gtk_spin_button_new (mag_v_zoom_adj, 0, 1);

	mag_zoom_same = gtk_check_button_new_with_label ("Keep them the same");
	mag_zoom_ratio = gtk_check_button_new_with_label("Preserve their ratio");

	mag_zoom_table = gtk_table_new (4, 2, FALSE);
	gtk_table_attach (GTK_TABLE (mag_zoom_table), mag_h_zoom_label, 0,1,0,1,
				GTK_FILL|GTK_EXPAND, GTK_FILL|GTK_EXPAND, 0, 0);
	gtk_table_attach (GTK_TABLE (mag_zoom_table), mag_h_zoom, 1,2,0,1,
				GTK_FILL|GTK_EXPAND, GTK_FILL|GTK_EXPAND, 0, 0);
	gtk_table_attach (GTK_TABLE (mag_zoom_table), mag_v_zoom_label, 0,1,1,2,
				GTK_FILL|GTK_EXPAND, GTK_FILL|GTK_EXPAND, 0, 0);
	gtk_table_attach (GTK_TABLE (mag_zoom_table), mag_v_zoom, 1,2,1,2,
				GTK_FILL|GTK_EXPAND, GTK_FILL|GTK_EXPAND, 0, 0);
	gtk_table_attach (GTK_TABLE (mag_zoom_table), mag_zoom_same, 0,2,2,3,
				GTK_FILL|GTK_EXPAND, GTK_FILL|GTK_EXPAND, 0, 0);
	gtk_table_attach (GTK_TABLE (mag_zoom_table), mag_zoom_ratio, 0,2,3,4,
				GTK_FILL|GTK_EXPAND, GTK_FILL|GTK_EXPAND, 0, 0);

	mag_zoom_frame = gtk_frame_new ("Magnify zoom");
	gtk_container_add (GTK_CONTAINER (mag_zoom_frame), mag_zoom_table);
	gtk_container_set_border_width (GTK_CONTAINER (mag_zoom_frame), 3);

	mag_box = gtk_vbox_new (FALSE, 0);
	gtk_box_pack_start (GTK_BOX (mag_box), mag_wh_table, TRUE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (mag_box), mag_zoom_frame, TRUE, TRUE, 0);
	mag_frame = gtk_frame_new ("Magnify");
	gtk_container_add (GTK_CONTAINER (mag_frame), mag_box);

	g->magnify.widget.h_zoom = (GtkSpinButton * )mag_h_zoom;
	g->magnify.widget.v_zoom = (GtkSpinButton * )mag_v_zoom;
	gtk_object_set_data (GTK_OBJECT (mag_h_zoom), "direction", (gpointer )0);
	gtk_object_set_data (GTK_OBJECT (mag_v_zoom), "direction", (gpointer )1);
	gtk_object_set_data (GTK_OBJECT (mag_zoom_same), "flag",
										(gpointer )MAGZOOMS_SAME);
	gtk_object_set_data (GTK_OBJECT (mag_zoom_ratio), "flag",
										(gpointer )MAGZOOMS_SAME_RATIO);

	gtk_signal_connect (GTK_OBJECT (mag_width), "changed",
		               	(GtkSignalFunc )callback_mag_width, g);
	gtk_signal_connect (GTK_OBJECT (mag_height), "changed",
		               	(GtkSignalFunc )callback_mag_height, g);
	gtk_signal_connect (GTK_OBJECT (mag_x), "changed",
		               	(GtkSignalFunc )callback_mag_x, g);
	gtk_signal_connect (GTK_OBJECT (mag_y), "changed",
		               	(GtkSignalFunc )callback_mag_y, g);
	gtk_signal_connect (GTK_OBJECT (mag_h_zoom), "changed",
		               	(GtkSignalFunc )callback_mag_zoom, g);
	gtk_signal_connect (GTK_OBJECT (mag_v_zoom), "changed",
		               	(GtkSignalFunc )callback_mag_zoom, g);
	gtk_signal_connect (GTK_OBJECT (mag_zoom_same), "clicked",
		               	(GtkSignalFunc )callback_mag_flags, g);
	gtk_signal_connect (GTK_OBJECT (mag_zoom_ratio), "clicked",
		               	(GtkSignalFunc )callback_mag_flags, g);

	return mag_frame;
}

static void callback_mag_width (GtkWidget *spin, gpointer data)
{
	struct graph *g = (struct graph * )data;

	g->magnify.width = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON(spin));
}

static void callback_mag_height (GtkWidget *spin, gpointer data)
{
	struct graph *g = (struct graph * )data;

	g->magnify.height = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(spin));
}

static void callback_mag_x (GtkWidget *spin, gpointer data)
{
	struct graph *g = (struct graph * )data;

	g->magnify.offset.x=gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(spin));
}

static void callback_mag_y (GtkWidget *spin, gpointer data)
{
	struct graph *g = (struct graph * )data;

	g->magnify.offset.y=gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(spin));
}

static void callback_mag_zoom (GtkWidget *spin, gpointer data)
{
	struct graph *g = (struct graph * )data;
	float value;
	int direction;
	double *zoom_this, *zoom_other;
	GtkSpinButton *widget_this, *widget_other;
	double old_this;

	if (g->magnify.flags & MAGZOOMS_IGNORE) {
		printf ("refusing callback for %s zoom widget.\n", (GtkSpinButton * )spin==g->magnify.widget.h_zoom ? "horizontal" : "vertical");
		g->magnify.flags &= ~MAGZOOMS_IGNORE;
		return;
	}
	direction = (int )gtk_object_get_data (GTK_OBJECT (spin), "direction");
	value = gtk_spin_button_get_value_as_float (GTK_SPIN_BUTTON (spin));

	if (direction) {
		zoom_this = &g->magnify.zoom.y;
		zoom_other = &g->magnify.zoom.x;
		widget_this = g->magnify.widget.v_zoom;
		widget_other = g->magnify.widget.h_zoom;
	} else {
		zoom_this = &g->magnify.zoom.x;
		zoom_other = &g->magnify.zoom.y;
		widget_this = g->magnify.widget.h_zoom;
		widget_other = g->magnify.widget.v_zoom;
	}

	old_this = *zoom_this;
	*zoom_this = value;
	if (g->magnify.flags & MAGZOOMS_SAME) {
		*zoom_other = value;
		/* g->magnify.flags |= MAGZOOMS_IGNORE; */
		gtk_spin_button_set_value (widget_other, *zoom_other);
	} else if (g->magnify.flags & MAGZOOMS_SAME_RATIO) {
		double old_other = *zoom_other;
		*zoom_other *= value / old_this;
		if (*zoom_other < 1.0) {
			*zoom_other = 1.0;
			*zoom_this = old_this * 1.0 / old_other;
			/* g->magnify.flags |= MAGZOOMS_IGNORE; */
			gtk_spin_button_set_value (widget_this, *zoom_this);
		} else if (*zoom_other > 25.0) {
			*zoom_other = 25.0;
			*zoom_this = old_this * 25.0 / old_other;
			/* g->magnify.flags |= MAGZOOMS_IGNORE; */
			gtk_spin_button_set_value (widget_this, *zoom_this);
		}
		/* g->magnify.flags |= MAGZOOMS_IGNORE; */
		gtk_spin_button_set_value (widget_other, *zoom_other);
	}
}

static void callback_mag_flags (GtkWidget *toggle, gpointer data)
{
	struct graph *g = (struct graph * )data;
	int flag = (int )gtk_object_get_data (GTK_OBJECT (toggle), "flag");

	if (GTK_TOGGLE_BUTTON (toggle)->active)
		g->magnify.flags |= flag;	
	else
		g->magnify.flags &= ~flag;	
}

static GtkWidget *control_panel_create_zoomlock_group (struct graph *g)
{
	GtkWidget *zoom_lock_h, *zoom_lock_v, *zoom_lock_none, *zoom_lock_box;
	GtkWidget *zoom_lock_frame;

	zoom_lock_none = gtk_radio_button_new_with_label (NULL, "none");
	zoom_lock_h = gtk_radio_button_new_with_label (
					gtk_radio_button_group (GTK_RADIO_BUTTON (zoom_lock_none)),
					"horizontal");
	zoom_lock_v = gtk_radio_button_new_with_label (
					gtk_radio_button_group (GTK_RADIO_BUTTON (zoom_lock_none)),
					"vertical");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (zoom_lock_none), TRUE);
	zoom_lock_box = gtk_hbox_new (FALSE, 0);
	gtk_box_pack_start (GTK_BOX (zoom_lock_box), zoom_lock_none, TRUE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (zoom_lock_box), zoom_lock_h, TRUE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (zoom_lock_box), zoom_lock_v, TRUE, TRUE, 0);
	zoom_lock_frame = gtk_frame_new ("Zoom lock:");
	gtk_container_add (GTK_CONTAINER (zoom_lock_frame), zoom_lock_box);

	gtk_signal_connect (GTK_OBJECT (zoom_lock_h), "toggled",
                    	(GtkSignalFunc )callback_zoomlock_h, g);
	gtk_signal_connect (GTK_OBJECT (zoom_lock_v), "toggled",
                    	(GtkSignalFunc )callback_zoomlock_v, g);

	return zoom_lock_frame;
}

static void callback_zoomlock_h (GtkWidget *toggle, gpointer data)
{
	struct graph *g = (struct graph * )data;

	if (GTK_TOGGLE_BUTTON (toggle)->active)
		g->zoom.flags |= ZOOM_HLOCK;	
	else
		g->zoom.flags &= ~ZOOM_HLOCK;	
}

static void callback_zoomlock_v (GtkWidget *toggle, gpointer data)
{
	struct graph *g = (struct graph * )data;

	if (GTK_TOGGLE_BUTTON (toggle)->active)
		g->zoom.flags |= ZOOM_VLOCK;	
	else
		g->zoom.flags &= ~ZOOM_VLOCK;	
}

static GtkWidget *control_panel_create_cross_group (struct graph *g)
{
	GtkWidget *on, *off, *box, *frame, *vbox, *label;

	label = gtk_label_new ("Crosshairs:");
	off = gtk_radio_button_new_with_label (NULL, "off");
	on = gtk_radio_button_new_with_label (
				gtk_radio_button_group (GTK_RADIO_BUTTON (off)), "on");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (off), TRUE);
	box = gtk_hbox_new (FALSE, 0);
	gtk_box_pack_start (GTK_BOX (box), label, FALSE, FALSE, 10);
	gtk_box_pack_start (GTK_BOX (box), off, FALSE, FALSE, 10);
	gtk_box_pack_start (GTK_BOX (box), on, FALSE, FALSE, 0);
	vbox = gtk_vbox_new (FALSE, 0);
	gtk_box_pack_start (GTK_BOX (vbox), box, FALSE, FALSE, 15);
	/* frame = gtk_frame_new ("Cross:"); */
	frame = gtk_frame_new (NULL);
	gtk_container_add (GTK_CONTAINER (frame), vbox);

	gtk_signal_connect (GTK_OBJECT (on), "toggled",
		               	(GtkSignalFunc )callback_cross_on_off, g);

	g->cross.on_toggle = (GtkToggleButton * )on;
	g->cross.off_toggle = (GtkToggleButton * )off;

	return frame;
}

static void callback_cross_on_off (GtkWidget *toggle, gpointer data)
{
	struct graph *g = (struct graph * )data;

	if (GTK_TOGGLE_BUTTON (toggle)->active) {
		int x, y;
		g->cross.draw = TRUE;
		gdk_window_get_pointer (g->drawing_area->window, &x, &y, 0);
		cross_draw (g, x, y);
	} else {
		g->cross.draw = FALSE;
		cross_erase (g);
	}
}

static GtkWidget *control_panel_create_graph_type_group (struct graph *g)
{
	GtkWidget *graph_tseqttrace, *graph_tseqstevens;
	GtkWidget *graph_tput, *graph_rtt, *graph_sep, *graph_init, *graph_box;
	GtkWidget *graph_frame;

	graph_tput = gtk_radio_button_new_with_label (NULL, "Throughput");
	graph_tseqttrace = gtk_radio_button_new_with_label (
					gtk_radio_button_group (GTK_RADIO_BUTTON (graph_tput)),
					"Time/Sequence (tcptrace-style)");
	graph_tseqstevens = gtk_radio_button_new_with_label (
					gtk_radio_button_group (GTK_RADIO_BUTTON (graph_tput)),
					"Time/Sequence (Stevens'-style)");
	graph_rtt = gtk_radio_button_new_with_label (
					gtk_radio_button_group (GTK_RADIO_BUTTON (graph_tput)),
					"Round-trip Time");
	switch (g->type) {
	case GRAPH_TSEQ_STEVENS:
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(graph_tseqstevens),TRUE);
		break;
	case GRAPH_TSEQ_TCPTRACE:
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(graph_tseqttrace),TRUE);
		break;
	case GRAPH_THROUGHPUT:
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (graph_tput), TRUE);
		break;
	case GRAPH_RTT:
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (graph_rtt), TRUE);
		break;
	}
	graph_init = gtk_check_button_new_with_label ("Init on change");
	graph_sep = gtk_hseparator_new ();
	graph_box = gtk_vbox_new (FALSE, 0);
	gtk_box_pack_start (GTK_BOX (graph_box), graph_tseqttrace, TRUE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (graph_box), graph_tseqstevens, TRUE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (graph_box), graph_tput, TRUE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (graph_box), graph_rtt, TRUE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (graph_box), graph_sep, TRUE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (graph_box), graph_init, TRUE, TRUE, 0);
	graph_frame = gtk_frame_new ("Graph type:");
	gtk_container_add (GTK_CONTAINER (graph_frame), graph_box);

	gtk_object_set_data (GTK_OBJECT (graph_tseqstevens), "new-graph-type",
							(gpointer )0);
	gtk_object_set_data (GTK_OBJECT (graph_tseqttrace), "new-graph-type",
							(gpointer )1);
	gtk_object_set_data (GTK_OBJECT (graph_tput), "new-graph-type", 
							(gpointer )2);
	gtk_object_set_data (GTK_OBJECT (graph_rtt), "new-graph-type", 
							(gpointer )3);

	gtk_signal_connect (GTK_OBJECT (graph_tseqttrace), "toggled",
	                   	(GtkSignalFunc )callback_graph_type, g);
	gtk_signal_connect (GTK_OBJECT (graph_tseqstevens), "toggled",
	                   	(GtkSignalFunc )callback_graph_type, g);
	gtk_signal_connect (GTK_OBJECT (graph_tput), "toggled",
	                   	(GtkSignalFunc )callback_graph_type, g);
	gtk_signal_connect (GTK_OBJECT (graph_rtt), "toggled",
	                   	(GtkSignalFunc )callback_graph_type, g);
	gtk_signal_connect (GTK_OBJECT (graph_init), "toggled",
	                   	(GtkSignalFunc )callback_graph_init_on_typechg, g);

	return graph_frame;
}

static void callback_graph_type (GtkWidget *toggle, gpointer data)
{
	int old_type, new_type;
	struct graph *g = (struct graph * )data;

	new_type = (int )gtk_object_get_data (GTK_OBJECT (toggle),"new-graph-type");

	if (!GTK_TOGGLE_BUTTON (toggle)->active)
		return;

	old_type = g->type;
	g->type = new_type;

	graph_element_lists_free (g);
	graph_element_lists_initialize (g);

	if (old_type == GRAPH_THROUGHPUT || new_type == GRAPH_THROUGHPUT) {
		/* throughput graph uses differently constructed segment list so we
		 * need to recreate it */
		graph_segment_list_free (g);
		graph_segment_list_get (g);
	}

	if (g->flags & GRAPH_INIT_ON_TYPE_CHANGE) {
		g->geom.width = g->wp.width;
		g->geom.height = g->wp.height;
		g->geom.x = g->wp.x;
		g->geom.y = g->wp.y;
	}
	g->x_axis->min = g->y_axis->min = 0;
	gtk_toggle_button_set_active (g->gui.time_orig_conn, TRUE);
	gtk_toggle_button_set_active (g->gui.seq_orig_isn, TRUE);
	graph_init_sequence (g);
}

static void callback_graph_init_on_typechg (GtkWidget *toggle, gpointer data)
{
	((struct graph * )data)->flags ^= GRAPH_INIT_ON_TYPE_CHANGE;
}

static struct graph *graph_new (void)
{
	struct graph *g;

	g = (struct graph * )calloc (1, sizeof (struct graph));
	graph_element_lists_initialize (g);

	g->x_axis = (struct axis * )calloc (1, sizeof (struct axis));
	g->y_axis = (struct axis * )calloc (1, sizeof (struct axis));
	g->x_axis->g = g;
	g->x_axis->flags = 0;
	g->x_axis->flags |= AXIS_ORIENTATION;
	g->x_axis->s.x = g->x_axis->s.y = 0;
	g->x_axis->s.height = HAXIS_INIT_HEIGHT;
	g->x_axis->p.x = VAXIS_INIT_WIDTH;
	g->x_axis->p.height = HAXIS_INIT_HEIGHT;
	g->y_axis->g = g;
	g->y_axis->flags = 0;
	g->y_axis->flags &= ~AXIS_ORIENTATION;
	g->y_axis->p.x = g->y_axis->p.y = 0;
	g->y_axis->p.width = VAXIS_INIT_WIDTH;
	g->y_axis->s.x = 0;
	g->y_axis->s.y = TITLEBAR_HEIGHT;
	g->y_axis->s.width = VAXIS_INIT_WIDTH;

	return g;
}

static void graph_initialize_values (struct graph *g)
{
	g->geom.width = g->wp.width = 750;
	g->geom.height = g->wp.height = 550;
	g->geom.x = g->wp.x = VAXIS_INIT_WIDTH;
	g->geom.y = g->wp.y = TITLEBAR_HEIGHT;
	g->flags = 0;
	/* g->zoom.x = g->zoom.y = 1.0; */
	g->zoom.step_x = g->zoom.step_y = 1.2;
	g->zoom.flags = 0;
	g->cross.draw = g->cross.erase_needed = 0;
	g->grab.grabbed = 0;
	g->magnify.active = 0;
	g->magnify.offset.x = g->magnify.offset.y = 0;
	g->magnify.width = g->magnify.height = 250;
	g->magnify.zoom.x = g->magnify.zoom.y = 10.0;
	g->magnify.flags = 0;
}

static void graph_put (struct graph *graph)
{
	struct graph *g;
	if (graphs) {
		for (g=graphs; g->next; g=g->next);
		g->next = graph;
	} else
		graphs = graph;
}

static void graph_init_sequence (struct graph *g)
{
	debug(DBS_FENTRY) puts ("graph_init_sequence()");

	graph_type_dependent_initialize (g);
	g->zoom.initial.x = g->zoom.x;
	g->zoom.initial.y = g->zoom.y;
	graph_element_lists_make (g);
	g->x_axis->s.width = g->wp.width;
	g->x_axis->p.width = g->x_axis->s.width + RMARGIN_WIDTH;
	g->x_axis->p.y = TITLEBAR_HEIGHT + g->wp.height;
	g->x_axis->s.height = g->x_axis->p.height = HAXIS_INIT_HEIGHT;
	g->y_axis->s.height = g->wp.height;
	g->y_axis->p.height = g->wp.height + TITLEBAR_HEIGHT;
	graph_pixmaps_create (g);
	axis_pixmaps_create (g->y_axis);
	axis_pixmaps_create (g->x_axis);
	graph_title_pixmap_create (g);
	graph_title_pixmap_draw (g);
	graph_title_pixmap_display (g);
	graph_display (g);
	axis_display (g->y_axis);
	axis_display (g->x_axis);
}

static void graph_type_dependent_initialize (struct graph *g)
{
	switch (g->type) {
	case GRAPH_TSEQ_STEVENS:
	case GRAPH_TSEQ_TCPTRACE:
		tseq_stevens_initialize (g);
		break;
	case GRAPH_THROUGHPUT:
		tput_initialize (g);
		break;
	case GRAPH_RTT:
		rtt_initialize (g);
		break;
	default:
		break;
	}
}

static void graph_destroy (struct graph *g)
{
	struct graph *gtmp;
	struct graph *p=NULL;
	/* struct graph *tmp; */

	debug(DBS_FENTRY) puts ("graph_destroy()");

	for (gtmp=graphs; gtmp; p=gtmp, gtmp=gtmp->next)
		if (gtmp == g)
			break;

	axis_destroy (g->x_axis);
	axis_destroy (g->y_axis);
	/* gtk_widget_destroy (g->drawing_area); */
	gtk_widget_destroy (g->gui.control_panel);
	gtk_widget_destroy (g->toplevel);
	/* gtk_widget_destroy (g->text); */
	gdk_gc_unref (g->fg_gc);
	gdk_gc_unref (g->bg_gc);
	gdk_font_unref (g->font);
	gdk_pixmap_unref (g->pixmap[0]);
	gdk_pixmap_unref (g->pixmap[1]);
	free (g->x_axis);
	free (g->y_axis);
	free (g->title);
	graph_segment_list_free (g);
	graph_element_lists_free (g);
#if 0
	for (tmp=graphs; tmp; tmp=tmp->next)
		printf ("%p next: %p\n", tmp, tmp->next);
	printf ("p=%p, g=%p, p->next=%p, g->next=%p\n",
									p, g, p ? p->next : NULL, g->next);
#endif
	if (g==graphs)
		graphs = g->next;
	else
		p->next = g->next;
	free (g);
#if 0
	for (tmp=graphs; tmp; tmp=tmp->next)
		printf ("%p next: %p\n", tmp, tmp->next);
#endif
}

/* here we collect all the external data we will ever need */
static void graph_segment_list_get (struct graph *g)
{
	frame_data *ptr;
	char pd[4096];
	struct segment *segment=NULL, *last=NULL;
	struct segment current;
	int condition;

	debug(DBS_FENTRY) puts ("graph_segment_list_get()");
	get_headers (cfile.current_frame, cfile.pd, &current);
	if (g->type == GRAPH_THROUGHPUT)
		condition = COMPARE_CURR_DIR;
	else
		condition = COMPARE_ANY_DIR;

	for (ptr=cfile.plist; ptr; ptr=ptr->next) {
		wtap_seek_read (cfile.wth, ptr->file_off, &cfile.pseudo_header,
							pd, 4096);
		if (!segment)
			segment = (struct segment * )malloc (sizeof (struct segment));
			if (!segment)
				perror ("malloc failed");
		if (!get_headers (ptr, pd, segment))
			continue;	/* not TCP over IP over Ethernet II */
		if (compare_headers (&current, segment, condition)) {
			segment->next = NULL;
			segment->num = ptr->num;
			segment->rel_secs = ptr->rel_secs;
			segment->rel_usecs = ptr->rel_usecs;
			segment->abs_secs = ptr->abs_secs;
			segment->abs_usecs = ptr->abs_usecs;
			segment->data = ntohs (segment->iphdr.tot_len) -
							4*IHL(&(segment->iphdr)) - 4*DOFF(segment->tcphdr);
			if (g->segments) {
				last->next = segment;
			} else {
				g->segments = segment;
			}
			last = segment;
			if (ptr==cfile.current_frame)
				g->current = segment;
		}
		segment = NULL;
	}
}

static int get_headers (frame_data *fd, char *pd, struct segment *hdrs)
{
	struct ether_header *e;
	struct ppp_header   *p;
	void *ip;
	void *tcp;

	/*
	 * XXX - on Alpha, even fetching one-byte fields from structures
	 * pointed to by unaligned pointers may be risky, as, unless
	 * the BWX instructions are being used, a one-byte load is done
	 * by loading the word containing the byte and then extracting
	 * the byte.
	 *
	 * This means that the references to "p->ppp_type" and
	 * "((struct iphdr *)ip)->protocol" may turn into a load of
	 * an unaligned word.
	 */
	switch (fd->lnk_t) {

	case WTAP_ENCAP_ETHERNET:
		/* It's Ethernet */
		e = (struct ether_header *)pd;
		if (pntohs (&e->ether_type) != ETHERTYPE_IP)
			return FALSE;	/* not IP */
		ip = e + 1;
		break;

	case WTAP_ENCAP_PPP:
		/* It's PPP */
		p = (struct ppp_header *)pd;
		if (p->ppp_type != PPPTYPE_IP)
			return FALSE;	/* not IP */
		ip = p + 1;
		break;

	case WTAP_ENCAP_RAW_IP:
		/* Raw IP */
		ip = pd;
		break;

	default:
		/* Those are the only encapsulation types we handle */
		return FALSE;
	}
	if (((struct iphdr *)ip)->protocol != IPPROTO_TCP) {
		/* printf ("transport protocol not TCP: %#1x\n", ip->protocol); */
		return FALSE;
	}
	tcp = (struct tcphdr *)((guint8 *)ip + 4*IHL((struct iphdr *)ip));

	memcpy(&hdrs->iphdr, ip, sizeof (struct iphdr));
	memcpy(&hdrs->tcphdr, tcp, sizeof (struct tcphdr));
	return TRUE;
}

static int compare_headers (struct segment *h1, struct segment *h2, int dir)
{
	if (dir == COMPARE_CURR_DIR)
		return h1->iphdr.saddr == h2->iphdr.saddr &&
			   h1->iphdr.daddr == h2->iphdr.daddr &&
			   h1->tcphdr.source == h2->tcphdr.source &&
			   h1->tcphdr.dest == h2->tcphdr.dest;
	else
		return (h1->iphdr.saddr == h2->iphdr.saddr &&
			   h1->iphdr.daddr == h2->iphdr.daddr &&
			   h1->tcphdr.source == h2->tcphdr.source &&
			   h1->tcphdr.dest == h2->tcphdr.dest) ||
			   (h1->iphdr.saddr == h2->iphdr.daddr &&
			   h1->iphdr.daddr == h2->iphdr.saddr &&
			   h1->tcphdr.source == h2->tcphdr.dest &&
			   h1->tcphdr.dest == h2->tcphdr.source);
}

static void graph_segment_list_free (struct graph *g)
{
	struct segment *segment;

	while (g->segments) {
		segment = g->segments->next;
		free (g->segments);
		g->segments = segment;
	}
	g->segments = NULL;
}

static void graph_element_lists_initialize (struct graph *g)
{
	g->elists = (struct element_list *)calloc (1, sizeof (struct element_list));
}

static void graph_element_lists_make (struct graph *g)
{
	debug(DBS_FENTRY) puts ("graph_element_lists_make()");

	switch (g->type) {
	case GRAPH_TSEQ_STEVENS:
		tseq_stevens_make_elmtlist (g);
		break;
	case GRAPH_TSEQ_TCPTRACE:
		tseq_tcptrace_make_elmtlist (g);
		break;
	case GRAPH_THROUGHPUT:
		tput_make_elmtlist (g);
		break;
	case GRAPH_RTT:
		rtt_make_elmtlist (g);
		break;
	default:
		printf ("graph_element_lists_make: unknown graph type: %d\n", g->type);
		break;
	}
}

static void graph_element_lists_free (struct graph *g)
{
	struct element_list *list, *next_list;

#if 0
	for (list=g->elists; list; list=list->next)
		free (list->elements);
	while (g->elists->next) {
		list = g->elists->next->next;
		free (g->elists->next);
		g->elists->next = list;
	}
#endif

	for (list=g->elists; list; list=next_list) {
		free (list->elements);
		next_list = list->next;
		free (list);
	}
	g->elists = NULL;	/* just to make debugging easier */
}

static void graph_title_pixmap_create (struct graph *g)
{
	if (g->title_pixmap)
		gdk_pixmap_unref (g->title_pixmap);

	g->title_pixmap = gdk_pixmap_new (g->drawing_area->window,
							g->x_axis->p.width, g->wp.y, -1);
}

static void graph_title_pixmap_draw (struct graph *g)
{
	int i;

	gdk_draw_rectangle (g->title_pixmap, g->bg_gc, TRUE, 0, 0,
							g->x_axis->p.width, g->wp.y);
	for (i=0; g->title[i]; i++) {
		gint w, h;
		w = gdk_string_width (g->font, g->title[i]);
		h = gdk_string_height (g->font, g->title[i]);
		gdk_draw_string (g->title_pixmap, g->font, g->fg_gc,
					g->wp.width/2 - w/2, 20+h + i*(h+3), g->title[i]);
	}
}

static void graph_title_pixmap_display (struct graph *g)
{
	gdk_draw_pixmap (g->drawing_area->window, g->fg_gc, g->title_pixmap,
						0, 0, g->wp.x, 0, g->x_axis->p.width, g->wp.y);
}

static void graph_pixmaps_create (struct graph *g)
{
	debug(DBS_FENTRY) puts ("graph_pixmaps_create()");

	if (g->pixmap[0])
		gdk_pixmap_unref (g->pixmap[0]);
	if (g->pixmap[1])
		gdk_pixmap_unref (g->pixmap[1]);

	g->pixmap[0] = gdk_pixmap_new (g->drawing_area->window,
									g->wp.width, g->wp.height, -1);
	g->pixmap[1] = gdk_pixmap_new (g->drawing_area->window,
									g->wp.width, g->wp.height, -1);

	g->displayed = 0;
}

static void graph_display (struct graph *g)
{
	graph_pixmap_draw (g);
	graph_pixmaps_switch (g);
	graph_pixmap_display (g);
}

static void graph_pixmap_display (struct graph *g)
{
    gdk_draw_pixmap (g->drawing_area->window, g->fg_gc,
					g->pixmap[g->displayed], 0, 0, g->wp.x, g->wp.y,
					g->wp.width, g->wp.height);
}

static void graph_pixmaps_switch (struct graph *g)
{
	g->displayed = 1 ^ g->displayed;
}

static void graph_pixmap_draw (struct graph *g)
{
	struct element_list *list;
	struct element *e;
	int not_disp;

	debug(DBS_FENTRY) puts ("graph_display()");
	not_disp = 1 ^ g->displayed;

	gdk_draw_rectangle (g->pixmap[not_disp], g->bg_gc, TRUE,
							0, 0, g->wp.width, g->wp.height);

	for (list=g->elists; list; list=list->next)
		for (e=list->elements; e->type != ELMT_NONE; e++) {
			switch (e->type) {
			case ELMT_RECT:
				break;
			case ELMT_LINE:
				draw_element_line (g, e);
				break;
			case ELMT_ARC:
				draw_element_arc (g, e);
				break;
			default:
				break;
			}
		}
}

static void draw_element_line (struct graph *g, struct element *e)
{
	int x1, x2, y1, y2;

	debug(DBS_GRAPH_DRAWING) printf ("line element: (%.2f,%.2f)->(%.2f,%.2f), "
				"seg %d ... ", e->p.line.dim.x1, e->p.line.dim.y1,
				e->p.line.dim.x2, e->p.line.dim.y2, e->parent->num);
	x1 = (int )rint (e->p.line.dim.x1 + g->geom.x - g->wp.x);
	x2 = (int )rint (e->p.line.dim.x2 + g->geom.x - g->wp.x);
	y1 = (int )rint ((g->geom.height-1-e->p.line.dim.y1) + g->geom.y-g->wp.y);
	y2 = (int )rint ((g->geom.height-1-e->p.line.dim.y2) + g->geom.y-g->wp.y);
	if (x1 > x2) {
		int tmp=x2;
		x2=x1;
		x1=tmp;
	}
	if (y1 > y2) {
		int tmp=y2;
		y2=y1;
		y1=tmp;
	}
	if ((x1<0 && x2<0) || (x1>=g->wp.width && x2>=g->wp.width) ||
				(y1<0 && y2<0) || (y1>=g->wp.height && y2>=g->wp.height)) {
		debug(DBS_GRAPH_DRAWING) printf (" refusing: (%d,%d)->(%d,%d)\n",
									x1, y1, x2, y2);
		return;
	}
	if (x2 > g->wp.width-1)
		x2 = g->wp.width-1;
	if (x1 < 0)
		x1 = 0;
	if (y2 > g->wp.height-1)
		y2 = g->wp.height-1;
	if (y1 < 0)
		y1 = 0;
	debug(DBS_GRAPH_DRAWING) printf ("line: (%d,%d)->(%d,%d)\n", x1, y1, x2,y2);
	gdk_draw_line (g->pixmap[1^g->displayed], e->gc, x1, y1, x2, y2);
}

static void draw_element_arc (struct graph *g, struct element *e)
{
	int x1, x2, y1, y2;

	x1 = (int )rint (e->p.arc.dim.x + g->geom.x - g->wp.x);
	x2 = e->p.arc.dim.width;
	y1 = (int )rint (g->geom.height-1 - e->p.arc.dim.y + g->geom.y - g->wp.y);
	y2 = e->p.arc.dim.height;
	if (x1<-x2 || x1>=g->wp.width || y1<-y2 || y1>=g->wp.height)
		return;
	debug(DBS_GRAPH_DRAWING) printf ("arc: (%d,%d)->(%d,%d)\n", x1, y1, x2, y2);
	gdk_draw_arc (g->pixmap[1^g->displayed], e->gc, e->p.arc.filled, x1,
					y1, x2, y2, e->p.arc.angle1, e->p.arc.angle2);
}

static void axis_pixmaps_create (struct axis *axis)
{
	debug(DBS_FENTRY) puts ("axis_pixmaps_create()");
	if (axis->pixmap[0])
		gdk_pixmap_unref (axis->pixmap[0]);
	if (axis->pixmap[1])
		gdk_pixmap_unref (axis->pixmap[1]);

	axis->pixmap[0] = gdk_pixmap_new (axis->drawing_area->window,
							axis->p.width, axis->p.height, -1);
	axis->pixmap[1] = gdk_pixmap_new (axis->drawing_area->window,
							axis->p.width, axis->p.height, -1);

	axis->displayed = 0;
}

static void axis_destroy (struct axis *axis)
{
	gdk_pixmap_unref (axis->pixmap[0]);
	gdk_pixmap_unref (axis->pixmap[1]);
	free (axis->label);
}

static void axis_display (struct axis *axis)
{
	if (axis->flags & AXIS_ORIENTATION)
		h_axis_pixmap_draw (axis);
	else
		v_axis_pixmap_draw (axis);
	axis_pixmaps_switch (axis);
	axis_pixmap_display (axis);
}

static void v_axis_pixmap_draw (struct axis *axis)
{
	struct graph *g = axis->g;
	int i;
	double major_tick;
	int not_disp, rdigits, offset, imin, imax;
	double bottom, top, j, fl, corr;

	debug(DBS_FENTRY) puts ("v_axis_pixmap_draw()");
	bottom = (g->geom.height - (g->wp.height + g->wp.y + (-g->geom.y))) /
					(double )g->geom.height * g->bounds.height;
	bottom += axis->min;
	top = (g->geom.height - (g->wp.y + (-g->geom.y))) /
					(double )g->geom.height * g->bounds.height;
	top += axis->min;
	axis_compute_ticks (axis, bottom, top, AXIS_VERTICAL);

	j = axis->major - floor (axis->major);
	for (rdigits=0; rdigits<=6; rdigits++) {
		j *= 10;
		if (j<=0.000001)
			break;
		j = j - floor (j);
	}

	not_disp = 1 ^ axis->displayed;
	gdk_draw_rectangle (axis->pixmap[not_disp], g->bg_gc, TRUE, 0, 0,
					axis->p.width, axis->p.height);
	/* axis */
	gdk_draw_line (axis->pixmap[not_disp], g->fg_gc, axis->p.width - 1,
			(axis->p.height-axis->s.height)/2.0, axis->s.width - 1,
			axis->p.height);

	offset = g->wp.y + (-g->geom.y);
	fl = floor (axis->min / axis->major) * axis->major;
	corr = rint ((axis->min - fl) * g->zoom.y);

	/* major ticks */
	major_tick = axis->major * g->zoom.y;
	imin = (g->geom.height - offset + corr - g->wp.height) / major_tick + 1;
	imax = (g->geom.height - offset + corr) / major_tick;
	for (i=imin; i <= imax; i++) {
		gint w, h;
		char desc[32];
		int y = g->geom.height-1 - (int )rint (i * major_tick) -
						offset + corr + axis->s.y;

		debug(DBS_AXES_DRAWING) printf ("%f @ %d\n", i*axis->major + fl, y);
		if (y < 0 || y > axis->p.height)
			continue;
		gdk_draw_line (axis->pixmap[not_disp], g->fg_gc,
						axis->s.width - 15, y, axis->s.width - 1, y);
		snprintf (desc, 32, "%.*f", rdigits, i*axis->major + fl);
		w = gdk_string_width (g->font, desc);
		h = gdk_string_height (g->font, desc);
		gdk_draw_string (axis->pixmap[not_disp], g->font, g->fg_gc,
					axis->s.width-15-4-w, y + h/2, desc);
	}
	/* minor ticks */
	if (axis->minor) {
		double minor_tick = axis->minor * g->zoom.y;
 		imin = (g->geom.height - offset + corr - g->wp.height)/minor_tick + 1;
		imax = (g->geom.height - offset + corr) / minor_tick;
		for (i=imin; i <= imax; i++) {
			int y = g->geom.height-1 - (int )rint (i*minor_tick) -
							offset + corr + axis->s.y;

			debug (DBS_AXES_DRAWING) printf ("%f @ %d\n", i*axis->minor+fl, y);
			if (y > 0 && y < axis->p.height)
				gdk_draw_line (axis->pixmap[not_disp], g->fg_gc,
							axis->s.width - 8, y, axis->s.width - 1, y);
		}
	}
	for (i=0; axis->label[i]; i++) {
		gint w, h;
		w = gdk_string_width (g->font, axis->label[i]);
		h = gdk_string_height (g->font, axis->label[i]);
		gdk_draw_string (axis->pixmap[not_disp], g->font, g->fg_gc,
					(axis->p.width - w)/2 , TITLEBAR_HEIGHT-15 - i*(h+3),
					axis->label[i]);
	}
}

static void h_axis_pixmap_draw (struct axis *axis)
{
	struct graph *g = axis->g;
	int i;
	double major_tick, minor_tick;
	int not_disp, rdigits, offset, imin, imax;
	double left, right, j, fl, corr;

	debug(DBS_FENTRY) puts ("h_axis_pixmap_draw()");
	left = (g->wp.x-g->geom.x) /
					(double )g->geom.width * g->bounds.width;
	left += axis->min;
	right = (g->wp.x-g->geom.x+g->wp.width) /
					(double )g->geom.width * g->bounds.width;
	right += axis->min;
	axis_compute_ticks (axis, left, right, AXIS_HORIZONTAL);

	j = axis->major - floor (axis->major);
	for (rdigits=0; rdigits<=6; rdigits++) {
		j *= 10;
		if (j<=0.000001)
			break;
		j = j - floor (j);
	}

	not_disp = 1 ^ axis->displayed;
	gdk_draw_rectangle (axis->pixmap[not_disp], g->bg_gc, TRUE, 0, 0,
					axis->p.width, axis->p.height);
	/* axis */
	gdk_draw_line (axis->pixmap[not_disp], g->fg_gc, 0, 0,	
						axis->s.width + (axis->p.width-axis->s.width)/2.0, 0);
	offset = g->wp.x - g->geom.x;

	fl = floor (axis->min / axis->major) * axis->major;
	corr = rint ((axis->min - fl) * g->zoom.x);

	/* major ticks */
	major_tick = axis->major*g->zoom.x;
	imin = (offset + corr) / major_tick + 1;
	imax = (offset + corr + axis->s.width) / major_tick;
	for (i=imin; i <= imax; i++) {
		char desc[32];
		int w, h;
		int x = (int )rint (i * major_tick) - offset - corr;

		/* printf ("%f @ %d\n", i*axis->major + fl, x); */
		if (x < 0 || x > axis->s.width)
			continue;
		gdk_draw_line (axis->pixmap[not_disp], g->fg_gc, x, 0, x, 15);
		snprintf (desc, 32, "%.*f", rdigits, i*axis->major + fl);
		w = gdk_string_width (g->font, desc);
		h = gdk_string_height (g->font, desc);
		gdk_draw_string (axis->pixmap[not_disp], g->font, g->fg_gc,
						x - w/2, 15+h+4, desc);
	}
	if (axis->minor > 0) {
		/* minor ticks */
		minor_tick = axis->minor*g->zoom.x;
		imin = (offset + corr) / minor_tick + 1;
		imax = (offset + corr + g->wp.width) / minor_tick;
		for (i=imin; i <= imax; i++) {
			int x = (int )rint (i * minor_tick) - offset - corr;
			if (x > 0 && x < axis->s.width)
				gdk_draw_line (axis->pixmap[not_disp], g->fg_gc, x, 0, x, 8);
		}
	}
	for (i=0; axis->label[i]; i++) {
		gint w, h;
		w = gdk_string_width (g->font, axis->label[i]);
		h = gdk_string_height (g->font, axis->label[i]);
		gdk_draw_string (axis->pixmap[not_disp], g->font, g->fg_gc,
					axis->s.width - w - 50, 15+2*h+15 + i*(h+3),
					axis->label[i]);
	}
}

static void axis_pixmaps_switch (struct axis *axis)
{
	axis->displayed = 1 ^ axis->displayed;
}

static void axis_pixmap_display (struct axis *axis)
{
	gdk_draw_pixmap (axis->drawing_area->window, axis->g->fg_gc,
			axis->pixmap[axis->displayed], 0, 0, axis->p.x, axis->p.y,
			axis->p.width, axis->p.height);
}

static void axis_compute_ticks (struct axis *axis, double x0, double xmax, int dir)
{
	int i, j, ii, jj, ms;
	double zoom, x, steps[3]={ 0.1, 0.5 };
	int dim, check_needed, diminished;
	double majthresh[2]={2.0, 3.0};

	debug((DBS_FENTRY | DBS_AXES_TICKS)) puts ("axis_compute_ticks()");
	debug(DBS_AXES_TICKS)
		printf ("x0=%f xmax=%f dir=%s\n", x0,xmax, dir?"VERTICAL":"HORIZONTAL");

	zoom = axis_zoom_get (axis, dir);
	x = xmax-x0;
	for (i=-9; i<=12; i++) {
		if (x / pow (10, i) < 1)
			break;
	}
	--i;
	ms = (int )(x / pow (10, i));

	if (ms > 5) {
		j = 0;
		++i;
	} else if (ms > 2)
		j = 1;
	else
		j = 0;

	axis->major = steps[j] * pow (10, i);

	debug(DBS_AXES_TICKS) printf ("zoom=%.1f, x=%f -> i=%d -> ms=%d -> j=%d ->"
			" axis->major=%f\n", zoom, x, i, ms, j, axis->major);

	/* let's compute minor ticks */
	jj = j;
	ii = i;
	axis_ticks_down (&ii, &jj);
	axis->minor = steps[jj] * pow (10, ii);
	/* we don't want minors if they would be less than 10 pixels apart */
	if (axis->minor*zoom < 10) {
		debug(DBS_AXES_TICKS) printf ("refusing axis->minor of %f: "
					"axis->minor*zoom == %f\n", axis->minor, axis->minor*zoom);
		axis->minor = 0;
	}

	check_needed = TRUE;
	diminished = FALSE;
	while (check_needed) {
		check_needed = FALSE;
		dim = get_label_dim (axis, dir, xmax);
		debug(DBS_AXES_TICKS) printf ("axis->major==%.1f, axis->minor==%.1f =>"
				" axis->major*zoom/dim==%f, axis->minor*zoom/dim==%f\n",
				axis->major, axis->minor, axis->major*zoom/dim,
				axis->minor*zoom/dim);

		/* corrections: if majors are less than majthresh[dir] times label
	 	* dimension apart, we need to use bigger ones */
		if (axis->major*zoom / dim < majthresh[dir]) {
			axis_ticks_up (&ii, &jj);
			axis->minor = axis->major;
			axis_ticks_up (&i, &j);
			axis->major = steps[j] * pow (10, i);
			check_needed = TRUE;
			debug(DBS_AXES_TICKS) printf ("axis->major enlarged to %.1f\n",
										axis->major);
		}
		/* if minor ticks are bigger than majthresh[dir] times label dimension,
		 * we could  promote them to majors as well */
		if (axis->minor*zoom / dim > majthresh[dir] && !diminished) {
			axis_ticks_down (&i, &j);
			axis->major = axis->minor;
			axis_ticks_down (&ii, &jj);
			axis->minor = steps[jj] * pow (10, ii);
			check_needed = TRUE;
			diminished = TRUE;
	
			debug(DBS_AXES_TICKS) printf ("axis->minor diminished to %.1f\n",
										axis->minor);
	
			if (axis->minor*zoom < 10) {
				debug(DBS_AXES_TICKS) printf ("refusing axis->minor of %f: "
					"axis->minor*zoom == %f\n", axis->minor, axis->minor*zoom);
				axis->minor = 0;
			}
		}
	}

	debug(DBS_AXES_TICKS) printf ("corrected: axis->major == %.1f -> "
							"axis->minor == %.1f\n", axis->major, axis->minor);
}

static void axis_ticks_up (int *i, int *j)
{
	(*j)++;
	if (*j>1) {
		(*i)++;
		*j=0;
	}
}

static void axis_ticks_down (int *i, int *j)
{
	(*j)--;
	if (*j<0) {
		(*i)--;
		*j=1;
	}
}

static int get_label_dim (struct axis *axis, int dir, double label)
{
	double y;
	char str[32];
	int rdigits, dim;

	 /* First, let's compute how many digits to the right of radix
	 * we need to print */
	y = axis->major - floor (axis->major);
	for (rdigits=0; rdigits<=6; rdigits++) {
		y *= 10;
		if (y<=0.000001)
			break;
		y = y - floor (y);
	}
	snprintf (str, 32, "%.*f", rdigits, label);
	switch (dir) {
	case AXIS_HORIZONTAL:
		dim = gdk_string_width (axis->g->font, str);
		break;
	case AXIS_VERTICAL:
		dim = gdk_string_height (axis->g->font, str);
		break;
	default:
		puts ("initialize axis: an axis must be either horizontal or vertical");
		return -1;
		break;
	}
	return dim;
}

static double axis_zoom_get (struct axis *axis, int dir)
{
	switch (dir) {
	case AXIS_HORIZONTAL:
		return axis->g->zoom.x;
		break;
	case AXIS_VERTICAL:
		return axis->g->zoom.y;
		break;
	default:
		return -1;
		break;
	}
}

static void graph_select_segment (struct graph *g, int x, int y)
{
	struct element_list *list;
	struct element *e;

	debug(DBS_FENTRY) puts ("graph_select_segment()");

	x -= g->geom.x;
	y = g->geom.height-1 - (y - g->geom.y);

	for (list=g->elists; list; list=list->next)
		for (e=list->elements; e->type != ELMT_NONE; e++) {
			switch (e->type) {
			case ELMT_RECT:
				break;
			case ELMT_LINE:
				if (line_detect_collision (e, x, y)) {
					int row = e->parent->num - 1;
					update_packet_list (row);
				}
				break;
			case ELMT_ARC:
				if (arc_detect_collision (e, x, y)) {
					int row = e->parent->num - 1;
					update_packet_list (row);
				}
				break;
			default:
				break;
			}
		}
}

static int line_detect_collision (struct element *e, int x, int y)
{
	int x1, y1, x2, y2;

	if (e->p.line.dim.x1 < e->p.line.dim.x2) {
		x1 = (int )rint (e->p.line.dim.x1);
		x2 = (int )rint (e->p.line.dim.x2);
	} else {
		x1 = (int )rint (e->p.line.dim.x2);
		x2 = (int )rint (e->p.line.dim.x1);
	}
	if (e->p.line.dim.y1 < e->p.line.dim.y2) {
		y1 = (int )rint (e->p.line.dim.y1);
		y2 = (int )rint (e->p.line.dim.y2);
	} else {
		y1 = (int )rint (e->p.line.dim.y2);
		y2 = (int )rint (e->p.line.dim.y1);
	}
	/*
	printf ("line: (%d,%d)->(%d,%d), clicked: (%d,%d)\n", x1, y1, x2, y2, x, y);
	 */
	if ((x1==x && x2==x && y1<=y && y<=y2)||(y1==y && y2==y && x1<=x && x<=x2))
		return TRUE;
	else
		return FALSE;
}

static int arc_detect_collision (struct element *e, int x, int y)
{
	int x1, y1, x2, y2;

	x1 = (int )rint (e->p.arc.dim.x);
	x2 = (int )rint (e->p.arc.dim.x + e->p.arc.dim.width);
	y1 = (int )rint (e->p.arc.dim.y - e->p.arc.dim.height);
	y2 = (int )rint (e->p.arc.dim.y);
	/*
	printf ("arc: (%d,%d)->(%d,%d), clicked: (%d,%d)\n", x1, y1, x2, y2, x, y);
	 */
	if (x1<=x && x<=x2 && y1<=y && y<=y2)
		return TRUE;
	else
		return FALSE;
}

static void update_packet_list (int row)
{
	select_packet (&cfile, row);
	if (gtk_clist_row_is_visible(GTK_CLIST(packet_list), row) !=
				GTK_VISIBILITY_FULL)
		gtk_clist_moveto(GTK_CLIST(packet_list), row, -1, 0.5, 0.5);
	GTK_CLIST(packet_list)->focus_row = row;
	gtk_clist_select_row(GTK_CLIST(packet_list), row, -1);
}

static void cross_xor (struct graph *g, int x, int y)
{
	if (x > g->wp.x && x < g->wp.x+g->wp.width &&
				y >= g->wp.y && y < g->wp.y+g->wp.height) {
		gdk_draw_line (g->drawing_area->window, xor_gc, g->wp.x,
						y, g->wp.x + g->wp.width, y);
		gdk_draw_line (g->drawing_area->window, xor_gc, x,
						g->wp.y, x, g->wp.y + g->wp.height);
	}
}

static void cross_draw (struct graph *g, int x, int y)
{
	cross_xor (g, x, y);
	g->cross.x = x;
	g->cross.y = y;
	g->cross.erase_needed = 1;
}

static void cross_erase (struct graph *g)
{
	cross_xor (g, g->cross.x, g->cross.y);
	g->cross.erase_needed = 0;
}

static void magnify_create (struct graph *g, int x, int y)
{
	struct graph *mg;
	struct element_list *list, *new_list;
	struct ipoint pos, offsetpos;
	GdkEvent *e=NULL;

	mg = g->magnify.g = (struct graph * )malloc (sizeof (struct graph));
	memcpy ((void * )mg, (void * )g, sizeof (struct graph));

	mg->toplevel = gtk_window_new (GTK_WINDOW_POPUP);
	gtk_signal_connect (GTK_OBJECT (mg->toplevel), "realize",
		GTK_SIGNAL_FUNC (window_icon_realize_cb), NULL);
	mg->drawing_area = mg->toplevel;
	gtk_widget_set_usize (mg->toplevel, g->magnify.width, g->magnify.height);
	gtk_widget_set_events (mg->drawing_area, GDK_EXPOSURE_MASK
			/*		| GDK_ENTER_NOTIFY_MASK	*/
			/*		| GDK_ALL_EVENTS_MASK	*/
					);

	mg->wp.x = 0;
	mg->wp.y = 0;
	mg->wp.width = g->magnify.width;
	mg->wp.height = g->magnify.height;
	mg->geom.width = (int )rint (g->geom.width * g->magnify.zoom.x);
	mg->geom.height = (int )rint (g->geom.height * g->magnify.zoom.y);
	mg->zoom.x = (mg->geom.width - 1) / g->bounds.width;
	mg->zoom.y = (mg->geom.height- 1) / g->bounds.height;

	/* in order to keep original element lists intact we need our own */
	graph_element_lists_initialize (mg);
	list = g->elists->next;
	new_list = mg->elists;
	for ( ; list; list=list->next) {
		new_list->next =
				(struct element_list * )malloc (sizeof (struct element_list));
		new_list = new_list->next;
		new_list->next = NULL;
		new_list->elements = NULL;
	}
	graph_element_lists_make (mg);

	gdk_window_get_position (GTK_WIDGET (g->toplevel)->window, &pos.x, &pos.y);
	g->magnify.x = pos.x + x - g->magnify.width/2;
	g->magnify.y = pos.y + y - g->magnify.height/2;
	offsetpos.x = g->magnify.x + g->magnify.offset.x;
	offsetpos.x = offsetpos.x >= 0 ? offsetpos.x : 0;
	offsetpos.y = g->magnify.y + g->magnify.offset.y;
	offsetpos.y = offsetpos.y >= 0 ? offsetpos.y : 0;
	gtk_widget_set_uposition (mg->drawing_area, offsetpos.x, offsetpos.y);
	magnify_get_geom (g, x, y);

	gtk_widget_show (mg->drawing_area);

	/* we need to wait for the first expose event before we start drawing */
	while (!gdk_events_pending ());
	do {
		e = gdk_event_get ();
		if (e) {
			if (e->any.type == GDK_EXPOSE) {
				gdk_event_free (e);
				break;
			}
			gdk_event_free (e);
		}
	} while (e);

	mg->pixmap[0] = mg->pixmap[1] = NULL;
	graph_pixmaps_create (mg);
	magnify_draw (g);
	g->magnify.active = 1;
}

static void magnify_move (struct graph *g, int x, int y)
{
	struct ipoint pos, offsetpos;

	gdk_window_get_position (GTK_WIDGET (g->toplevel)->window, &pos.x, &pos.y);
	g->magnify.x = pos.x + x - g->magnify.width/2;
	g->magnify.y = pos.y + y - g->magnify.height/2;
	offsetpos.x = g->magnify.x + g->magnify.offset.x;
	offsetpos.x = offsetpos.x >= 0 ? offsetpos.x : 0;
	offsetpos.y = g->magnify.y + g->magnify.offset.y;
	offsetpos.y = offsetpos.y >= 0 ? offsetpos.y : 0;
	magnify_get_geom (g, x, y);
	gtk_widget_set_uposition (g->magnify.g->drawing_area, offsetpos.x,
								offsetpos.y);
	magnify_draw (g);
}

static void magnify_destroy (struct graph *g)
{
	struct element_list *list;
	struct graph *mg = g->magnify.g;

	gtk_widget_destroy (GTK_WIDGET (mg->drawing_area));
	gdk_pixmap_unref (mg->pixmap[0]);
	gdk_pixmap_unref (mg->pixmap[1]);
	for (list=mg->elists; list; list=list->next)
		free (list->elements);
	while (mg->elists->next) {
		list = mg->elists->next->next;
		free (mg->elists->next);
		mg->elists->next = list;
	}
	free (g->magnify.g);
	g->magnify.active = 0;
}

static void magnify_get_geom (struct graph *g, int x, int y)
{
	int posx, posy;

	gdk_window_get_position (GTK_WIDGET (g->toplevel)->window, &posx, &posy);

	g->magnify.g->geom.x = g->geom.x;
	g->magnify.g->geom.y = g->geom.y;

	g->magnify.g->geom.x -=
				(int )rint ((g->magnify.g->geom.width - g->geom.width) *
				((x-g->geom.x)/(double )g->geom.width));
	g->magnify.g->geom.y -=
				(int )rint ((g->magnify.g->geom.height - g->geom.height) *
				((y-g->geom.y)/(double )g->geom.height));

	/* we have coords of origin of graph relative to origin of g->toplevel.
	 * now we need them to relate to origin of magnify window */
	g->magnify.g->geom.x -= (g->magnify.x - posx);
	g->magnify.g->geom.y -= (g->magnify.y - posy);
}

static void magnify_draw (struct graph *g)
{
	int not_disp = 1 ^ g->magnify.g->displayed;

	graph_pixmap_draw (g->magnify.g);
	/* graph pixmap is almost ready, just add border */
	gdk_draw_line (g->magnify.g->pixmap[not_disp], g->fg_gc, 0, 0,
						g->magnify.width - 1, 0);
	gdk_draw_line (g->magnify.g->pixmap[not_disp], g->fg_gc,
			g->magnify.width - 1, 0, g->magnify.width - 1, g->magnify.height);
	gdk_draw_line (g->magnify.g->pixmap[not_disp], g->fg_gc, 0, 0,
						0, g->magnify.height - 1);
	gdk_draw_line (g->magnify.g->pixmap[not_disp], g->fg_gc, 0,
			g->magnify.height - 1, g->magnify.width - 1, g->magnify.height - 1);

	graph_pixmaps_switch (g->magnify.g);
	graph_pixmap_display (g->magnify.g);

}

static gint configure_event (GtkWidget *widget, GdkEventConfigure *event)
{
	struct graph *g;
	struct {
		double x, y;
	} zoom;
	int cur_g_width, cur_g_height;
	int cur_wp_width, cur_wp_height;

	debug(DBS_FENTRY) puts ("configure_event()");

	for (g=graphs; g; g=g->next)
		if (g->drawing_area == widget)
			break;

	cur_wp_width = g->wp.width;
	cur_wp_height = g->wp.height;
	g->wp.width = event->width - g->y_axis->p.width - RMARGIN_WIDTH;
	g->wp.height = event->height - g->x_axis->p.height - g->wp.y;
	g->x_axis->s.width = g->wp.width;
	g->x_axis->p.width = g->wp.width + RMARGIN_WIDTH;
	g->y_axis->p.height = g->wp.height + g->wp.y;
	g->y_axis->s.height = g->wp.height;
	g->x_axis->p.y = g->y_axis->p.height;
	zoom.x = (double )g->wp.width / cur_wp_width;
	zoom.y = (double )g->wp.height / cur_wp_height;
	cur_g_width = g->geom.width;
	cur_g_height = g->geom.height;
	g->geom.width = (int )rint (g->geom.width * zoom.x);
	g->geom.height = (int )rint (g->geom.height * zoom.y);
	g->zoom.x = (double )(g->geom.width - 1) / g->bounds.width;
	g->zoom.y = (double )(g->geom.height -1) / g->bounds.height;
	/* g->zoom.initial.x = g->zoom.x; */
	/* g->zoom.initial.y = g->zoom.y; */

	g->geom.x = g->wp.x - (double )g->geom.width/cur_g_width *
							(g->wp.x - g->geom.x);
	g->geom.y = g->wp.y - (double )g->geom.height/cur_g_height *
							(g->wp.y - g->geom.y);
#if 0
	printf ("configure: graph: (%d,%d), (%d,%d); viewport: (%d,%d), (%d,%d); "
				"zooms: (%f,%f)\n", g->geom.x, g->geom.y, g->geom.width,
				g->geom.height, g->wp.x, g->wp.y, g->wp.width, g->wp.height,
				g->zoom.x, g->zoom.y);
#endif

	update_zoom_spins (g);
	graph_element_lists_make (g);
	graph_pixmaps_create (g);
	graph_title_pixmap_create (g);
	axis_pixmaps_create (g->y_axis);
	axis_pixmaps_create (g->x_axis);
	/* we don't do actual drawing here; we leave it to expose handler */
	graph_pixmap_draw (g);
	graph_pixmaps_switch (g);
	graph_title_pixmap_draw (g);
	h_axis_pixmap_draw (g->x_axis);
	axis_pixmaps_switch (g->x_axis);
	v_axis_pixmap_draw (g->y_axis);
	axis_pixmaps_switch (g->y_axis);
	return TRUE;
}

static gint expose_event (GtkWidget *widget, GdkEventExpose *event)
{
	struct graph *g;

	debug(DBS_FENTRY) puts ("expose_event()");

	if (event->count)
		return TRUE;

	for (g=graphs; g; g=g->next)
		if (g->drawing_area == widget)
			break;

	/* lower left corner */
	gdk_draw_rectangle (g->drawing_area->window, g->bg_gc, TRUE, 0,
			g->wp.y + g->wp.height, g->y_axis->p.width, g->x_axis->p.height);
	/* right margin */
	gdk_draw_rectangle (g->drawing_area->window, g->bg_gc, TRUE,
			g->wp.x + g->wp.width, g->wp.y, RMARGIN_WIDTH, g->wp.height);

	graph_pixmap_display (g);
	graph_title_pixmap_display (g);
	axis_pixmap_display (g->x_axis);
	axis_pixmap_display (g->y_axis);

	return TRUE;
}

static gint button_press_event (GtkWidget *widget, GdkEventButton *event)
{
	struct graph *g;

	debug(DBS_FENTRY) puts ("button_press_event()");

	for (g=graphs; g; g=g->next)
		if (g->drawing_area == widget)
			break;

	if (event->button == 3) {
		if (event->state & GDK_CONTROL_MASK)
			magnify_create (g, (int )rint (event->x), (int )rint (event->y));
		else {
			g->grab.x = (int )rint (event->x) - g->geom.x;
			g->grab.y = (int )rint (event->y) - g->geom.y;
			g->grab.grabbed = TRUE;
		}
#ifdef WIN32
				/* Windows mouse control:        */
				/* [<ctrl>-left] - select packet */
				/* [left] - zoom in              */
				/* [<shift>-left] - zoom out     */
	} else if (event->button == 1) {
		if (event->state & GDK_CONTROL_MASK) {
			graph_select_segment (g, (int)event->x, (int)event->y);
		} else {
#else /* WIN32 */
	} else if (event->button == 2) {
#endif
		int cur_width = g->geom.width, cur_height = g->geom.height;
		struct { double x, y; } factor;

		if (g->zoom.flags & ZOOM_OUT) {
			if (g->zoom.flags & ZOOM_HLOCK)
				factor.x = 1.0;
			else
				factor.x = 1 / g->zoom.step_x;
			if (g->zoom.flags & ZOOM_VLOCK)
				factor.y = 1.0;
			else
				factor.y = 1 / g->zoom.step_y;
		} else {
			if (g->zoom.flags & ZOOM_HLOCK)
				factor.x = 1.0;
			else
				factor.x = g->zoom.step_x;
			if (g->zoom.flags & ZOOM_VLOCK)
				factor.y = 1.0;
			else
				factor.y = g->zoom.step_y;
		}

		g->geom.width = (int )rint (g->geom.width * factor.x);
		g->geom.height = (int )rint (g->geom.height * factor.y);
		if (g->geom.width < g->wp.width)
			g->geom.width = g->wp.width;
		if (g->geom.height < g->wp.height)
			g->geom.height = g->wp.height;
		g->zoom.x = (g->geom.width - 1) / g->bounds.width;
		g->zoom.y = (g->geom.height- 1) / g->bounds.height;

		g->geom.x -= (int )rint ((g->geom.width - cur_width) *
						((event->x-g->geom.x)/(double )cur_width));
		g->geom.y -= (int )rint ((g->geom.height - cur_height) *
						((event->y-g->geom.y)/(double )cur_height));

		if (g->geom.x > g->wp.x)
			g->geom.x = g->wp.x;
		if (g->geom.y > g->wp.y)
			g->geom.y = g->wp.y;
		if (g->wp.x + g->wp.width > g->geom.x + g->geom.width)
			g->geom.x = g->wp.width + g->wp.x - g->geom.width;
		if (g->wp.y + g->wp.height > g->geom.y + g->geom.height)
			g->geom.y = g->wp.height + g->wp.y - g->geom.height;
#if 0
		printf ("button press: graph: (%d,%d), (%d,%d); viewport: (%d,%d), "
				"(%d,%d); zooms: (%f,%f)\n", g->geom.x, g->geom.y,
				g->geom.width, g->geom.height, g->wp.x, g->wp.y, g->wp.width,
				g->wp.height, g->zoom.x, g->zoom.y);
#endif
		graph_element_lists_make (g);
		graph_display (g);
		axis_display (g->y_axis);
		axis_display (g->x_axis);
		update_zoom_spins (g);
		if (g->cross.draw)
			cross_draw (g, event->x, event->y);
#ifndef WIN32
	} else if (event->button == 1) {
		graph_select_segment (g, (int )event->x, (int )event->y);
#else /* WIN32 */
		}
#endif
	}
	return TRUE;
}

static gint motion_notify_event (GtkWidget *widget, GdkEventMotion *event)
{
	struct graph *g;
	int x, y;
	GdkModifierType state;

	/* debug(DBS_FENTRY) puts ("motion_notify_event()"); */

	for (g=graphs; g; g=g->next)
		if (g->drawing_area == widget)
			break;

	if (event->is_hint)
		gdk_window_get_pointer (event->window, &x, &y, &state);
	else {
		x = event->x;
		y = event->y;
		state = event->state;
	}
    
	/* Testing just (state & GDK_BUTTON1_MASK) is not enough since when button1
	 * is pressed while pointer is in motion, we will receive one more motion
	 * notify *before* we get the button press. This last motion notify works
	 * with stale grab coordinates */
	if (state & GDK_BUTTON3_MASK) {
		if (g->grab.grabbed) {
			g->geom.x = x-g->grab.x;
			g->geom.y = y-g->grab.y;

			if (g->geom.x > g->wp.x)
				g->geom.x = g->wp.x;
			if (g->geom.y > g->wp.y)
				g->geom.y = g->wp.y;
			if (g->wp.x + g->wp.width > g->geom.x + g->geom.width)
				g->geom.x = g->wp.width + g->wp.x - g->geom.width;
			if (g->wp.y + g->wp.height > g->geom.y + g->geom.height)
				g->geom.y = g->wp.height + g->wp.y - g->geom.height;
			graph_display (g);
			axis_display (g->y_axis);
			axis_display (g->x_axis);
			if (g->cross.draw)
				cross_draw (g, x, y);
		} else if (g->magnify.active)
			magnify_move (g, x, y);
	} else if (state & GDK_BUTTON1_MASK) {
		graph_select_segment (g, x, y);
		if (g->cross.erase_needed)
			cross_erase (g);
		if (g->cross.draw)
			cross_draw (g, x, y);
	} else {
		if (g->cross.erase_needed)
			cross_erase (g);
		if (g->cross.draw)
			cross_draw (g, x, y);
	}
  
	return TRUE;
}

static gint button_release_event (GtkWidget *widget, GdkEventButton *event)
{
	struct graph *g;

	debug(DBS_FENTRY) puts ("button_release_event()");

	for (g=graphs; g; g=g->next)
		if (g->drawing_area == widget)
			break;

	if (event->button == 3)
		g->grab.grabbed = FALSE;

	if (g->magnify.active)
		magnify_destroy (g);
	return TRUE;
}

static gint key_press_event (GtkWidget *widget, GdkEventKey *event)
{
	struct graph *g;

	debug(DBS_FENTRY) puts ("key_press_event()");

	for (g=graphs; g; g=g->next)
		if (g->toplevel == widget)
			break;

	if (event->keyval == 32 /*space*/) {
		g->cross.draw ^= 1;
#if 0
		if (g->cross.draw) {
			int x, y;
			gdk_window_get_pointer (g->drawing_area->window, &x, &y, 0);
			cross_draw (g);
		} else if (g->cross.erase_needed) {
			cross_erase (g);
		}
#endif
		/* toggle buttons emit their "toggled" signals so don't bother doing
		 * any real work here, it will be done in signal handlers */
		if (g->cross.draw)
			gtk_toggle_button_set_active (g->cross.on_toggle, TRUE);
		else
			gtk_toggle_button_set_active (g->cross.off_toggle, TRUE);
	} else if (event->keyval == 't')
		toggle_time_origin (g);
	else if (event->keyval == 's')
		toggle_seq_origin (g);
	else if (event->keyval == GDK_Shift_L) {
		/* g->zoom.flags |= ZOOM_OUT; */
		gtk_toggle_button_set_active (g->zoom.widget.out_toggle, TRUE);
	}
	return TRUE;
}

static gint key_release_event (GtkWidget *widget, GdkEventKey *event)
{
	struct graph *g;

	debug(DBS_FENTRY) puts ("key_release_event()");

	for (g=graphs; g; g=g->next)
		if (g->toplevel == widget)
			break;

	if (event->keyval == GDK_Shift_L || event->keyval == GDK_ISO_Prev_Group) {
		/* g->zoom.flags &= ~ZOOM_OUT; */
		gtk_toggle_button_set_active (g->zoom.widget.in_toggle, TRUE);
	}
	return TRUE;
}

static gint leave_notify_event (GtkWidget *widget, GdkEventCrossing *event)
{
	struct graph *g;

	for (g=graphs; g; g=g->next)
		if (g->drawing_area == widget)
			break;

	if (g->cross.erase_needed)
		cross_erase (g);

	return TRUE;
}

static gint enter_notify_event (GtkWidget *widget, GdkEventCrossing *event)
{
	struct graph *g;

	for (g=graphs; g; g=g->next)
		if (g->drawing_area == widget)
			break;

	/* graph_pixmap_display (g); */
	if (g->cross.draw) {
		int x, y;
		gdk_window_get_pointer (g->drawing_area->window, &x, &y, 0);
		cross_draw (g, x, y);
	}
	return TRUE;
}

static void toggle_time_origin (struct graph *g)
{
	switch (g->type) {
	case GRAPH_TSEQ_STEVENS:
		tseq_stevens_toggle_time_origin (g);
		break;
	case GRAPH_TSEQ_TCPTRACE:
		tseq_tcptrace_toggle_time_origin (g);
		break;
	case GRAPH_THROUGHPUT:
		tput_toggle_time_origin (g);
		break;
	default:
		break;
	}
	axis_display (g->x_axis);
}

static void toggle_seq_origin (struct graph *g)
{
	switch (g->type) {
	case GRAPH_TSEQ_STEVENS:
		tseq_stevens_toggle_seq_origin (g);
		axis_display (g->y_axis);
		break;
	case GRAPH_TSEQ_TCPTRACE:
		tseq_tcptrace_toggle_seq_origin (g);
		axis_display (g->y_axis);
		break;
	case GRAPH_RTT:
		rtt_toggle_seq_origin (g);
		axis_display (g->x_axis);
		break;
	default:
		break;
	}
}

static int get_num_dsegs (struct graph *g)
{
	int count;
	struct segment *tmp;

	for (tmp=g->segments, count=0; tmp; tmp=tmp->next) {
		if (compare_headers (g->current, tmp, COMPARE_CURR_DIR)) {
			count++;
		}
	}
	return count;
}

static int get_num_acks (struct graph *g)
{
	int count;
	struct segment *tmp;

	for (tmp=g->segments, count=0; tmp; tmp=tmp->next) {
		if (!compare_headers (g->current, tmp, COMPARE_CURR_DIR)) {
			count++;
		}
	}
	return count;
}

/*
 * Stevens-style time-sequence grapH
 */

static void tseq_stevens_read_config (struct graph *g)
{
	debug(DBS_FENTRY) puts ("tseq_stevens_read_config()");

	g->s.tseq_stevens.seq_width = 4;
	g->s.tseq_stevens.seq_height = 4;
	g->s.tseq_stevens.flags = 0;

	g->title = (char ** )malloc (2 * sizeof (char *));
	g->title[0] = "Time/Sequence Graph";
	g->title[1] = NULL;
	g->y_axis->label = (char ** )malloc (3 * sizeof (char * ));
	g->y_axis->label[0] = "number[B]";
	g->y_axis->label[1] = "Sequence";
	g->y_axis->label[2] = NULL;
	g->x_axis->label = (char ** )malloc (2 * sizeof (char * ));
	g->x_axis->label[0] = "Time[s]";
	g->x_axis->label[1] = NULL;
}

static void tseq_stevens_initialize (struct graph *g)
{
	debug(DBS_FENTRY) puts ("tseq_stevens_initialize()");
	tseq_stevens_get_bounds (g);

	g->x_axis->min = 0;
	g->y_axis->min = 0;

	switch (g->type) {
	case GRAPH_TSEQ_STEVENS:
		tseq_stevens_read_config(g);
		break;
	case GRAPH_TSEQ_TCPTRACE:
		tseq_tcptrace_read_config(g);
		break;
	}
}

static void tseq_stevens_get_bounds (struct graph *g)
{
	struct segment *tmp, *last, *first;
	double t0, tmax, y0, ymax;

	for (first=g->segments; first->next; first=first->next) {
		if (compare_headers (g->current, first, COMPARE_CURR_DIR))
			break;
	}
	last = NULL;
	ymax = 0;
	for (tmp=g->segments; tmp; tmp=tmp->next) {
		unsigned int highest_byte_num;
		last = tmp;
		if (compare_headers (g->current, tmp, COMPARE_CURR_DIR))
			highest_byte_num = ntohl (tmp->tcphdr.seq) + tmp->data;
		else
			highest_byte_num = ntohl (tmp->tcphdr.ack_seq);
		if (highest_byte_num > ymax)
			ymax = highest_byte_num;
	}
	if (!last) {
		puts ("tseq_stevens_get_bounds: segment list corrupted!");
		return;
	}

	t0 = g->segments->rel_secs + g->segments->rel_usecs / 1000000.0;
	tmax = last->rel_secs + last->rel_usecs / 1000000.0;
	y0 = ntohl (first->tcphdr.seq);

	g->bounds.x0 = t0;
	g->bounds.y0 = y0;
	g->bounds.width = tmax - t0;
	g->bounds.height = ymax - y0;
	g->zoom.x = (g->geom.width - 1) / g->bounds.width;
	g->zoom.y = (g->geom.height -1) / g->bounds.height;
}

static void tseq_stevens_make_elmtlist (struct graph *g)
{
	struct segment *tmp;
	struct element *elements, *e;
	double x0 = g->bounds.x0, y0 = g->bounds.y0;

	debug(DBS_FENTRY) puts ("tseq_stevens_make_elmtlist()");
	if (g->elists->elements == NULL) {
		int n = 1 + get_num_dsegs (g);
		e = elements = (struct element * )malloc (n*sizeof (struct element));
	} else
		e = elements = g->elists->elements;

	for (tmp=g->segments; tmp; tmp=tmp->next) {
		double secs, seqno;

		if (!compare_headers (g->current, tmp, COMPARE_CURR_DIR))
			continue;

		secs = g->zoom.x * (tmp->rel_secs + tmp->rel_usecs / 1000000.0 - x0);
		seqno = g->zoom.y * (ntohl (tmp->tcphdr.seq) - y0);

		e->type = ELMT_ARC;
		e->parent = tmp;
		e->gc = g->fg_gc;
		e->p.arc.dim.width = g->s.tseq_stevens.seq_width;
		e->p.arc.dim.height = g->s.tseq_stevens.seq_height;
		e->p.arc.dim.x = secs - g->s.tseq_stevens.seq_width/2.0;
		e->p.arc.dim.y = seqno + g->s.tseq_stevens.seq_height/2.0;
		e->p.arc.filled = TRUE;
		e->p.arc.angle1 = 0;
		e->p.arc.angle2 = 23040;
		e++;
	}
	e->type = ELMT_NONE;
	g->elists->elements = elements;
}

static void tseq_stevens_toggle_seq_origin (struct graph *g)
{
	g->s.tseq_stevens.flags ^= SEQ_ORIGIN;

	if ((g->s.tseq_stevens.flags & SEQ_ORIGIN) == SEQ_ORIGIN_ZERO)
		g->y_axis->min = g->bounds.y0;
	else		/* g->tseq_stevens.flags & SEQ_ORIGIN == SEQ_ORIGIN_ISN */
		g->y_axis->min = 0;
}

static void tseq_stevens_toggle_time_origin (struct graph *g)
{
	g->s.tseq_stevens.flags ^= TIME_ORIGIN;

	if ((g->s.tseq_stevens.flags & TIME_ORIGIN) == TIME_ORIGIN_CAP)
		g->x_axis->min = g->bounds.x0;
	else		/* g->tseq_stevens.flags & TIME_ORIGIN == TIME_ORIGIN_CONN */
		g->x_axis->min = 0;
}

/*
 * tcptrace-style time-sequence graph
 */

static void tseq_tcptrace_read_config (struct graph *g)
{
	GdkColormap *colormap;
	GdkColor color;

	g->s.tseq_tcptrace.flags = 0;
	g->s.tseq_tcptrace.gc_seq = gdk_gc_new (g->drawing_area->window);
	g->s.tseq_tcptrace.gc_ack[0] = gdk_gc_new (g->drawing_area->window);
	g->s.tseq_tcptrace.gc_ack[1] = gdk_gc_new (g->drawing_area->window);
	colormap = gdk_window_get_colormap (g->drawing_area->window);
	gdk_color_parse ("black", &color);
	gdk_colormap_alloc_color (colormap, &color, FALSE, TRUE);
	gdk_gc_set_foreground (g->s.tseq_tcptrace.gc_seq, &color);
	gdk_color_parse ("LightSlateGray", &color);
	gdk_colormap_alloc_color (colormap, &color, FALSE, TRUE);
	gdk_gc_set_foreground (g->s.tseq_tcptrace.gc_ack[0], &color);
	gdk_color_parse ("LightGray", &color);
	gdk_colormap_alloc_color (colormap, &color, FALSE, TRUE);
	gdk_gc_set_foreground (g->s.tseq_tcptrace.gc_ack[1], &color);

	g->elists->next = (struct element_list * )
										malloc (sizeof (struct element_list));
	g->elists->next->next = NULL;
	g->elists->next->elements = NULL;

	g->title = (char ** )malloc (2 * sizeof (char *));
	g->title[0] = "Time/Sequence Graph";
	g->title[1] = NULL;
	g->y_axis->label = (char ** )malloc (3 * sizeof (char * ));
	g->y_axis->label[0] = "number[B]";
	g->y_axis->label[1] = "Sequence";
	g->y_axis->label[2] = NULL;
	g->x_axis->label = (char ** )malloc (2 * sizeof (char * ));
	g->x_axis->label[0] = "Time[s]";
	g->x_axis->label[1] = NULL;
}

static void tseq_tcptrace_make_elmtlist (struct graph *g)
{
	struct segment *tmp;
	struct element *elements0, *e0;		/* list of elmts with prio 0 */
	struct element *elements1, *e1;		/* list of elmts with prio 1 */
	double x0, y0;
	double p_t; /* ackno, window and time of previous segment */
	double p_ackno, p_win;
	int toggle=0;

	debug(DBS_FENTRY) puts ("tseq_tcptrace_make_elmtlist()");

	if (g->elists->elements == NULL) {
		int n = 1 + 4*get_num_acks(g);
		e0 = elements0 = (struct element * )malloc (n*sizeof (struct element));
	} else
		e0 = elements0 = g->elists->elements;

	if (g->elists->next->elements == NULL ) {
		int n = 1 + 3*get_num_dsegs(g);
		e1 = elements1 = (struct element * )malloc (n*sizeof (struct element));
	} else
		e1 = elements1 = g->elists->next->elements;

	x0 = g->bounds.x0;
	y0 = g->bounds.y0;
	/* initialize "previous" values */
	for (tmp=g->segments; tmp; tmp=tmp->next)
		if (!compare_headers (g->current, tmp, COMPARE_CURR_DIR))
			break;
	/*
	p_ackno = (unsigned int )(g->zoom.y * (ntohl (tmp->tcphdr.ack_seq) - y0));
	 */
	p_ackno = 0;
	p_win = g->zoom.y * ntohs (tmp->tcphdr.window);
	p_t = g->segments->rel_secs + g->segments->rel_usecs/1000000.0 - x0;
	for (tmp=g->segments; tmp; tmp=tmp->next) {
		double secs, seqno, data;
		double x;

		secs = tmp->rel_secs + tmp->rel_usecs / 1000000.0;
		x = secs - x0;
		x *= g->zoom.x;
		if (compare_headers (g->current, tmp, COMPARE_CURR_DIR)) {
			/* forward direction -> we need seqno and amount of data */
			double y1, y2;

			seqno = ntohl (tmp->tcphdr.seq);
			if (TCP_SYN (tmp->tcphdr))
				data = 1;
			else
				data = tmp->data;

			y1 = g->zoom.y * (seqno - y0);
			y2 = g->zoom.y * (seqno - y0 + data);
			e1->type = ELMT_LINE;
			e1->parent = tmp;
			e1->gc = g->s.tseq_tcptrace.gc_seq;
			e1->p.line.dim.x1 = e1->p.line.dim.x2 = x;
			e1->p.line.dim.y1 = y1;
			e1->p.line.dim.y2 = y2;
			e1++;
			e1->type = ELMT_LINE;
			e1->parent = tmp;
			e1->gc = g->s.tseq_tcptrace.gc_seq;
			e1->p.line.dim.x1 = x - 1;
			e1->p.line.dim.x2 = x + 1;
			e1->p.line.dim.y1 = e1->p.line.dim.y2 = y1;
			e1++;
			e1->type = ELMT_LINE;
			e1->parent = tmp;
			e1->gc = g->s.tseq_tcptrace.gc_seq;
			e1->p.line.dim.x1 = x + 1;
			e1->p.line.dim.x2 = x - 1;
			e1->p.line.dim.y1 = e1->p.line.dim.y2 = y2;
			e1++;
		} else {
			double ackno, win;
			if (TCP_SYN (tmp->tcphdr) && ! TCP_ACK (tmp->tcphdr))
				/* SYN's have ACK==0 and are useless here */
				continue;
			/* backward direction -> we need ackno and window */
			ackno = (ntohl (tmp->tcphdr.ack_seq) - y0) * g->zoom.y;
			win = ntohs (tmp->tcphdr.window) * g->zoom.y;

			/* ack line */
			e0->type = ELMT_LINE;
			e0->parent = tmp;
			e0->gc = g->s.tseq_tcptrace.gc_ack[toggle];
			e0->p.line.dim.x1 = p_t;
			e0->p.line.dim.y1 = p_ackno;
			e0->p.line.dim.x2 = x;
			e0->p.line.dim.y2 = p_ackno;
			e0++;
			e0->type = ELMT_LINE;
			e0->parent = tmp;
			e0->gc = g->s.tseq_tcptrace.gc_ack[toggle];
			e0->p.line.dim.x1 = x;
			e0->p.line.dim.y1 = p_ackno;
			e0->p.line.dim.x2 = x;
			e0->p.line.dim.y2 = ackno!=p_ackno || ackno<4 ? ackno : ackno-4;
			e0++;
			/* window line */
			e0->type = ELMT_LINE;
			e0->parent = tmp;
			e0->gc = g->s.tseq_tcptrace.gc_ack[toggle];
			e0->p.line.dim.x1 = p_t;
			e0->p.line.dim.y1 = p_win + p_ackno;
			e0->p.line.dim.x2 = x;
			e0->p.line.dim.y2 = p_win + p_ackno;
			e0++;
			e0->type = ELMT_LINE;
			e0->parent = tmp;
			e0->gc = g->s.tseq_tcptrace.gc_ack[toggle];
			e0->p.line.dim.x1 = x;
			e0->p.line.dim.y1 = p_win + p_ackno;
			e0->p.line.dim.x2 = x;
			e0->p.line.dim.y2 = win + ackno;
			e0++;
			p_ackno = ackno;
			p_win = win;
			p_t = x;
			toggle = 1^toggle;
		}
	}
	e0->type = ELMT_NONE;
	e1->type = ELMT_NONE;
	g->elists->elements = elements0;
	g->elists->next->elements = elements1;
}

static void tseq_tcptrace_toggle_seq_origin (struct graph *g)
{
	g->s.tseq_tcptrace.flags ^= SEQ_ORIGIN;

	if ((g->s.tseq_tcptrace.flags & SEQ_ORIGIN) == SEQ_ORIGIN_ZERO)
		g->y_axis->min = g->bounds.y0;
	else	/* g->tseq_stevens.flags & SEQ_ORIGIN == SEQ_ORIGIN_ISN */
		g->y_axis->min = 0;
}

static void tseq_tcptrace_toggle_time_origin (struct graph *g)
{
	g->s.tseq_tcptrace.flags ^= TIME_ORIGIN;

	if ((g->s.tseq_tcptrace.flags & TIME_ORIGIN) == TIME_ORIGIN_CAP)
		g->x_axis->min = g->bounds.x0;
	else	/* g->tseq_stevens.flags & TIME_ORIGIN == TIME_ORIGIN_CONN */
		g->x_axis->min = 0;
}

/*
 * throughput graph
 */

static void tput_make_elmtlist (struct graph *g)
{
	struct segment *tmp, *oldest;
	struct element *elements, *e;
	int i, sum=0;
	double dtime, tput;

	if (g->elists->elements == NULL) {
		int n = 1 + get_num_dsegs (g);
		e = elements = (struct element * )malloc (n*sizeof (struct element));
	} else
		e = elements = g->elists->elements;

	for (oldest=g->segments,tmp=g->segments->next,i=0; tmp; tmp=tmp->next,i++) {
		double time = tmp->rel_secs + tmp->rel_usecs/1000000.0;
		dtime = time - (oldest->rel_secs + oldest->rel_usecs/1000000.0);
		if (i>g->s.tput.nsegs) {
			sum -= oldest->data;
			oldest=oldest->next;
		}
		sum += tmp->data;
		tput = sum / dtime;
		/* debug(DBS_TPUT_ELMTS) printf ("tput=%f\n", tput); */

		e->type = ELMT_ARC;
		e->parent = tmp;
		e->gc = g->fg_gc;
		e->p.arc.dim.width = g->s.tput.width;
		e->p.arc.dim.height = g->s.tput.height;
		e->p.arc.dim.x = g->zoom.x*(time - g->bounds.x0) - g->s.tput.width/2.0;
		e->p.arc.dim.y = g->zoom.y*tput + g->s.tput.height/2.0;
		e->p.arc.filled = TRUE;
		e->p.arc.angle1 = 0;
		e->p.arc.angle2 = 23040;
		e++;
	}
	e->type = ELMT_NONE;
	g->elists->elements = elements;
}

/* Purpose of <graph_type>_initialize functions:
 * - find maximum and minimum for both axes
 * - call setup routine for style struct */
static void tput_initialize (struct graph *g)
{
	struct segment *tmp, *oldest, *last;
	int i, sum=0;
	double dtime, tput, tputmax=0;
	double t0, tmax, y0, ymax;

	debug(DBS_FENTRY) puts ("tput_initialize()");

	tput_read_config(g);

	for (last=g->segments; last->next; last=last->next);
	for (oldest=g->segments,tmp=g->segments->next,i=0; tmp; tmp=tmp->next,i++) {
		dtime = tmp->rel_secs + tmp->rel_usecs/1000000.0 -
						(oldest->rel_secs + oldest->rel_usecs/1000000.0);
		if (i>g->s.tput.nsegs) {
			sum -= oldest->data;
			oldest=oldest->next;
		}
		sum += tmp->data;
		tput = sum / dtime;
		debug(DBS_TPUT_ELMTS) printf ("tput=%f\n", tput);
		if (tput > tputmax)
			tputmax = tput;
	}

	t0 = g->segments->rel_secs + g->segments->rel_usecs / 1000000.0;
	tmax = last->rel_secs + last->rel_usecs / 1000000.0;
	y0 = 0;
	ymax = tputmax;

	g->bounds.x0 = t0;
	g->bounds.y0 = y0;
	g->bounds.width = tmax - t0;
	g->bounds.height = ymax - y0;
	g->zoom.x = (g->geom.width - 1) / g->bounds.width;
	g->zoom.y = (g->geom.height -1) / g->bounds.height;
}

static void tput_read_config (struct graph *g)
{
	debug(DBS_FENTRY) puts ("tput_read_config()");

	g->s.tput.width = 4;
	g->s.tput.height = 4;
	g->s.tput.nsegs = 20;

	g->title = (char ** )malloc (2 * sizeof (char *));
	g->title[0] = "Throughput Graph";
	g->title[1] = NULL;
	g->y_axis->label = (char ** )malloc (3 * sizeof (char * ));
	g->y_axis->label[0] = "[B/s]";
	g->y_axis->label[1] = "Throughput";
	g->y_axis->label[2] = NULL;
	g->x_axis->label = (char ** )malloc (2 * sizeof (char * ));
	g->x_axis->label[0] = "Time[s]";
	g->x_axis->label[1] = NULL;
	g->s.tput.flags = 0;
}

static void tput_toggle_time_origin (struct graph *g)
{
	g->s.tput.flags ^= TIME_ORIGIN;

	if ((g->s.tput.flags & TIME_ORIGIN) == TIME_ORIGIN_CAP)
		g->x_axis->min = g->bounds.x0;
	else 	/* g->s.tput.flags & TIME_ORIGIN == TIME_ORIGIN_CONN */
		g->x_axis->min = 0;
}

/* RTT graph */

static void rtt_read_config (struct graph *g)
{
	debug(DBS_FENTRY) puts ("rtt_read_config()");

	g->s.rtt.width = 4;
	g->s.rtt.height = 4;
	g->s.rtt.flags = 0;

	g->title = (char ** )malloc (2 * sizeof (char *));
	g->title[0] = "Round Trip Time Graph";
	g->title[1] = NULL;
	g->y_axis->label = (char ** )malloc (3 * sizeof (char * ));
	g->y_axis->label[0] = "RTT [s]";
	g->y_axis->label[1] = NULL;
	g->x_axis->label = (char ** )malloc (2 * sizeof (char * ));
	g->x_axis->label[0] = "Sequence Number[B]";
	g->x_axis->label[1] = NULL;
}

static void rtt_initialize (struct graph *g)
{
	struct segment *tmp, *first=NULL;
	struct unack *unack = NULL, *u;
	double rttmax=0;
	double x0, xmax=0, y0, ymax;

	debug(DBS_FENTRY) puts ("rtt_initialize()");

	rtt_read_config (g);

	for (tmp=g->segments; tmp; tmp=tmp->next) {
		if (compare_headers (g->current, tmp, COMPARE_CURR_DIR)) {
			unsigned int seqno = ntohl (tmp->tcphdr.seq);
			
			if (!first)
				first= tmp;

			if (tmp->data && !rtt_is_retrans (unack, seqno)) {
				double time = tmp->rel_secs + tmp->rel_usecs / 1000000.0;
				u = rtt_get_new_unack (time, seqno);
				if (!u) return;
				rtt_put_unack_on_list (&unack, u);
			}

			if (seqno + tmp->data > xmax)
				xmax = seqno + tmp->data;
		} else {
			unsigned int ackno = ntohl (tmp->tcphdr.ack_seq);
			double time = tmp->rel_secs + tmp->rel_usecs / 1000000.0;
			struct unack *v;

			for (u=unack; u; u=v)
				if (ackno > u->seqno) {
					double rtt = time - u->time;
					if (rtt > rttmax)
						rttmax = rtt;
					v=u->next;
					rtt_delete_unack_from_list (&unack, u);
				} else
					v=u->next;
		}
	}

	x0 = ntohl (first->tcphdr.seq);
	y0 = 0;
	ymax = rttmax;

	g->bounds.x0 = x0;
	g->bounds.y0 = y0;
	g->bounds.width = xmax - x0;
	g->bounds.height = ymax - y0;
	g->zoom.x = g->geom.width / g->bounds.width;
	g->zoom.y = g->geom.height / g->bounds.height;
}

static int rtt_is_retrans (struct unack *list, unsigned int seqno)
{
	struct unack *u;

	for (u=list; u; u=u->next)
		if (u->seqno == seqno)
			return TRUE;

	return FALSE;
}

static struct unack *rtt_get_new_unack (double time, unsigned int seqno)
{
	struct unack *u;

	u = (struct unack * )malloc (sizeof (struct unack));
	if (!u)
		return NULL;
	u->next = NULL;
	u->time = time;
	u->seqno = seqno;
	return u;
}

static void rtt_put_unack_on_list (struct unack **l, struct unack *new)
{
	struct unack *u, *list = *l;

	for (u=list; u; u=u->next)
		if (!u->next)
			break;

	if (u)
		u->next = new;
	else
		*l = new;
}

static void rtt_delete_unack_from_list (struct unack **l, struct unack *dead)
{
	struct unack *u, *list = *l;

	if (!dead || !list)
		return;

	if (dead==list) {
		*l = list->next;
		free (list);
	} else
		for (u=list; u; u=u->next)
			if (u->next == dead) {
				u->next = u->next->next;
				free (dead);
				break;
			}
}

static void rtt_make_elmtlist (struct graph *g)
{
	struct segment *tmp;
	struct unack *unack = NULL, *u;
	struct element *elements, *e;

	debug(DBS_FENTRY) puts ("rtt_make_elmtlist()");

	if (g->elists->elements == NULL) {
		int n = 1 + get_num_dsegs (g);
		e = elements = (struct element * )malloc (n*sizeof (struct element));
	} else
		e = elements = g->elists->elements;

	for (tmp=g->segments; tmp; tmp=tmp->next) {
		if (compare_headers (g->current, tmp, COMPARE_CURR_DIR)) {
			unsigned int seqno = ntohl (tmp->tcphdr.seq);

			if (tmp->data && !rtt_is_retrans (unack, seqno)) {
				double time = tmp->rel_secs + tmp->rel_usecs / 1000000.0;
				u = rtt_get_new_unack (time, seqno);
				if (!u) return;
				rtt_put_unack_on_list (&unack, u);
			}
		} else {
			unsigned int ackno = ntohl (tmp->tcphdr.ack_seq);
			double time = tmp->rel_secs + tmp->rel_usecs / 1000000.0;
			struct unack *v;

			for (u=unack; u; u=v)
				if (ackno > u->seqno) {
					double rtt = time - u->time;

					e->type = ELMT_ARC;
					e->parent = tmp;
					e->gc = g->fg_gc;
					e->p.arc.dim.width = g->s.rtt.width;
					e->p.arc.dim.height = g->s.rtt.height;
					e->p.arc.dim.x = g->zoom.x * (u->seqno - g->bounds.x0)
														- g->s.rtt.width/2.0;
					e->p.arc.dim.y = g->zoom.y * rtt + g->s.rtt.height/2.0;
					e->p.arc.filled = TRUE;
					e->p.arc.angle1 = 0;
					e->p.arc.angle2 = 23040;
					e++;

					v=u->next;
					rtt_delete_unack_from_list (&unack, u);
				} else
					v=u->next;
		}
	}
	e->type = ELMT_NONE;
	g->elists->elements = elements;
}

static void rtt_toggle_seq_origin (struct graph *g)
{
	g->s.rtt.flags ^= SEQ_ORIGIN;

	if ((g->s.rtt.flags & SEQ_ORIGIN) == SEQ_ORIGIN_ZERO)
		g->x_axis->min = g->bounds.x0;
	else
		g->x_axis->min = 0;
}

#ifdef WIN32
/* replacement of Unix rint() for Windows */
static int rint (double x)
{
	char *buf;
	int i,dec,sig;

	buf = _fcvt(x, 0, &dec, &sig);
	i = atoi(buf);
	if(sig == 1) {
		i = i * -1;
	}
	return(i);
}
#endif
