/*
 * Copyright (c) 1997, 1999 Hellmuth Michaelis. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *---------------------------------------------------------------------------
 *
 *	i4b_trace.h - header file for trace data read device
 *	----------------------------------------------------
 *
 *	$Id: i4b_trace.h,v 1.2 2001/07/13 00:55:58 guy Exp $ 
 *
 *      last edit-date: [Sun Feb 14 10:39:26 1999]
 *
 *---------------------------------------------------------------------------*/

#ifndef _I4B_TRACE_H_
#define _I4B_TRACE_H_

/*---------------------------------------------------------------------------*
 *	structure of the header at the beginning of every trace mbuf
 *---------------------------------------------------------------------------*/
typedef struct {
	unsigned int length;	/* length of the following mbuf		*/
	int unit;		/* controller unit number		*/
	int type;		/* type of channel			*/
#define TRC_CH_I	0		/* Layer 1 INFO's		*/
#define TRC_CH_D 	1		/* D channel 			*/
#define TRC_CH_B1	2		/* B1 channel			*/
#define TRC_CH_B2	3		/* B2 channel			*/
	int dir;		/* direction 				*/
#define FROM_TE	0			/* user -> network		*/
#define FROM_NT 1			/* network -> user		*/
	int trunc;		/* # of truncated bytes (frame > MCLBYTES) */
	unsigned int count;	/* frame count for this unit/type	*/
	struct timeval time;	/* timestamp for this frame		*/
} i4b_trace_hdr_t;

#define INFO0		0	/* layer 1 */
#define INFO1_8		1
#define INFO1_10	2
#define INFO2		3
#define INFO3		4
#define INFO4_8		5
#define INFO4_10	6

/*---------------------------------------------------------------------------*
 * 	ioctl via /dev/i4btrc device(s):
 *	get/set current trace flag settings
 *---------------------------------------------------------------------------*/
	
#define	I4B_TRC_GET	_IOR('T', 0, int)	/* get trace settings	*/
#define	I4B_TRC_SET	_IOW('T', 1, int)	/* set trace settings	*/

#define TRACE_OFF       0x00		/* tracing off 		*/
#define TRACE_I		0x01		/* trace L1 INFO's on	*/
#define TRACE_D_TX	0x02		/* trace D channel on	*/
#define TRACE_D_RX	0x04		/* trace D channel on	*/
#define TRACE_B_TX	0x08		/* trace B channel on	*/
#define TRACE_B_RX	0x10		/* trace B channel on	*/

typedef struct {
	int rxunit;		/* unit # for rx frames	*/
	int rxflags;		/* d and/or b channel	*/
	int txunit;		/* unit # for tx frames */
	int txflags;		/* d and/or b channel	*/
} i4b_trace_setupa_t;

#define	I4B_TRC_SETA	_IOW('T', 2, i4b_trace_setupa_t) /* set analyze mode */
#define	I4B_TRC_RESETA	_IOW('T', 3, int)	/* reset analyze mode	*/

#endif /* _I4B_TRACE_H_ */
