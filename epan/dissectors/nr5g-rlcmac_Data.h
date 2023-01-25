#ifndef nr5g_rlcmac_Data_DEFINED
#define nr5g_rlcmac_Data_DEFINED

//#include "lsu.h"
#include "nr5g.h"

#define nr5g_rlcmac_Data_VERSION   "0.1.0"

#pragma pack(1)

/*
 * This interface conforms to the rules specified in `lsu.h'.
 */

/*------------------------------------------------------------------*
 |  PRIMITIVES OPCODES                                              |
 *------------------------------------------------------------------*/

/*
 * AUX SAP
 */
/* Request for a Random Access (USER side only) */
#define nr5g_rlcmac_Data_RA_REQ		0x02

/* Confirm success or failure of a Random Access (USER side only) */
#define nr5g_rlcmac_Data_RA_CNF		0x202

/* Indicate a successful Random Access */
#define nr5g_rlcmac_Data_RA_IND		0x402

/* Indicate RLC Re-Establishment */
#define nr5g_rlcmac_Data_RE_EST_IND	0x403

/* Indicate end of RLC Re-Establishment */
#define nr5g_rlcmac_Data_RE_EST_END_IND	0x404

/* Set RLC uplink split threshold */
#define nr5g_rlcmac_Data_RLC_SPLIT_THR_REQ	0x05

/* Set RLC uplink split threshold */
#define nr5g_rlcmac_Data_RLC_SPLIT_THR_IND	0x405

/* Request for RLC Entity status */
#define nr5g_rlcmac_Data_RLC_ENTITY_REQ	0x06

/* Indicate RLC Entity status */
#define nr5g_rlcmac_Data_RLC_ENTITY_IND	0x406

/* Indicate RLC Entity Creation */
#define nr5g_rlcmac_Data_RLC_ENTITY_CREATE_IND	0x407

/* Request for a SI on demand (USER side only) */
#define nr5g_rlcmac_Data_SI_REQ		0x08

/* Confirm success or failure of a Random Access (USER side only) */
#define nr5g_rlcmac_Data_SI_CNF		0x208

/* Indicate a successful Random Access */
#define nr5g_rlcmac_Data_SI_IND		0x408

/*
 * TM SAP
 */
#define  nr5g_rlcmac_Data_TM_DATA_REQ       0x01
#define  nr5g_rlcmac_Data_TM_DATA_IND       0x401

/* For L2 TEST Mode */
#define  nr5g_rlcmac_Data_RAR_DATA_IND      0x402
#define  nr5g_rlcmac_Data_CE_DATA_IND       0x403

/*
 * UM SAP
 */
#define  nr5g_rlcmac_Data_UM_DATA_REQ       0x01
#define  nr5g_rlcmac_Data_UM_DATA_IND       0x401

/*
 * AM SAP
 */
#define  nr5g_rlcmac_Data_AM_DATA_REQ       0x01
#define  nr5g_rlcmac_Data_AM_DATA_CNF       0x201
#define  nr5g_rlcmac_Data_AM_DATA_IND       0x401
#define  nr5g_rlcmac_Data_AM_MAX_RETX_IND   0x402

/*------------------------------------------------------------------*
 |  LAYOUT OF PRIMITIVES                                            |
 *------------------------------------------------------------------*/

/*
 * nr5g_rlcmac_Data_TM_DATA_REQ
 * nr5g_rlcmac_Data_UM_DATA_REQ
 * nr5g_rlcmac_Data_AM_DATA_REQ
 */
typedef struct {

	nr5g_Id_t		Nr5gId;		/* NR5G Id */
	nr5g_RbType_v	RbType;
	uchar			RbId;		/* Rb id */
	nr5g_LchType_v	Lch;		/* Logical Channel Type */
	uint			Ref;		/* Reference for Cnf */
	uchar			MUI;		/* User Information */
	uint                    DataVolume;     /* Data Volume */
	uchar                   ScGid;          /* 0 for MCG 1 for SGC */
	uchar                   LcId;           /* Logical Channel Id (in case of duplication)*/
	nr5g_Ref_Ul_t	UlLogRef;	/* Reference for UL Logging */
	uchar			Data[1];

} nr5g_rlcmac_Data_DATA_REQ_t;

typedef struct {
	uint	RlcSn;		// RLC Sn
	uchar	Info;		// Flags: 1 Segmented
	ushort	Frame;		// Frame of MAC PDU of first RLC segment or of whole RLC
	ushort	Slot;		// Slot  of MAC PDU of first RLC segment or of whole RLC
} nr5g_rlcmac_info_t;

/*
 * nr5g_rlcmac_Data_TM_DATA_IND
 * nr5g_rlcmac_Data_UM_DATA_IND
 * nr5g_rlcmac_Data_AM_DATA_IND
 */
typedef struct {

	nr5g_Id_t		Nr5gId;		/* NR5G Id */
	nr5g_RbType_v	RbType;
	uchar			RbId;		/* Rb id */
	nr5g_LchType_v	Lch;		/* Logical Channel Type */
	uchar			ReEst;		/* Re-Establish flag [BOOL] */
	ushort			Esbf;		/* Extended L1 SFN/SBF number (1) */
	nr5g_Ref_Dl_1_t	DlLogRef;	/* Reference for DL Logging */
	nr5g_rlcmac_info_t	RLcMacInfo; /* Additional info */
	uint			RlcBuffer;
	uint			RlcStatus;
	uint			NrCurrentRate;
	uint			Spare[2];
	uchar			Data[1];

} nr5g_rlcmac_Data_DATA_IND_t;

#define nr5g_rlcmac_Data_NOP			(0)
#define nr5g_rlcmac_Data_RE_EST		(1)

/*
 * (1) Used the convention of consider an extended subframe number, as
 *       Esbf = SFN*10 + SBF
 *     so,
 *     System Frame Number (SFN) is equal to:
 *       [Esbf/10]
 *     Subfame number (SBF) is equal to:
 *       [Esbf%10]
 *     Value range:  0 - 10239.
 *
 *     Value -1U (0xFFFF) means 'not apply or not reported'
 */

/*
 * nr5g_rlcmac_Data_TM_DISC_REQ
 * nr5g_rlcmac_Data_UM_DISC_REQ
 * nr5g_rlcmac_Data_AM_DATA_CNF
 * nr5g_rlcmac_Data_AM_DISC_REQ
 */
typedef struct {

	nr5g_Id_t		Nr5gId;		/* NR5G Id */
	nr5g_RbType_v	RbType;
	uchar			RbId;		/* Rb id */
	nr5g_LchType_v	Lch;		/* Logical Channel Type */
	uchar                   ScGid;          /* 0 for MCG 1 for SGC */
	uint			Ref;		/* Reference for Cnf */
	uchar			MUI;		/* User Information */
	uint			RlcBuffer;
	uint			RlcStatus;
	uint			NrCurrentRate;
	uint			Spare[2];

} nr5g_rlcmac_Data_MUI_t;

/*
 * nr5g_rlcmac_Data_AM_MAX_RETX_IND
 */
typedef struct {

	nr5g_Id_t		Nr5gId;		/* NR5G Id */
	nr5g_RbType_v	RbType;
	uchar			RbId;		/* Rb id */

} nr5g_rlcmac_Data_AM_MAX_RETX_t;

/*
 * nr5g_rlcmac_Data_RA_REQ
 */
typedef struct {
	nr5g_Id_t		Nr5gId;		/* NR5G Id */
    nr5g_RbType_v    RbType;     /* Radio Bearer Type */
	uchar			RbId;		/* Rb id */
	nr5g_LchType_v	Lch;		/* Logical Channel Type */
    int				MaxUpPwr;   /* Maximum uplink power (in dBm) */
	int				BRSRP;		/* Simulated BRSRP [dBm, 0x7FFFFFFF for none] */
	int				UeCategory; /* UE category */
	
	uint			Flags;
#define nr5g_rlcmac_Data_FLAG_RA_TEST_01	(0x01) /* Enable RA test mode type 1 */
	uchar                   ScGid;          /* 0 for MCG 1 for SGC */
	uchar			Spare[11];	/* Must be set to zero */
	uchar			Rt_Preamble;	/* RA test mode preamble. Valid in RA_TEST_* mode only.
									   [0 - 63, -1 for none] */
	uint			Rt_RaRnti;		/* RA test mode RA-RNTI. Valid in RA_TEST_* mode only. 
									   [-1 for none] */
    uchar			UlSubCarrSpacing;  /* Subcarrier spacing
										  [Enum kHz15, kHz30, kHz60, kHz120, kHz240, 0xFF for none] */

	uchar			DiscardRarNum;		/* 0x00 -> Do not discard any RAR (default) */
										/* 0x.. -> Number of RARs to discard before accepting a new one */
										/* 0xFF -> Discard all RARs */
	uchar			NoData;		/* If set, Data is not present/valid */
	uchar			Data[1];	/* Data to be transmitted in RA procedure (Msg3) */
} nr5g_rlcmac_Data_RA_REQ_t;

/*
 * nr5g_rlcmac_Data_RA_CNF
 */
typedef struct {
	nr5g_Id_t		Nr5gId;		/* NR5G Id */
	short			Res;		/* Result code (see TODO) */
	nr5g_RA_RES_v	RaRes;		/* RA Result code */
	uint			Crnti;		/* Assigned C-RNTI */
	uint			numberOfPreamblesSent;	/* number of RACH preambles that were transmitted. Corresponds to parameter PREAMBLE_TRANSMISSION_COUNTER in TS 36.321 */
	uchar			contentionDetected;		/* If set contention was detected for at least one of the transmitted preambles */
} nr5g_rlcmac_Data_RA_CNF_t;

/*
 * nr5g_rlcmac_Data_RA_IND
 */
typedef struct {
	nr5g_Id_t		Nr5gId;		/* NR5G Id; CellId is valid */
	short			Res;		/* Result code (see TODO) */
	uint			Crnti;		/* Assigned C-RNTI */
	uchar			CrId[1];	/* Contention Resolution Id */
} nr5g_rlcmac_Data_RA_IND_t;

/*
 * nr5g_rlcmac_Data_SI_REQ
 */
typedef struct {
	nr5g_Id_t					Nr5gId;			/* NR5G Id */
	uchar						RequestResIdx;	/* Request Resources index */
	nr5g_rlcmac_Data_RA_REQ_t	SiRaInfo;		/* RA Info */
} nr5g_rlcmac_Data_SI_REQ_t;

/*
 * nr5g_rlcmac_Data_SI_CNF
 */
typedef struct {
	nr5g_Id_t		Nr5gId;					/* NR5G Id */
	short			Res;					/* Result code (see TODO) */
	nr5g_SI_RES_v	SiRes;					/* RA Result code */
	uchar			RequestResIdx;			/* Request Resources index */
	uint			numberOfPreamblesSent;	/* number of RACH preambles that were transmitted. Corresponds to parameter PREAMBLE_TRANSMISSION_COUNTER in TS 36.321 */
	uchar			contentionDetected;		/* If set contention was detected for at least one of the transmitted preambles */
} nr5g_rlcmac_Data_SI_CNF_t;

/*
 * nr5g_rlcmac_Data_SI_IND
 */
typedef struct {
	nr5g_Id_t		Nr5gId;			/* NR5G Id; CellId is valid */
	short			Res;			/* Result code (see TODO) */
	uchar			RequestResIdx;	/* Request Resources index */
} nr5g_rlcmac_Data_SI_IND_t;

/*
 * (1) Returned value is choose by MAC and returned to client.
 *     It can correspond to a new or reconfigured UE.
 */

/*
 * nr5g_rlcmac_Data_RE_EST_IND
 * nr5g_rlcmac_Data_RE_EST_END_IND
 */
typedef struct {
	nr5g_Id_t		Nr5gId;		/* NR5G Id */
	nr5g_RbType_v	RbType;
	uchar			RbId;		/* Rb id */
} nr5g_rlcmac_Data_RE_EST_t;

/*
 * nr5g_rlcmac_Data_RAR_DATA_IND
 */
typedef struct {
    nr5g_Id_t        NrId;      /* NR Id */
    uint             RaRnti;    /* RA RNTI*/
    uint             Rapid;     /* RAP_ID*/
    uchar            Data[1];    /* Figure 6.2.3-1: MAC RAR of 38.321*/
} nr5g_rlcmac_Data_RAR_DATA_IND_t;

/*
 * nr5g_rlcmac_Data_CE_DATA_IND
 */
typedef struct {
    nr5g_Id_t        NrId;      /* NR Id */
    uchar            Lcid;      /* LCID see Table 6.2.1-1 of 38.321 (from 110111 to 111110)*/
    uchar            Data[1];    /* CE Body - See 6.1.3 of 38.321 */
} nr5g_rlcmac_Data_CE_DATA_IND_t;

#define NR_RLC_COMMAND_SEND		0
#define NR_RLC_COMMAND_EMPTY	1
#define NR_RLC_COMMAND_STOP		2

#define NR_RLC_STATUS_NORMAL	0
#define NR_RLC_STATUS_EMPTYING	1
#define NR_RLC_STATUS_EMPTIED	2
#define NR_RLC_STATUS_STOP		3
/*
 * nr5g_rlcmac_Data_RLC_SPLIT_THR_REQ
 * nr5g_rlcmac_Data_RLC_SPLIT_THR_IND
 */
typedef struct {
	nr5g_Id_t		Nr5gId;		/* NR5G Id; CellId is valid */
	nr5g_RbType_v	RbType;
	uchar			RbId;		/* Rb id */
	uchar                   NrStkInst;
	uchar			RlcCommand;	/* see above NR_RLC_COMMAND_XXX */
	uchar			RlcStatus;	/* see above NR_RLC_STATUS_XXX */
    uchar           Flag[3];
    uint            SplitThr;   /* UL Split threshold */
} nr5g_rlcmac_Data_RLC_SPLIT_THR_t;

/*
 * nr5g_rlcmac_Data_RLC_ENTITY_REQ
 */
#define NUM_LCID_FOR_RBID	(4)

// values for tx_DuplicationState, dup_state
#define ggDUP_NO     (0)
#define ggDUP_CONFIG (1)
#define ggDUP_ACTIVE (2)

// values for flag
#define ggLCID_FLAG_NONE           (0)
#define ggLCID_FLAG_PRIMARY        (1)
#define ggLCID_FLAG_CGID_PRIMARY   (2)

typedef struct {
	uchar lcid;        /* LcId value */
	uchar cgid;        /* Cell Group Identifier */
	uchar dup_state;   /* State: used in DRB/SRB, changed by MAC or by PDCP: ggDUP_* */
	uchar flag;        /* ggLCID_FLAG_* */
} nr5g_rlcmac_Data_LCID_t;

typedef struct {
	nr5g_Id_t		Nr5gId;		/* NR5G Id; CellId is valid */
	nr5g_RbType_v	RbType;
	uchar			RbId;		/* Rb id */
	uchar			cgid;                            /* Cell Group Identifier */
	uchar			flag;                            /* ggLCID_FLAG_* */
	uchar			dup_state;                       /* State: used in DRB/SRB, changed by MAC or by PDCP: ggDUP_* */
	uchar			NumLcId;                         /* Global LcId Num for this RbId */
	nr5g_rlcmac_Data_LCID_t LcId[NUM_LCID_FOR_RBID]; /* Global LcId List for this RbId */
} nr5g_rlcmac_Data_RLC_ENTITY_REQ_t;

/*
 * nr5g_rlcmac_Data_RLC_ENTITY_IND
 */
typedef struct {
	nr5g_Id_t		Nr5gId;		/* NR5G Id; CellId is valid */
	nr5g_RbType_v	RbType;
	uchar			RbId;		/* Rb id */
	uchar			cgid;                            /* Cell Group Identifier */
	uchar			flag;                            /* ggLCID_FLAG_* */
	uchar			dup_state;                       /* State: used in DRB/SRB, changed by MAC or by PDCP: ggDUP_* */
	uchar			NumLcId;                         /* Global LcId Num for this RbId */
	nr5g_rlcmac_Data_LCID_t LcId[NUM_LCID_FOR_RBID]; /* Global LcId List for this RbId */
	uchar			Answer;                          /* Answer: 0 Spontaneous from RLCMAC, 1 answer to nr5g_rlcmac_Data_RLC_ENTITY_REQ */
} nr5g_rlcmac_Data_RLC_ENTITY_IND_t;

/*
 * nr5g_rlcmac_Data_RLC_ENTITY_IND
 */
typedef struct {
	nr5g_Id_t		Nr5gId;		/* NR5G Id; CellId is valid */
	nr5g_RbType_v	RbType;
	uchar			RbId;		/* Rb id */
} nr5g_rlcmac_Data_RLC_ENTITY_CREATE_IND_t;

/*------------------------------------------------------------------*
 |  SUMMARY OF PRIMITIVES                                           |
 *------------------------------------------------------------------*/

typedef union {

	nr5g_rlcmac_Data_DATA_REQ_t  DataReq;
	nr5g_rlcmac_Data_DATA_IND_t  DataInd;
	nr5g_rlcmac_Data_MUI_t       DataCnf;
	nr5g_rlcmac_Data_MUI_t       DiscReq;
	
	/* AUX SAP */
	nr5g_rlcmac_Data_RA_REQ_t      RaReq;
	nr5g_rlcmac_Data_RA_CNF_t      RaCnf;
	nr5g_rlcmac_Data_RA_IND_t      RaInd;
	nr5g_rlcmac_Data_RE_EST_t      ReestInd;
	nr5g_rlcmac_Data_RE_EST_t      ReestEndInd;
	nr5g_rlcmac_Data_RLC_SPLIT_THR_t RlcSplitThrReq;
	nr5g_rlcmac_Data_RLC_SPLIT_THR_t RlcSplitThrInd;
	nr5g_rlcmac_Data_RLC_ENTITY_REQ_t RlcEntityReq;
	nr5g_rlcmac_Data_RLC_ENTITY_IND_t RlcEntityInd;
	nr5g_rlcmac_Data_RLC_ENTITY_CREATE_IND_t RlcCreateInd;
	nr5g_rlcmac_Data_SI_REQ_t      SiReq;
	nr5g_rlcmac_Data_SI_CNF_t      SiCnf;
	nr5g_rlcmac_Data_SI_IND_t      SiInd;

	/* TM SAP */
	nr5g_rlcmac_Data_DATA_REQ_t  TmDataReq;
	nr5g_rlcmac_Data_DATA_IND_t  TmDataInd;
	nr5g_rlcmac_Data_MUI_t       TmDiscReq;
	
	/* UM SAP */
	nr5g_rlcmac_Data_DATA_REQ_t  UmDataReq;
	nr5g_rlcmac_Data_DATA_IND_t  UmDataInd;
	nr5g_rlcmac_Data_MUI_t       UmDiscReq;
	
	/* AM SAP */
	nr5g_rlcmac_Data_DATA_REQ_t  AmDataReq;
	nr5g_rlcmac_Data_MUI_t       AmDataCnf;
	nr5g_rlcmac_Data_DATA_IND_t  AmDataInd;
	nr5g_rlcmac_Data_MUI_t       AmDiscReq;
	nr5g_rlcmac_Data_AM_MAX_RETX_t AmMaxRetxInd;

} nr5g_rlcmac_Data_PRIMt;

#pragma    pack()
#endif
