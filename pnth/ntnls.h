/*
 * This file is part of the Process Hacker project - https://processhacker.sourceforge.io/
 *
 * You can redistribute this file and/or modify it under the terms of the 
 * Attribution 4.0 International (CC BY 4.0) license. 
 * 
 * You must give appropriate credit, provide a link to the license, and 
 * indicate if changes were made. You may do so in any reasonable manner, but 
 * not in any way that suggests the licensor endorses you or your use.
 */

#ifndef _NTNLS_H
#define _NTNLS_H

#define MAXIMUM_LEADBYTES   12

// This structure is the data from the raw codepage files.  Note that we set the "Codepage" field
// last, so any threads accessing this pointers in this structure should check to see if that is
// CP_UTF8 (65001) first.  If so, they should not use the pointers.
// MemoryBarrier might be warranted before checking CodePage to protect out-of-order reads of the pointers.
typedef struct _CPTABLEINFO {
	USHORT CodePage;                    // code page number (For UTF-8 the rest of the structure is unused)
	USHORT MaximumCharacterSize;        // max length (bytes) of a char
	USHORT DefaultChar;                 // default character (MB)
	USHORT UniDefaultChar;              // default character (Unicode)
	USHORT TransDefaultChar;            // translation of default char (Unicode)
	USHORT TransUniDefaultChar;         // translation of Unic default char (MB)
	USHORT DBCSCodePage;                // Non 0 for DBCS code pages
	UCHAR  LeadByte[MAXIMUM_LEADBYTES]; // lead byte ranges
	PUSHORT MultiByteTable;             // pointer to MB->Unicode translation table
	PVOID   WideCharTable;              // pointer to WC (Unicode->CodePage) translation table
	PUSHORT DBCSRanges;                 // pointer to DBCS ranges (UNUSED, DO NOT SET)
	PUSHORT DBCSOffsets;                // pointer to DBCS offsets
} CPTABLEINFO, *PCPTABLEINFO;

typedef struct _NLSTABLEINFO {
	CPTABLEINFO OemTableInfo;
	CPTABLEINFO AnsiTableInfo;
	PUSHORT UpperCaseTable;             // 844 format upcase table
	PUSHORT LowerCaseTable;             // 844 format lower case table
} NLSTABLEINFO, *PNLSTABLEINFO;

typedef struct _RTL_NLS_STATE {
	CPTABLEINFO DefaultAcpTableInfo;
	CPTABLEINFO DefaultOemTableInfo;
	PUSHORT ActiveCodePageData;
	PUSHORT OemCodePageData;
	PUSHORT LeadByteInfo;
	PUSHORT OemLeadByteInfo;
	PUSHORT CaseMappingData;
	PUSHORT UnicodeUpcaseTable844;
	PUSHORT UnicodeLowercaseTable844;
} RTL_NLS_STATE, *PRTL_NLS_STATE;

#if (PHNT_MODE != PHNT_MODE_KERNEL)

#ifdef DATA_EXPORT
_DATAIMP USHORT NlsAnsiCodePage;
_DATAIMP BOOLEAN NlsMbCodePageTag;
_DATAIMP BOOLEAN NlsMbOemCodePageTag;

#endif

#endif

#endif
