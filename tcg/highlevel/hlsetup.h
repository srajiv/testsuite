/*
 *
 *   Copyright (C) International Business Machines  Corp., 2004
 *
 *   This program is free software;  you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY;  without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 *   the GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program;  if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

/*
 * NAME
 *	hlsetup.h
 *
 * DESCRIPTION
 *	This function will provide the basic prototypes
 *		and data structures for hlsetup.c.
 *
 * ALGORITHM
 *	Setup:
 *		None.
 *
 *	Test:
 *		None. This is a common setup function for
 *		higher-level testcases.
 *
 *	Cleanup:
 *		Print errno log and/or timing stats if options given
 *
 * USAGE
 *      Takes no arguments.
 *
 * HISTORY
 *      Megan Schneider, mschnei@us.ibm.com, 6/04.
 *
 * RESTRICTIONS
 *	None.
 */

#include "../common/common.h"

TSS_HCONTEXT	hContext;
TSS_HKEY	hKey1, hKey2, hKey3, hKey4, hKey5, hKey6, hKey7, hKey8,
		hKey9, hKey0, hKey10;
TSS_UUID	SRKUUID			= {0,0,0,0,0,0,0,0,0,0,1};
TSS_UUID	kuuid1			= {0,0,1,0,0,0,0,0,0,0,0};
TSS_UUID	kuuid2			= {0,0,2,0,0,0,0,0,0,0,0};
TSS_UUID	kuuid3			= {0,0,4,0,0,0,0,0,0,0,0};
