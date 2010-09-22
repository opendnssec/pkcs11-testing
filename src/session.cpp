/* $Id$ */

/*
 * Copyright (c) 2010 .SE (The Internet Infrastructure Foundation)
 * All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*****************************************************************************
 session.cpp

 Functions for session handling
 *****************************************************************************/

#include "session.h"
#include "config.h"
#include "getpw.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <unistd.h>


extern CK_FUNCTION_LIST_PTR p11;

int openLogin(char *slot, char *pin, CK_SLOT_ID *slotID, CK_SESSION_HANDLE *hSession)
{
	CK_RV rv;
	int retVal = 0;
	char user_pin_copy[MAX_PIN_LEN+1];

	if (slotID == NULL || hSession == NULL)
	{
		return 1;
	}

	if (slot == NULL)       
	{
		fprintf(stderr, "ERROR: A slot number must be supplied. "
			"Use --slot <number>\n");
		return 1;
	}
	*slotID = atoi(slot);

	// Open a session
	rv = p11->C_OpenSession(*slotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, hSession);
	if (rv == CKR_SLOT_ID_INVALID)
	{
		fprintf(stderr, "ERROR: The slot does not exist.\n");
		return 1;
	}
	if (rv != CKR_OK)
	{
		fprintf(stderr, "ERROR: Could not open a session. rv=0x%08X\n", rv);
		return 1;
	}

	// Login
	getPW(pin, user_pin_copy, CKU_USER);
	rv = p11->C_Login(*hSession, CKU_USER, (CK_UTF8CHAR_PTR)user_pin_copy, strlen(user_pin_copy));
	if (rv != CKR_OK)
	{
		if (rv == CKR_PIN_INCORRECT) {
			fprintf(stderr, "ERROR: The given user PIN does not match the one in the token.\n");
		}
		else
		{
			fprintf(stderr, "ERROR: Could not log in on the token. rv=0x%08X\n", rv);
		}
		return 1;
	}

	return 0;
}
