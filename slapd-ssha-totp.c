/* slapd-ssha-totp.c - Password module for combined password+MFA (depends on slapd-totp) */
/* $OpenLDAP$ */
/* Authors: David Caldwell <david@galvanix.com>, Igor Brezac <igor_brezac@discovery.com>
   MIT License

   Copyright (c) 2018 Discovery Communications

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in all
   copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
   SOFTWARE.
*/

#include <portable.h>

#include <stdbool.h>

#include "lutil.h"
#include "slap.h"
#include "config.h"

static LUTIL_PASSWD_CHK_FUNC chk_ssha_totp;
static const struct berval scheme_ssha_totp = BER_BVC("{SSHA+TOTP}");

#define DIGITS 6

static int chk_ssha_totp(
	const struct berval *scheme,
	const struct berval *passwd,
	const struct berval *cred,
	const char **text)
{
	char *comma = NULL;
	int ret = LUTIL_PASSWD_ERR;

	if (cred->bv_len < DIGITS+1)
		goto fail;
	struct berval cred_totp;
	ber_mem2bv(cred->bv_val + cred->bv_len - DIGITS, DIGITS, false, &cred_totp);

	struct berval cred_ssha;
	ber_mem2bv(cred->bv_val, cred->bv_len - DIGITS, false, &cred_ssha);

	comma = memchr(passwd->bv_val, ',', passwd->bv_len);
	if (!comma)
		goto fail;
	struct berval passwd_ssha;
	ber_str2bv(passwd->bv_val, comma - passwd->bv_val, false, &passwd_ssha);
	struct berval passwd_totp;
	ber_str2bv(comma+1, passwd->bv_len - (comma + 1 - passwd->bv_val), false, &passwd_totp);

	*comma = '\0'; // Hack: chk_ssha() assumes its inputs are null terminated, even though they are bervals
	if ((ret=lutil_passwd(&passwd_ssha, &cred_ssha, (const char*[]){"{SSHA}", NULL}, text)))
		goto fail;
	if ((ret=lutil_passwd(&passwd_totp, &cred_totp, (const char*[]){"{TOTP1}", "{TOTP256}", "{TOTP512}", NULL}, text)))
		goto fail;
	ret = LUTIL_PASSWD_OK; // Success!

fail:
	if (comma)
		*comma = ',';
	return ret;
}

int
ssha_totp_initialize(void)
{
	return lutil_passwd_add((struct berval *) &scheme_ssha_totp, chk_ssha_totp, NULL);
}

int init_module(int argc, char *argv[]) {
	return ssha_totp_initialize();
}
