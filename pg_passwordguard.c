/*
 * pg_passwordguard.c
 *
 * Simple password complexity hook for PostgreSQL.
 *
 * This will plug into check_password_hook and enforce a few basic rules:
 *   - minimum length
 *   - must include upper/lower-case letters, digits, and a special character
 *   - must not contain the username
 *
 * Settings are exposed as GUCs under the "pg_passwordguard.*" prefix so they can be tuned in postgresql.conf or per-role.
 * NOTE
 * ====
 * This module only checks password rules when someone sets a new password or updates an existing one. It does not touch or re-check old passwords, so all existing accounts keep working normally.
 *
 * Developed by: Kothari Nishchay
 */

#include "postgres.h"

#include <ctype.h>
#include <string.h>
#include <limits.h>
#include "commands/user.h"
#include "fmgr.h"
#include "utils/guc.h"
#include "utils/elog.h"

PG_MODULE_MAGIC;

/* Store any previous password-check hook so this will don't break other extensions */
static check_password_hook_type prev_check_password_hook = NULL;

/* GUC-backed parameters with defaults. These can be overridden in postgresql.conf or with ALTER ROLE SET. */
static int  pg_passwordguard_min_length      = 12;
static bool pg_passwordguard_require_upper   = true;
static bool pg_passwordguard_require_lower   = true;
static bool pg_passwordguard_require_digit   = true;
static bool pg_passwordguard_require_special = true;
static bool pg_passwordguard_reject_username = true;
static bool pg_passwordguard_log_only        = false;

static void pg_passwordguard_check(const char *username,
                                const char *shadow_pass,
                                PasswordType password_type,
                                Datum validuntil_time,
                                bool validuntil_null);

/*_PG_init Called once when the server loads the module (at startup). Also register few GUCs and hook into check_password_hook here. */
void
_PG_init(void)
{
    DefineCustomIntVariable(
        "pg_passwordguard.min_length",
        "Minimum allowed password length.",
        NULL,
        &pg_passwordguard_min_length,
        12,
        0, INT_MAX,
        PGC_SUSET,
        0,
        NULL, NULL, NULL);

    DefineCustomBoolVariable(
        "pg_passwordguard.require_upper",
        "Require at least one uppercase letter in passwords.",
        NULL,
        &pg_passwordguard_require_upper,
        true,
        PGC_SUSET,
        0,
        NULL, NULL, NULL);

    DefineCustomBoolVariable(
        "pg_passwordguard.require_lower",
        "Require at least one lowercase letter in passwords.",
        NULL,
        &pg_passwordguard_require_lower,
        true,
        PGC_SUSET,
        0,
        NULL, NULL, NULL);

    DefineCustomBoolVariable(
        "pg_passwordguard.require_digit",
        "Require at least one digit in passwords.",
        NULL,
        &pg_passwordguard_require_digit,
        true,
        PGC_SUSET,
        0,
        NULL, NULL, NULL);

    DefineCustomBoolVariable(
        "pg_passwordguard.require_special",
        "Require at least one special (non-alphanumeric) character in passwords.",
        NULL,
        &pg_passwordguard_require_special,
        true,
        PGC_SUSET,
        0,
        NULL, NULL, NULL);

    DefineCustomBoolVariable(
        "pg_passwordguard.reject_username",
        "Reject passwords that contain the username (case-insensitive).",
        NULL,
        &pg_passwordguard_reject_username,
        true,
        PGC_SUSET,
        0,
        NULL, NULL, NULL);

    DefineCustomBoolVariable(
        "pg_passwordguard.log_only",
        "Log policy violations but do not reject the password.",
        "Useful for testing impact before enforcing the policy.",
        &pg_passwordguard_log_only,
        false,
        PGC_SUSET,
        0,
        NULL, NULL, NULL);

    /* Reserve the prefix so other extensions don't clash with us. */
    MarkGUCPrefixReserved("pg_passwordguard");

    /* Chain our hook after any existing one. */
    prev_check_password_hook = check_password_hook;
    check_password_hook = pg_passwordguard_check;
}

/* pg_passwordguard_check, This is called whenever a password is set or changed. This extension only validate plaintext passwords. Existing passwords are not re-checked; they continue to work until changed. */
static void
pg_passwordguard_check(const char *username,
                    const char *shadow_pass,
                    PasswordType password_type,
                    Datum validuntil_time,
                    bool validuntil_null)
{
    bool has_upper   = false;
    bool has_lower   = false;
    bool has_digit   = false;
    bool has_special = false;

    const char *password;
    int         len;
    int         i;

    /* This extension don't use these, but the hook API requires them. */
    (void) validuntil_time;
    (void) validuntil_null;

    /* Let any previously-registered hook run first. */
    if (prev_check_password_hook)
        prev_check_password_hook(username,
                                 shadow_pass,
                                 password_type,
                                 validuntil_time,
                                 validuntil_null);

    /* Only enforce rules when this extension see a plaintext password. */
    if (password_type != PASSWORD_TYPE_PLAINTEXT)
    {
        ereport(DEBUG1,
                (errmsg("pg_passwordguard: skipping non-plaintext password")));
        return;
    }

    /* Password cleared (ALTER ROLE ... PASSWORD NULL) → nothing to check. */
    if (shadow_pass == NULL)
        return;

    password = shadow_pass;
    len = strlen(password);

    /* Minimum length check. */
    if (len < pg_passwordguard_min_length)
    {
        if (pg_passwordguard_log_only)
        {
            ereport(WARNING,
                    (errmsg("pg_passwordguard: password too short (len=%d, min=%d)",
                            len, pg_passwordguard_min_length)));
        }
        else
        {
            ereport(ERROR,
                    (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                     errmsg("password does not meet complexity requirements"),
                     errdetail("Password must be at least %d characters long.",
                               pg_passwordguard_min_length)));
        }
        return;
    }

    /* Classify characters. */
    for (i = 0; i < len; i++)
    {
        unsigned char c = (unsigned char) password[i];

        if (isupper(c))
            has_upper = true;
        else if (islower(c))
            has_lower = true;
        else if (isdigit(c))
            has_digit = true;
        else
            has_special = true;
    }

    /* Uppercase requirement. */
    if (pg_passwordguard_require_upper && !has_upper)
    {
        if (pg_passwordguard_log_only)
            ereport(WARNING, (errmsg("pg_passwordguard: missing uppercase letter")));
        else
            ereport(ERROR,
                    (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                     errmsg("password does not meet complexity requirements"),
                     errdetail("Password must contain at least one uppercase letter.")));
    }

    /* Lowercase requirement. */
    if (pg_passwordguard_require_lower && !has_lower)
    {
        if (pg_passwordguard_log_only)
            ereport(WARNING, (errmsg("pg_passwordguard: missing lowercase letter")));
        else
            ereport(ERROR,
                    (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                     errmsg("password does not meet complexity requirements"),
                     errdetail("Password must contain at least one lowercase letter.")));
    }

    /* Digit requirement. */
    if (pg_passwordguard_require_digit && !has_digit)
    {
        if (pg_passwordguard_log_only)
            ereport(WARNING, (errmsg("pg_passwordguard: missing digit")));
        else
            ereport(ERROR,
                    (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                     errmsg("password does not meet complexity requirements"),
                     errdetail("Password must contain at least one digit.")));
    }

    /* Special character requirement. */
    if (pg_passwordguard_require_special && !has_special)
    {
        if (pg_passwordguard_log_only)
            ereport(WARNING, (errmsg("pg_passwordguard: missing special character")));
        else
            ereport(ERROR,
                    (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                     errmsg("password does not meet complexity requirements"),
                     errdetail("Password must contain at least one special character.")));
    }

    /* Reject passwords that contain the username (case-insensitive). */
    if (pg_passwordguard_reject_username && username != NULL)
    {
        char *lower_pwd  = pstrdup(password);
        char *lower_user = pstrdup(username);

        for (i = 0; lower_pwd[i]; i++)
            lower_pwd[i] = (char) tolower((unsigned char) lower_pwd[i]);
        for (i = 0; lower_user[i]; i++)
            lower_user[i] = (char) tolower((unsigned char) lower_user[i]);

        if (strstr(lower_pwd, lower_user) != NULL)
        {
            if (pg_passwordguard_log_only)
            {
                ereport(WARNING,
                        (errmsg("pg_passwordguard: password contains username")));
            }
            else
            {
                ereport(ERROR,
                        (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                         errmsg("password does not meet complexity requirements"),
                         errdetail("Password must not contain the username.")));
            }
        }

        pfree(lower_pwd);
        pfree(lower_user);
    }

    /* If we reach here, all enabled checks passed and the password is accepted. */
}

