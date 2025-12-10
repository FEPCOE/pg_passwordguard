-- sql/pg_passwordguard.sql

-- Load the extension library so _PG_init runs and hooks check_password_hook.
LOAD 'pg_passwordguard';

-- Now create the extension (for the SQL objects, version tracking etc.).
CREATE EXTENSION IF NOT EXISTS pg_passwordguard;

-- Use a small min_length here to keep tests simple.
SET pg_passwordguard.min_length = 8;
SET pg_passwordguard.require_upper = on;
SET pg_passwordguard.require_lower = on;
SET pg_passwordguard.require_digit = on;
SET pg_passwordguard.require_special = on;
SET pg_passwordguard.reject_username = on;
SET pg_passwordguard.log_only = off;

--
-- 1) Too short password (length < min_length)
--
CREATE ROLE sp_short LOGIN PASSWORD 'Aa1!';

--
-- 2) Missing uppercase letter
--
CREATE ROLE sp_noupper LOGIN PASSWORD 'abc12345!';

--
-- 3) Missing lowercase letter
--
CREATE ROLE sp_nolower LOGIN PASSWORD 'ABC12345!';

--
-- 4) Missing digit
--
CREATE ROLE sp_nodigit LOGIN PASSWORD 'Abcdefg!';

--
-- 5) Missing special character
--
CREATE ROLE sp_nospecial LOGIN PASSWORD 'Abcdefg1';

--
-- 6) Password contains username (case-insensitive)
--
CREATE ROLE spuser LOGIN PASSWORD 'Spuser1!';

--
-- 7) Valid password that satisfies all rules
--
CREATE ROLE sp_ok LOGIN PASSWORD 'Abc12345!';
