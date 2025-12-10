# pg_passwordguard

## Introduction
*pg_passwordguard* is a PostgreSQL extension that enforces strong password rules using the *check_password_hook*. It validates new or updated passwords for minimum length, character requirements, and username avoidance, helping administrators maintain consistent and secure authentication policies.

## Features
* Enforces password complexity rules:
  * Minimum length
  * At least one uppercase letter
  * At least one lowercase letter
  * At least one digit
  * At least one special character
* Rejects passwords that contain the username (case-insensitive)
* Fully configurable using PostgreSQL GUC parameters
* Supports per-role and global settings
* Optional log-only mode for testing policy impact
* Designed as a lightweight, pluggable extension built on top of PostgreSQL’s hook framework

## Installation
### 1. Build the extension
<pre>sudo make
sudo make install</pre>
Ensure that *pg_config* is pointing to the correct PostgreSQL installation, or update your *PATH* environment variable accordingly.

### 2. Enable the extension
Add the extension to *shared_preload_libraries* in PostgreSQL configuration file:
<pre>shared_preload_libraries = 'pg_passwordguard'</pre>
Then restart PostgreSQL using either *systemctl* or *pg_ctl*, depending on your environment.

### 3. Create the extension in the database
<pre>CREATE EXTENSION pg_passwordguard;</pre>

## Configuration Parameters
All settings use the *pg_passwordguard.** prefix and can be defined by manually modifying postgresql.conf, using ALTER SYSTEM SET, or at the role level with ALTER ROLE SET.
| Parameter                          | Description                                               | Default |
|------------------------------------|-----------------------------------------------------------|---------|
| `pg_passwordguard.min_length`      | Minimum number of characters required                     | `12`    |
| `pg_passwordguard.require_upper`   | Require at least one uppercase letter                     | `on`    |
| `pg_passwordguard.require_lower`   | Require at least one lowercase letter                     | `on`    |
| `pg_passwordguard.require_digit`   | Require at least one numeric digit                        | `on`    |
| `pg_passwordguard.require_special` | Require at least one special (non-alphanumeric) character | `on`    |
| `pg_passwordguard.reject_username` | Reject passwords that contain the username                | `on`    |
| `pg_passwordguard.log_only`        | Log violations instead of rejecting them (testing mode)   | `off`   |

## Parameter Description
### 1. pg_passwordguard.min_length
Minimum allowed length for a password.
Passwords shorter than this value are rejected unless pg_passwordguard.log_only is enabled.

**Default: 12**
### 2. pg_passwordguard.require_upper
Specifies whether a password must contain at least one uppercase ASCII letter (A–Z).
When enabled, passwords without an uppercase character are rejected.

**Default: on**
### 3. pg_passwordguard.require_lower
Specifies whether a password must contain at least one lowercase ASCII letter (a–z).
When enabled, passwords without a lowercase character are rejected.

**Default: on**
### 4. pg_passwordguard.require_digit
Specifies whether a password must contain at least one numeric digit (0–9).
When enabled, passwords without a digit are rejected.

**Default: on**
### 5. pg_passwordguard.require_special
Specifies whether a password must contain at least one special character.
A special character is any non-alphanumeric character.

**Default: on**
### 6. pg_passwordguard.reject_username
Controls whether passwords containing the role name are rejected.
The comparison is case-insensitive.

**Default: on**
### 7. pg_passwordguard.log_only
If enabled, policy violations are logged as warnings instead of causing the password to be rejected.
This mode is intended for testing or evaluating the policy before enforcing it in production.

**Default: off**

### Example configuration
<pre>pg_passwordguard.min_length = 10
pg_passwordguard.require_upper = on
pg_passwordguard.require_special = on
pg_passwordguard.log_only = off</pre>

## How It Works
pg_passwordguard hooks into PostgreSQL’s check_password_hook function. Whenever a password is set or changed using:
<pre>CREATE ROLE ... PASSWORD '...';
ALTER ROLE ... PASSWORD '...';
CREATE USER ... PASSWORD '...';
ALTER USER ... PASSWORD '...';</pre>
The hook receives the plaintext password and evaluates it against the configured policy.
* If all rules pass → password is accepted
* If a rule fails → either an ERROR is raised or a WARNING is logged (if log_only=on)
The extension does not re-check or invalidate existing passwords. Old passwords continue working until changed.

## Regression Tests
Basic regression tests are included and can be executed with:
<pre>make installcheck</pre>
These tests validate each policy check, including: 
* Too short passwords
* Missing character classes
* Username included in password
* Valid password case
