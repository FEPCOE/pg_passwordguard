# Makefile for pg_passwordguard

 EXTENSION  = pg_passwordguard
 MODULE_big = pg_passwordguard
 OBJS       = pg_passwordguard.o

# SQL script installed for CREATE EXTENSION
 DATA = pg_passwordguard--1.0.sql

# Regression tests (for "make installcheck")
 REGRESS = pg_passwordguard

# Use pg_config to find PostgreSQL paths
 PG_CONFIG = pg_config
 PGXS := $(shell $(PG_CONFIG) --pgxs)
 include $(PGXS)
