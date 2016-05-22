PROJECT = erlsnappy
PROJECT_DESCRIPTION = Erlang implementation of Snappy
PROJECT_VERSION = 0.0.1

include erlang.mk

ERLC_COMPILE_OPTS = +bin_opt_info -DAPPLICATION=erlsnappy

ERLC_OPTS += $(ERLC_COMPILE_OPTS)
TEST_ERLC_OPTS += $(ERLC_COMPILE_OPTS)
