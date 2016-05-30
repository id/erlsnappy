PROJECT = erlsnappy
PROJECT_DESCRIPTION = Erlang implementation of Snappy
PROJECT_VERSION = 0.0.1

TEST_DEPS = snappyer proper

dep_snappyer = git https://github.com/zmstone/snappy-erlang-nif.git master

NO_AUTOPATCH = snappyer

include erlang.mk

ERLC_COMPILE_OPTS = +bin_opt_info -DAPPLICATION=erlsnappy

COVER = true

ERLC_OPTS += $(ERLC_COMPILE_OPTS)
TEST_ERLC_OPTS += $(ERLC_COMPILE_OPTS)
