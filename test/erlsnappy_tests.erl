
-module(erlsnappy_tests).

-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").

proper_test() ->
  ?assert(proper:quickcheck(prop_compressed(), 1000)).

prop_compressed() ->
  ?FORALL(RandomBytes, proper_types:binary(),
          begin
            {ok, Compressed} = snappy:encode(RandomBytes),
            {ok, Decompressed} = snappyer:decompress(Compressed),
            ?assertEqual(RandomBytes, Decompressed),
            true
          end).

