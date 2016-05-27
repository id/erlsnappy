-module(snappy).

-export([encode/1]).

-define(TAG_LITERAL, 16#00).
-define(TAG_COPY1,   16#01).
-define(TAG_COPY2,   16#02).
-define(TAG_COPY4,   16#03).

-define(CHUNK_TYPE_COMPRESSED_DATA,   16#00).
-define(CHUNK_TYPE_UNCOMPRESSED_DATA, 16#01).
-define(CHUNK_TYPE_PADDING,           16#fe).
-define(CHUNK_TYPE_STREAM_IDENTIFIER, 16#ff).

-define(CHECK_SUM_SIZE, 4).
-define(CHUNK_HEADER_SIZE, 4).
-define(MAGIC_BODY, "sNaPpY").
-define(MAGIC_CHUNK, "\xff\x06\x00\x00" ++ magicBody).
-define(MAX_BLOCK_SIZE, 65536).
-define(MAX_ENCODED_BLOCK_SIZE, 76490).
-define(O_BUF_HEADER_LEN, (length(magicChunk) + ?CHECK_SUM_SIZE + ?CHUNK_HEADER_SIZE)).
-define(O_BUF_LEN, (?O_BUF_HEADER_LEN + ?MAX_ENCODED_BLOCK_SIZE)).

-define(INPUT_MARGIN, 15).
-define(MIN_NON_LITERAL_BLOCK_SIZE, 17).

-define(MAX_TABLE_SIZE, 16384). % 1 << 14
%-define(TABLE_MASK, 16383). % ?MAX_TABLE_SIZE - 1

-define(UINT, unsigned-integer).

encode(Bytes) ->
  Size = erlang:size(Bytes),
  case is_too_large(Size) of
    true ->
      {error, too_large};
    false ->
      Acc = <<(varint(Size))/binary>>,
      {ok, encode(Bytes, Acc)}
  end.

encode(<<Block:?MAX_BLOCK_SIZE/binary, Bin>>, Acc0) ->
  Acc = encode_block(Block, Acc0),
  encode(Bin, Acc);
encode(<<>>, Acc) ->
  Acc;
encode(Block, Acc) ->
  encode_block(Block, Acc).

encode_block(Block, Acc0) ->
  Table = ets:new(table, [set]), % ask caller to provide a table?
  BlockSize = erlang:size(Block),
  InitTableSize = 1 bsl 8,
  Shift = calc_shift(InitTableSize, BlockSize),
  %% sLimit is when to stop looking for offset/length copies. The inputMargin
  %% lets us use a fast path for emitLiteral in the main loop, while we are
  %% looking for copies.
  SLimit = BlockSize - ?INPUT_MARGIN,
  NextEmit = 0,
  %% The encoded form must start with a literal, as there are no previous
  %% bytes to copy, so we start looking for hash matches at s == 1.
  Ip = 1,
  NextHash = hash(load32(Block, Ip), Shift),
  {NextEmit, Acc} = do_encode_block(Table, Block, BlockSize, Ip, Shift, SLimit, NextEmit, NextHash, Acc0),
  ets:delete(Table),
  emit_reminder(Block, BlockSize, NextEmit, Acc).

do_encode_block(Table, Block, BlockSize, Ip, Shift, SLimit, NextEmit, NextHash, Acc0) ->
  %% Heuristic match skipping: If 32 bytes are scanned with no matches
  %% found, start looking only at every other byte. If 32 more bytes are
  %% scanned (or skipped), look at every third byte, etc.. When a match
  %% is found, immediately go back to looking at every byte. This is a
  %% small loss (~5% performance, ~0.1% density) for compressible data
  %% due to more bookkeeping, but for non-compressible data (such as
  %% JPEG) it's a huge win since the compressor quickly "realizes" the
  %% data is incompressible and doesn't bother looking for matches
  %% everywhere.

  %% The "skip" variable keeps track of how many bytes there are since
  %% the last match; dividing it by 32 (ie. right-shifting by five) gives
  %% the number of bytes to move ahead for each iteration.
  Skip0 = 32,
  NextIp = Ip,
  case find_candidate(Table, Skip0, NextIp, Block, Shift, SLimit, NextHash) of
    {ok, Candidate} ->
      %% A 4-byte match has been found. We'll later see if more than 4 bytes
      %% match. But, prior to the match, bytes NextEmit..S are unmatched. Emit
      %% them as literal bytes.
      Acc = emit_literal(Block, NextEmit, Ip, Acc0),
      do_encode_block1(Table, Block, BlockSize, Ip, Shift, SLimit, Candidate, Acc);
    false ->
      {NextEmit, Acc0}
  end.

do_encode_block1(Table, Block, BlockSize, Ip, Shift, SLimit, Candidate0, Acc0) ->
  Base = Ip,
  Ip = extend_match(Block, BlockSize, Candidate0 + 4, Ip + 4),
  Acc = emit_copy(Base - Candidate0, Ip - Base, Acc0),
  NextEmit = Ip,
  case Ip >= SLimit of
    true -> {NextEmit, Acc};
    false ->
      X = load64(Block, Ip),
      PrevHash = hash(X bsr 0, Shift),
      ets:insert(Table, {PrevHash, Ip - 1}),
      CurrHash = hash(X bsr 8, Shift),
      Candidate = lookup_table(Table, CurrHash),
      ets:insert(Table, {CurrHash, Ip}),
      case (X bsr 8) /= load32(Block, Candidate) of
        true ->
          NextHash = hash(X bsr 16, Shift),
          do_encode_block(Table, Block, BlockSize, Ip, Shift, SLimit, NextEmit, NextHash, Acc0);
        false ->
          do_encode_block1(Table, Block, BlockSize, Ip, Shift, SLimit, Candidate, Acc0)
      end
  end.

find_candidate(Table, NextIp0, Block, Shift, SLimit, Skip0, NextHash0) ->
  Ip = NextIp0,
  Hash = NextHash0,
  BytesBetweenHashLookups = Skip0 bsr 5,
  Skip = Skip0 + BytesBetweenHashLookups,
  NextIp = Ip + BytesBetweenHashLookups,
  case NextIp > SLimit of
    true ->
      false;
    false ->
      NextHash = hash(load32(Block, NextIp), Shift),
      Candidate = lookup_table(Table, Hash),
      ets:insert(Table, {Hash, Ip}),
      case load32(Block, Ip) == load32(Block, Candidate) of
        true ->
          {ok, Candidate};
        false ->
          find_candidate(Table, NextIp, Block, Shift, SLimit, Skip, NextHash)
      end
  end.

emit_literal(Bin, Start, End, Acc) ->
  Size = End - Start,
  <<_:Start/binary, Literal:Size/binary, _/binary>> = Bin,
  N = Size - 1,
  Tag = case N < 60 of
          true ->
            <<((N bsl 2) bor ?TAG_LITERAL):8/?UINT>>;
          false ->
            get_literal_tag(N, 0, <<>>)
        end,
  <<Acc/binary, Tag/binary, Literal/binary>>.

get_literal_tag(N, Count, Tag) when N =< 0 ->
  <<(((59 + Count) bsl 2) bor ?TAG_LITERAL):8/?UINT, Tag/binary>>;
get_literal_tag(N, Count, Tag0) ->
  Tag = <<Tag0/binary, (N band 16#ff):8/?UINT>>,
  get_literal_tag(N bsr 8, Count + 1, Tag).

emit_copy(Offset, Length0, Acc0) ->
  {Length1, Acc1} = do_emit_copy1(Offset, Length0, Acc0),
  {Length2, Acc2} = do_emit_copy2(Offset, Length1, Acc1),
  {Length, Acc} = do_emit_copy3(Offset, Length2, Acc2),
  Rem = <<(((Offset bsr 8) bsl 5) bor ((Length - 4) bsl 2) bor ?TAG_COPY1):8/?UINT>>,
  <<Acc/binary, Rem/binary, Offset:8/?UINT>>.

do_emit_copy1(Offset, Length, Acc0) when Length >= 68 ->
  Acc = <<Acc0/binary, ((63 bsl 2) bor ?TAG_COPY2):8/?UINT, Offset:8/?UINT, (Offset bsr 8):8/?UINT>>,
  do_emit_copy1(Offset, Length - 64, Acc);
do_emit_copy1(_Offset, Length, Acc) ->
  {Length, Acc}.

do_emit_copy2(Offset, Length, Acc0) when Length < 64 ->
  Acc = <<Acc0/binary, ((59 bsl 2) bor ?TAG_COPY2):8/?UINT, Offset:8/?UINT, (Offset bsr 8):8/?UINT>>,
  {Length - 60, Acc};
do_emit_copy2(_Offset, Length, Acc) ->
  {Length, Acc}.

do_emit_copy3(Offset, Length, Acc0) when Length >= 12 orelse Offset >= 2048 ->
  Acc = <<Acc0/binary, (((Length - 1) bsl 2) bor ?TAG_COPY2):8/?UINT, Offset:8/?UINT, (Offset bsr 8):8/?UINT>>,
  {Length, Acc};
do_emit_copy3(_Offset, Length, Acc) ->
  {Length, Acc}.

extend_match(Block, BlockSize, I, Ip) when Ip < BlockSize ->
  X = binary:part(Block, I, 1),
  Y = binary:part(Block, Ip, 1),
  case X =:= Y of
    true  -> extend_match(Block, BlockSize, I + 1, Ip + 1);
    false -> Ip
  end.

lookup_table(Table, Index) ->
  case ets:lookup(Table, Index) of
    [X] -> X;
    []  -> 0
  end.

emit_reminder(Block, BlockSize, NextEmit, Acc) when NextEmit < BlockSize ->
  emit_literal(Block, NextEmit, BlockSize, Acc);
emit_reminder(_Block, _BlockSize, _NextEmit, Acc) ->
  Acc.

calc_shift(TableSize, BlockSize) when TableSize >= ?MAX_TABLE_SIZE;
                                      TableSize >= BlockSize ->
  32 - log2floor(TableSize);
calc_shift(TableSize, BlockSize) ->
  calc_shift(TableSize bsl 1, BlockSize).

is_too_large(Size) when Size > 16#ffffffff ->
  true;
is_too_large(Size) ->
  (32 + Size + Size/6) > 16#ffffffff.

hash(I, Shift) ->
  (I * 16#1e35a7bd) bsr Shift.

load32(Bin, Offset) ->
  <<_:Offset/binary, X:32/?UINT, _/binary>> = Bin,
  X.

load64(Bin, Offset) ->
  <<_:Offset/binary, X:64/?UINT, _/binary>> = Bin,
  X.

varint(I) ->
  H = I bsr 7,
  L = I band 127,
  case H =:= 0 of
    true  -> iolist_to_binary([L]);
    false -> iolist_to_binary([128 + L | varint(H)])
  end.

log2floor(0) ->
  -1;
log2floor(N) ->
  log2floor(0, N, 4).

log2floor(Log, _Value, -1) ->
  Log;
log2floor(Log, Value0, I) ->
  Shift = 1 bsl I,
  Value = Value0 bsr Shift,
  case Value /= 0 of
    true ->
      log2floor(Log + Shift, Value, I - 1);
    false ->
      log2floor(Log, Value0, I - 1)
  end.

