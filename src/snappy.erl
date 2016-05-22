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
-define(TABLE_MASK, 16383). % ?MAX_TABLE_SIZE - 1

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
  emit_literal(Block, Acc).

emit_literal(Bin, Acc) ->
  emit_literal(Bin, 0, erlang:size(Bin), Acc).

emit_literal(Bin, Start, End, Acc) ->
  Size = End - Start,
  <<_:Start/binary, Literal:Size/binary, _/binary>> = Bin,
  do_emit_literal(Literal, Size - 1, Acc).

do_emit_literal(Literal, N, Acc) when N < 60 ->
  X = (N bsl 2) bor ?TAG_LITERAL,
  <<Acc/binary, X:8/?UINT, Literal/binary>>;
do_emit_literal(Literal, N, Acc) when N < 256 ->
  X = 240 bor ?TAG_LITERAL,
  <<Acc/binary, X:8/?UINT, N:8/?UINT, Literal/binary>>;
do_emit_literal(Literal, N, Acc) ->
  X = 244 bor ?TAG_LITERAL,
  <<Acc/binary, X:8/?UINT, N:8/?UINT, (N bsr 8):8/?UINT, Literal/binary>>.

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

encode_block(Block, Acc0) ->
  Table = ets:new(table, [set]),
  BlockSize = erlang:size(Block),
  Shift0 = 32 - 8,
  InitTableSize = 1 bsl 8,
  Shift = calc_shift(Shift0, InitTableSize, BlockSize),
  SLimit = BlockSize - ?INPUT_MARGIN,
  NextEmit = 0,
  S = 1,
  NextHash = hash(load32(Block, S), Shift),
  {NextEmit, Acc} = do_encode_block(Table, Block, BlockSize, S, Shift, SLimit, NextEmit, NextHash, Acc0),
  emit_reminder(Block, BlockSize, NextEmit, Acc).

do_encode_block(Table, Block, BlockSize, S, Shift, SLimit, NextEmit, NextHash, Acc0) ->
  Skip0 = 32,
  NextS = S,
  case find_candidate(Table, Skip0, NextS, Block, Shift, SLimit, NextHash) of
    {ok, Candidate} ->
      Acc = emit_literal(Block, NextEmit, S, Acc0),
      do_encode_block1(Table, Block, BlockSize, S, Shift, SLimit, Candidate, Acc);
    false ->
      {NextEmit, Acc0}
  end.

do_encode_block1(Table, Block, BlockSize, S, Shift, SLimit, Candidate0, Acc0) ->
  Base = S,
  S = extend_match(Block, BlockSize, Candidate0 + 4, S + 4),
  Acc = emit_copy(Base - Candidate0, S - Base, Acc0),
  NextEmit = S,
  case S >= SLimit of
    true -> {NextEmit, Acc};
    false ->
      X = load64(Block, S),
      PrevHash = hash(X bsr 0, Shift),
      ets:insert(Table, {PrevHash band ?TABLE_MASK, S - 1}),
      CurrHash = hash(X bsr 8, Shift),
      Candidate = lookup_table(Table, CurrHash band ?TABLE_MASK),
      ets:insert(Table, {CurrHash band ?TABLE_MASK, S}),
      case (X bsr 8) /= load32(Block, Candidate) of
        true ->
          NextHash = hash(X bsr 16, Shift),
          do_encode_block(Table, Block, BlockSize, S, Shift, SLimit, NextEmit, NextHash, Acc0);
        false ->
          do_encode_block1(Table, Block, BlockSize, S, Shift, SLimit, Candidate, Acc0)
      end
  end.

extend_match(Block, BlockSize, I, S) when S < BlockSize ->
  X = binary:part(Block, I, 1),
  Y = binary:part(Block, S, 1),
  case X =:= Y of
    true  -> extend_match(Block, BlockSize, I + 1, S + 1);
    false -> S
  end.

find_candidate(Table, NextS0, Block, Shift, SLimit, Skip0, NextHash0) ->
  S = NextS0,
  BytesBetweenHashLookups = Skip0 bsr 5,
  NextS = S + BytesBetweenHashLookups,
  Skip = Skip0 + BytesBetweenHashLookups,
  case NextS =< SLimit of
    false ->
      false;
    true ->
      Candidate = lookup_table(Table, NextHash0 band ?TABLE_MASK),
      ets:insert(Table, {NextHash0 band ?TABLE_MASK, S}),
      NextHash = hash(load32(Block, NextS), Shift),
      case load32(Block, S) == load32(Block, Candidate) of
        true ->
          {ok, Candidate};
        false ->
          find_candidate(Table, NextS, Block, Shift, SLimit, Skip, NextHash)
      end
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

calc_shift(Shift, TableSize, BlockSize) when TableSize >= ?MAX_TABLE_SIZE;
                                             TableSize >= BlockSize ->
  Shift;
calc_shift(Shift, TableSize, BlockSize) ->
  calc_shift(Shift - 1, TableSize * 2, BlockSize).

is_too_large(Size) when Size > 16#ffffffff ->
  true;
is_too_large(Size) ->
  (32 + Size + Size/6) > 16#ffffffff.

hash(I, Shift) ->
  (I * 16#1e35a7bd) bsr Shift.

load32(Bin, I) ->
  Offset = (I-1)*32,
  <<_:Offset/binary, B0:32/?UINT, B1:32/?UINT, B2:32/?UINT, B3:32/?UINT, _/binary>> = Bin,
  B0 bor (B1 bsl 8) bor (B2 bsl 16) bor (B3 bsl 24).

load64(Bin, I) ->
  Offset = (I-1)*64,
  <<_:Offset/binary,
    B0:64/?UINT, B1:64/?UINT, B2:64/?UINT, B3:64/?UINT,
    B4:64/?UINT, B5:64/?UINT, B6:64/?UINT, B7:64/?UINT, _/binary>> = Bin,
  B0 bor (B1 bsl 8) bor (B2 bsl 16) bor (B3 bsl 24) bor (B4 bsl 32) bor (B5 bsl 40) bor (B6 bsl 48) bor (B7 bsl 56).

varint(I) ->
  H = I bsr 7,
  L = I band 127,
  case H =:= 0 of
    true  -> iolist_to_binary([L]);
    false -> iolist_to_binary([128 + L | varint(H)])
  end.
