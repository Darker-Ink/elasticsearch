# Out-of-bounds read/write audit — Elasticsearch (branch `claude/dazzling-wozniak-094mqo`, HEAD `d7dac6d69`)

Scope: the whole repository plus its vendored native dependencies, looking specifically for
**out-of-bounds read and write primitives** reachable from the HTTP API.

## Method and framing

In a JVM, array and `ByteBuffer` indexing is checked, so a genuine OOB primitive needs one of:

1. **Panama FFM** — a `MemorySegment` whose declared size exceeds the real allocation
   (`reinterpret`/`ofAddress`, or a wrongly-sized `FileChannel.map`), or a native downcall given a
   length larger than the buffer passed.
2. **`sun.misc`/`jdk.internal.misc.Unsafe`.**
3. **An unchecked accessor over paged heap storage** — notably `BigArrays`/`BytesRefArray`, which
   deliberately omit bounds checks on the hot path.

I enumerated that surface exhaustively rather than sampling:

- `@LibrarySpecification` FFM libraries: exactly four — `libs/zstd`, `libs/simdvec`, `libs/simdjson`,
  `libs/native`. Nothing in `x-pack` or `modules` declares native functions.
- Nothing bypasses the generated bindings: the only self-linked downcall handle is
  `VecCaps.java:74` (`vec_caps`, no arguments).
- `MemorySegment.reinterpret(` — 6 non-test sites, all enumerated below.
- `FileChannel.map(` — exactly **one** non-test site, and it is `READ_ONLY`
  (`libs/gpu-codec/.../MemorySegmentUtils.java:80`).
- `Unsafe` — one production use, `UninitializedArrays` (allocation only).

Caveat on confidence: this is a source audit. The container has JDK 21 while the build requires
JDK 25, so I could not run the Java paths end to end. Where I say "verified", I mean I read the
code at the cited line. The one dynamic result is V-3's native demo, which I did compile and run.

---

## V-1 — OOB read: unvalidated Parquet dictionary ordinals → cross-request heap disclosure

**Severity: high (confidentiality, cross-tenant).** Reachable from the ES|QL query API against an
attacker-supplied Parquet dataset, where every page-header field is attacker-controlled.

Verified chain, every link read at the cited line:

| # | Location | What happens |
|---|---|---|
| 1 | `PageColumnReader.java:1458-1493` | `readBytesBatchAsOrdinals` fills `int[] ordinals` straight from `dictDecoder.readIndices(...)`. **No range check against the dictionary size.** |
| 2 | `DictionaryValueDecoder.java:77-80`, `:465-477` | The bit-width byte is capped at 32 but **not** at the dictionary size; with width 32 `readBitsLE` yields an arbitrary 32-bit int, so the attacker controls each ordinal outright. |
| 3 | `PageColumnReader.java:1495-1521` | `buildOrdinalResult` publishes `new OrdinalBytesRefBlock(ordinalsBlock, dictVector)` — still unvalidated. |
| 4 | `OrdinalBytesRefBlock.java:74-76` | `bytes.getBytesRef(ordinals.getInt(valueIndex), dest)` — raw ordinal passed through. |
| 5 | `BytesRefArray.java:257-261` | `get(long id, BytesRef dest)` — **no `id < size` check.** |
| 6 | `BytesRefArray.java:121-127` | `getOffset`: when entries share a length (`fixedLength >= 0`) it is bare `(long) fixedLength * index`. |
| 7 | `BytesRefArray.java:797-812` | `Bytes.get`: for `offset + length <= PAGE_SIZE` it sets `dst.bytes = pages[pageIndex]; dst.offset = offset; dst.length = length` — a view with **no check that the region was ever written.** |
| 8 | `BytesRefArray.java:652`, `:676` → `PageCacheRecycler.java:141-145` | Pages come from `recycler.bytePage(false)`, and the recycler zeroes **only when `clear == true`**. Recycled pages retain prior contents. |

`PageCacheRecycler` is node-wide and shared across requests, so an out-of-range ordinal returns the
unwritten remainder of a recycled page — another request's heap bytes — as an ordinary `KEYWORD`
column value. It reaches the client either via `BytesRefBlock.writeTo` on the data node (the
non-dense path, selected by making the dictionary larger than half the batch) or on the coordinator
while rendering the response.

**The asymmetry that makes this a bug rather than a design choice:** every *other* consumer of these
ordinals indexes a plain Java array and therefore merely throws — the constant-ordinal shortcut at
`PageColumnReader.java:1506-1509` (which even guards `constantOrdinal >= 0`), `:1695`/`:1706`,
`DictionaryValueDecoder.java:135`, `ParquetPushedExpressions.java:2891`. Only the
`OrdinalBytesRefBlock` path leaves Java arrays for `BigArrays`-backed storage.

**Fix:** validate `0 <= ordinal < dict.length` before `buildOrdinalResult` publishes the block
(the write loops at `:1470`/`:1474`/`:1481`, or one pass in `buildOrdinalResult`). Independently,
consider an `assert`-free bound in `BytesRefArray.get`, since it is a general-purpose unchecked sink.

## V-2 — OOB read: Parquet V2 page-header level lengths escape the page window

**Severity: medium-high.** Discloses other column chunks in the same coalesced read, including
columns the query never projected.

- `PrefetchedRowGroupBuilder.java:404-410` — `rlBytes = dph.repetition_levels_byte_length` and
  `dlBytes = dph.definition_levels_byte_length` are raw Thrift `i32`s. They are **never sign-checked
  and never checked against `compressed_page_size`**; `dataCompressedSize` is then
  `compressedPayloadSize - rlBytes - dlBytes`.
- `PrefetchedRowGroupBuilder.java:566-579` — `bytesInputFromSlice`'s **heap branch is the production
  path** (`DirectBufferFactory.forBreaker` wraps a heap `byte[]`) and does
  `BytesInput.from(source.array(), source.arrayOffset() + source.position() + offsetFromPosition, length)`
  with no bounds validation. The direct-buffer branch immediately below *is* validated, because
  `position`/`limit` throw.

A negative `dlBytes` moves the window *before* the page; an oversized one runs past it. The only
backstop is `ByteBuffer.wrap` inside `BytesInput.toByteBuffer()`, which validates against the whole
merged coalesced range array, not the page. The sibling V1 path (`PageColumnReader.java:548-574`)
is safe precisely because it stays on `ByteBuffer.slice`.

**Fix:** reject `rlBytes < 0 || dlBytes < 0 || rlBytes + dlBytes > compressedPayloadSize` in
`makeDataPage`, and add `Objects.checkFromIndexSize(offsetFromPosition, length, source.remaining())`
to the heap branch so it matches the direct branch.

## V-3 — OOB write primitive: native kernels with no emitted bounds check

**Confirmed primitive; not reachable today.** This is the only unchecked native *write* target in the
repository.

Of 73 `@Function` declarations in `SimdVecLibrary`, 61 carry `@VectorSegment`/`@MatrixSegment`/
`@SlicedSegment`, which the annotation processor turns into a **real** runtime
`Objects.checkFromIndexSize` at the top of the generated `$Impl` method
(`ImplClassWriter.java:597-614`; only `aligned=` is an `assert`). Six carry none, by explicit
decision — the comment at `SimdVecLibrary.java:1249` says they "carry no segment bounds
annotations":

`applyCorrections{Euclidean,MaxInnerProduct,DotProduct}Bulk` (`:1263`, `:1280`, `:1297`) and
`bbqApplyCorrections{Euclidean,MaxInnerProduct,DotProduct}Bulk` (`:1325`, `:1345`, `:1365`).

Native behaviour (`libs/simdvec/native/src/vec/c/amd64/score_1.cpp`): `scores[0..bulkSize)` is
written via `_mm256_storeu_ps` plus a scalar tail, and in the `bbq*` family the `data` parameter is
really `const void* const* addresses` whose entries are **dereferenced** at
`addresses[i] + vectorSizeInBytes`. `ScoreCorrections.java` is a pure pass-through with no validation.

I compiled `score_1.cpp` against a harness: calling `bbq_apply_corrections_dot_product_bulk` with
`bulkSize = 16` and an 8-float `scores` buffer overwrote **32 bytes past the end** (canary
`0xCAFEBABE` → `0x3F000000`). There is no clamp in the kernel. In Java the buffer is a pinned
`float[]` under a `critical(true)` downcall, so such a write lands in the Java heap.

**Why it is not currently exploitable:** all 7 Java call sites perform an *annotated* native
dot-product call on the same `scores` segment with the same count immediately beforehand, which
throws `IndexOutOfBoundsException` first. I checked every caller, including Lucene 10.5.1's own
`bulkScore` sites (`AbstractHnswGraphSearcher`, `HnswGraphSearcher`, `HnswGraphBuilder`
(`MAX_BULK_SCORE_NODES = 8`), `FilteredHnswGraphSearcher`, `VectorScorer`,
`Lucene99HnswVectorsReader`/`Lucene104ScalarQuantizedVectorsReader`
(`EXHAUSTIVE_BULK_SCORE_ORDS = 64`)), Elasticsearch's `HnswUtils` (5 sites), and the three DiskBBQ
readers (`BULK_SIZE = 32`, tail provably ≤ 31).

**The one unenforced invariant.** On the `scoreBulkOffsets` paths
(`NativeMemorySegmentScorer.java:155-170`, `StripedES940OSQVectorsScorer.java:129-140`) the guarding
call binds the native `count` parameter to **`offsetsCount`**, so only `scores.length >= offsetsCount`
is proven — while the corrections kernel then writes `count >= offsetsCount` floats. Nothing checks
`scores.length >= count`; the Java zero-fill loops that would notice run *after* the native call.
Safe today only because every caller happens to allocate `new float[BULK_SIZE]`. The public entry
points guard with assertions only (`ES940OSQVectorsScorer.java:319`, `:369-370`).

**Fix:** annotate all six (`scores` → `@VectorSegment(countParam = "bulkSize", elementBits = Float.SIZE)`;
`data`/`corrections` → the pointer-array / 16-byte-record shape), and bind the guard in
`scoreBulkOffsets` to `count`. Note the javadoc at `:1317-1319` describes `data` as a contiguous
segment with a `pitchInBytes` stride, which is wrong — it is a pointer array and `pitchInBytes` is
unused — so anyone annotating from the javadoc would emit the wrong check.

## V-4 — latent OOB read: `reinterpret` with an unvalidated size (Arrow)

`AbstractArrowBufVector.java:88`:

```java
return MemorySegment.ofAddress(valueBuffer.memoryAddress()).reinterpret((long) positionCount * byteSize());
```

`reinterpret` erases bounds. The constructor (`:31-35`, `:38-46`) takes
`valueBuffer = arrowVector.getDataBuffer()` and `positionCount = arrowVector.getValueCount()` with
**no check that `valueBuffer.capacity() >= positionCount * byteSize()`**. The only validation is
`ArrowUtils.checkItemSize` (`ArrowUtils.java:32-39`), which checks the per-item *width* only.
`AbstractArrowBufBlock:92-94` has the same shape. Twelve generated aggregator files consume the
segment in reduction loops up to `positionCount`.

**Not reachable today:** the only callers of the `ArrowToEsql` converters are tests
(`ArrowToBlockConverterTests`); no production code constructs these vectors. The live Arrow path is
output-only (`formatter/arrow/`). But Arrow Java's record-batch loader sets `valueCount` from the IPC
field node independently of the data-buffer length, so this becomes a remote off-heap OOB read the
moment an Arrow ingest reader is wired up.

**Fix:** validate capacity in the constructor, or clamp the `reinterpret` to
`min(capacity, positionCount * byteSize())`.

## V-5 — systemic: security-relevant validation that is `assert`-only

Release builds run without `-ea`, so these do not execute in production. Each is defence-in-depth
today, but each is also the *only* check on the value it guards:

- `SimdVecChecks.validateBulkOffsets` / `validateBulkSparse` — invoked as `assert validate…(…)` at
  **33 sites** in `SimdVecLibrary`. `validateBulkOffsets` is the only check on the *values* inside the
  `offsets` array; the `@MatrixSegment` annotation bounds the dataset as `rows = count` where `count`
  is the *offsets* count, so it never bounds `max(offsets[i])`. Current callers pass in-block indices
  (`offsets[i] < count`), so no violation is reachable.
- `IndexInputUtils.java:228-231`, `:258`, `:261`, `:297-308` — all assertions. The real runtime
  guarantee comes from Lucene's `segmentSliceOrNull` and from the blob cache's region containment
  plus `SparseFileTracker.checkAvailable`, not from this class.
- `SharedBlobCacheService.java:1790` — `assertOffsetsWithinFileLength`.
  `DirectAccessInput.checkSlicesArgs` validates neither `offsets[i] >= 0` nor `length > 0`.
- `ES92GpuHnswVectorsWriter.java:482` — the only range check on neighbour ordinals returned by the
  third-party cuVS GPU graph build, before they are written into the `.vex` file. Validating
  third-party native output with an `assert` is the wrong tool.

## V-6 — lower-severity hardening

- `MemorySegmentUtils.java:80` (gpu-codec) — `fc.map(READ_ONLY, 0L, dataSize, arena)` with no
  `dataSize > fc.size()` check. `mmap` past EOF succeeds on Linux and yields a segment reporting the
  larger size, which would then satisfy the `DatasetUtilsImpl.java:53` check while touching unmapped
  pages (SIGBUS). Not reachable today — every `dataSize` is a value this process just wrote — but it
  defeats the one check protecting the cuVS handoff. One line fixes it permanently.
- `ES92GpuHnswVectorsWriter.java:706` — the `int8_hnsw` merge path calls the *raw*
  `DatasetUtilsImpl.fromMemorySegment`, bypassing the validating `DatasetUtils.fromInput` the float
  path uses at `:763-764`.
- `ES92GpuHnswVectorsFormat.java:67-82` — no `maxConn`/`beamWidth` validation, unlike its sibling
  `ES92GpuHnswSQVectorsFormat.java:84-93`. Because the GPU provider short-circuits
  `indexOptions.getVectorsFormat(...)` (`DenseVectorFieldMapper.java:4411-4427`), Lucene99's
  `maxConn <= 512` / `beamWidth <= 3200` validation is skipped, and `m`/`ef_construction` are not
  validated at mapping-parse time either. `m * ef` is an unwidened `int` multiply. DoS/robustness only.
- `PageColumnReader.java:1253-1261` (and `ParquetFormatReader.java:4226`,
  `ParquetColumnDecoding.java:496`) — FLOAT16 decode reads 2 bytes without checking the value length,
  unlike its siblings `int96ToEpochMillis` (`:377-381`) and `formatUuid` (`:556-562`) which both
  validate. Wrong value on the PLAIN path; unhandled `AIOOBE` (including at plan time on footer
  statistics) on the others.
- `PlainValueDecoder.java:79-88`, `:156-161` — a negative `length` read from the file produces a
  `BytesRef` with negative length (`isValid()` is an assertion), failing later and less diagnosably.
- `MemorySegmentES92NativeInt7VectorsScorer.scoreBulk` (`:50-78`) removes an implicit guard the
  pure-Java parent had: `ES92Int7VectorsScorer.scoreBulk:123-126` reads into `float[bulkSize]` fields
  and throws if driven with a larger `bulkSize`; the native override bypasses those arrays.
- `AddressesScratch`/`OffsetsScratch`/`BufferScratch` grow but never shrink, so slots beyond `count`
  hold stale — possibly dangling — addresses. No consumer reads past `count` today.

## V-7 — uninitialized-memory read: `FIRST()`/`LAST()` emit unwritten `keys[]` slots

**Severity: medium.** Confirmed read of non-zeroed recycled heap; reaches an intermediate transport
page, but I could not trace the bytes into the `_query` response body.

- `AbstractAllByLongGroupingState.java:30-31` — `keys = bigArrays.newLongArray(1, false)`
  (`clearOnResize = false`), then **only slot 0** is initialised (`keys.set(0, -1L)`).
  `grow(group)` (`:49`) is `bigArrays.grow(keys, group + 1)` and never fills the new region;
  `key(group)` (`:40`) is a bare `keys.get(group)`. Same in `AbstractAllByIntGroupingState.java:30-31`.
- `AllFirstLongByLongAggregator.java:273-277` (one of 24 generated copies):

```java
if (group <= maxGroupId) {
    // We must have seen this group before and saved its state   <-- wrong assumption
    observedBlockBuilder.appendBoolean(hasValue(group));
    hasTimestampBuilder.appendBoolean(nullKey(group) == false);
    timestampsBuilder.appendLong(key(group));                     // reads an unwritten slot
```

`maxGroupId` is the *highest* group ever collected, so `group <= maxGroupId` is a **range** test
standing in for a **seen** test. `hasValue(group)` — the real "was this written" bit — is consulted
only for the neighbouring `observed` block, while `key(group)` is read unconditionally. Any group id
below `maxGroupId` that was never collected is a hole.

Trigger: a filtered aggregation, which is the documented way an aggregator sees fewer groups than the
block hash has — `STATS f = FIRST(value, @timestamp) WHERE flag == true BY key`.
`AbstractPhysicalOperationProviders.java:370-382` wraps the supplier in
`FilteredAggregatorFunctionSupplier` in the data-node INITIAL stage (the stage that calls
`toIntermediate`), and `FilteredGroupingAggregatorFunction.java:36-40` nulls out filtered positions —
its own constructor comment notes "the underlying aggregator may not see all groups". Needs >512
groups for the leak to be real heap rather than JVM zeroes, because the first `grow` past
`LONG_PAGE_SIZE/2` switches to a `BigLongArray` whose pages come from `recycler.bytePage(false)`
(`AbstractBigByteArray.java:59-109`); `BigArrays.resize` (`:771-790`) preserves
`clearOnResize = false` and never clears the grown region.

Again the asymmetry: the sibling templates all gate correctly on `hasValue(group)` —
`X-ValuesAggregator.java.st:232`, `X-AnyValueAggregator.java.st:256-258`,
`X-ValueByTimestampAggregator.java.st:147`.

Aggravating defect in the same file (`:163`): `group < observed.getPositionCount()` compares the
*receiver's* group ord against the *incoming page's* position count, so the guard silently disables
itself for coordinator group ids ≥ the page size — which is what causes the stale timestamp to be
consumed as a genuine candidate rather than ignored.

**Fix** belongs in the template `X-AllValueByTimestampAggregator.java.st`
(`toIntermediate`), not the 24 generated files: gate the `key(group)` read on `hasValue(group)`.

## V-8 — latent: `FirstDocIdGroupingAggregatorFunction` reads `docs[]` with no guard at all

`FirstDocIdGroupingAggregatorFunction.java` — `docs = bigArrays.newIntArray(1024, false)` (`:76`),
`selectedMayContainUnseenGroups` is **empty** (`:86-88`), and `evaluate` (`:205-215`) reads
`docs.get(3L * group + 1)` etc. with no `hasValue`, no `maxGroupId` and no `size()` check. For an
unseen group those indices land past `docs.size()`, and `BigIntArray.get` has no production bounds
check, so an index inside the last dirty page returns stale heap ints.

This would be worse than a byte leak: the three ints become a `DocVector` consumed by `ReadDimsExec`,
which loads dimension field values at that `(shard, segment, doc)` — surfacing fields of an arbitrary
document the query never matched, bypassing DLS/FLS. It is not reachable today only because the one
mechanism that manufactures unseen groups (`TimeSeriesAggregationOperator.expandWindowBuckets`,
`:225-266`) returns early for partial output modes while `FirstDocId` is injected only for INITIAL
(`ExtractDimensionFieldsAfterAggregation.java:71`). It also relies on an unenforced BlockHash
ordinal-monotonicity invariant. Treat as must-fix defence-in-depth.

## V-9 — transport-trust: `readArrayVector` trusts a stream-supplied byte count

`X-BigArrayVector.java.st:55-60` allocates `new$Type$Array(positions, false)` and calls
`values.fillWith(in)`; `AbstractBigByteArray.readPages` (`:111-118`) takes the byte count from
`in.readVInt()`. A count smaller than `positions * BYTES` leaves the tail of the last touched —
dirty, recycled — page unwritten, and the resulting vector's values flow into the `_query` response.
Requires the ability to forge a transport page (compromised node), so lower priority, but the
`, false` buys nothing here; make it `true` or validate the count against `positions`.

---

## Negative results

These were investigated and found correctly guarded. They are recorded because they bound the search.

- **Vendored `simdjson` is byte-identical to upstream v4.6.9** — `diff` of both `simdjson.h`
  (187,692 lines) and `simdjson.cpp` (65,360 lines) against the official release is empty. The
  `es_simdjson.cpp` wrapper is correct, and its claim that no readable padding past `offset + len` is
  required holds: `buf_block_reader::get_remainder` copies the tail into a stack buffer padded with
  `0x20`.
- **`libs/zstd`** — every `byte[]`/`ByteBuffer` entry point runs an overflow-safe
  `checkRange(offset, size, capacity)` (written as `offset > capacity - size`) before `asSlice`.
  `DStream.decompress` uses `checkFromToIndex` and caps output at the staging-buffer size.
- **Parquet decompressors** (`PlainCompressionCodecFactory`) — all five implementations guarantee
  every byte of the `UninitializedArrays` destination is written: Snappy pre-checks the declared
  length, Gzip loops to `destLen` with a trailing-byte check, Zstd passes `destLen` (not
  `dest.length`), LZ4 raw requires the exact size, and Hadoop-framed LZ4 uses explicitly
  overflow-safe comparisons.
- **ES|QL HTTP/S3 datasource buffers** — all three fill paths call
  `KnownLengthBodyFill.shortReadOrNull()` at completion and clamp with
  `position(0).limit(fill.offset())`, so a short body cannot expose the uninitialized tail.
  `DiscardingSubscriber` returns an empty buffer.
- **`withSliceAddresses` is genuinely bounded at runtime**, assertions off: the mmap path via
  `segmentSliceOrNull`'s `checkIndex(segOffset + len, seg.byteSize() + 1)` against the real mapped
  chunk, and the blob-cache path via `checkSlicesArgs` (a real throw) + region containment +
  `SparseFileTracker.checkAvailable`. There is no partial-tail case at EOF on either path. The three
  `reinterpret` sites in `Int7SQVectorScorer`/`Supplier` are safe because of this.
- **`libs/gpu-codec`** — zero `reinterpret`/`ofAddress`, no native bindings of its own, stride
  arithmetic correctly widened (`(long) i * rowPitch`), and **no reader at all**: both formats
  delegate `fieldsReader` to stock `Lucene99HnswVectorsReader`, so no attacker-crafted file reaches
  the mapping arithmetic.
- **The native write surface is closed.** Every native output buffer is either annotated (real
  generated check) or allocated from the very same length passed to native —
  `GetCompressedFileSizeW` allocates `arena.allocate(JAVA_INT)` internally; `GetShortPathNameW`
  allocates `ArenaAdapter.allocate(arena, JAVA_CHAR, cchBuffer)` with the same `cchBuffer`;
  `PosixCLibrary.send` has one caller with a constant-length systemd message.
- **Pure-Java paths are JVM-checked**, so they yield exceptions rather than corruption:
  `WordMask` is `long[]`-backed; `RecyclerBytesStreamOutput.seek(0)` + `bytes()` is correctly bounded
  by `position()` (so `ColumnarOffsetsBuilder`'s per-document stream rewind does not leak the previous
  document); `Utf8Sanitizer.sanitize` is read-only (returns the input or a fresh copy), so V-1's
  attacker-controlled `BytesRef` is never written through.
- HEAD commit `d7dac6d69` ("bound dictionary coverage during merges") is a compression-efficiency
  fix, not a memory-safety fix.
- **`server/.../escf/` and `server/.../sourcebatch/` are clean** on the uninitialized-memory axis: no
  `clearOnResize = false` and no `UninitializedArrays` anywhere in either package; all scratch,
  offset, type and validity buffers are plain Java arrays (JVM-zeroed).
  `EscfColumnBuilder.FixedNumericBuilder.addAbsent` explicitly writes zero slots, and
  `EscfBatchCodec.encodeBatch` derives every column-index length from the actual
  `BytesReference.length()` it wrote.
- **Most `clearOnResize = false` sites in the ES|QL compute engine are correctly gated**, which is
  what makes V-7/V-8 stand out. `SpatialExtentGroupingState`(`WrappedLongitude`) reads every array
  only under `hasValue(group)`; `IpArrayState.ensureCapacity` re-fills the grown region with `init`
  and bounds-checks `ipIndex + IP_LENGTH <= values.size()`; `X-FallibleArrayState.java.st:63` does
  `values.fill(prevSize, values.size(), init)`; `X-ValuesAggregator.java.st:232` creates its `seen`
  bitmap exactly when a gap first appears and back-fills `[0, maxGroupId+1)`;
  `TimeSeriesAdjacentGroups` explicitly `fill(0, numGroups, -1)`; `GroupedLimitOperator:104` writes
  `counts.set(ord, 0)` before any read; `LongTopNSet`/`IpBucketedSort`/`X-BucketedSort` never emit
  ungathered slots (gather-offset sentinels written into every newly allocated bucket root).
  All block/vector *builders* use plain Java arrays, so an under-filled position reads a JVM zero —
  which is why `AbstractBlockBuilder.writeNullValue()`'s no-op is benign.

## Reachability of the vector stack (context for V-3/V-5)

The native kernels are **on by default**: `ESVectorizationProvider.java:98` calls `lookup(true, true)`,
`JdkFeatures.SUPPORTS_HEAP_SEGMENTS` is `version >= 22`, and the library is enabled unless
`-Dorg.elasticsearch.nativeaccess.enableVectorLibrary=false` or `es.vec_caps_override=0`. No feature
flag or cluster setting gates it, and assertions are off — so the V-5 checks do not run.

`int8_*` → `Int7uOSQVectorScorer*`; `int4_*` → `Int4VectorScorer*`; `bbq_flat`/`bbq_hnsw` →
`NativeBinaryQuantizedVectorScorer`; `bbq_disk` → `StripedES940OSQVectorsScorer.NativeImpl` and
friends. Ordinary `create_index` + `write` + `read` privileges suffice; dynamic mapping of a
≥128-float array even reaches the native kernels with no explicit `index_options`
(`DocumentParser.java:784-805`). `bbq_disk` additionally requires an Enterprise license.

No request parameter reaches a bulk size or count, and the query vector length is validated against
`dims` (`DenseVectorFieldMapper.java:894-900`). User-controlled `dims` (1–4096) does flow into the
native `length`/`pitch` arguments.

## Priority

1. **V-1** — user-visible cross-request heap disclosure with full attacker control of the offset; a
   one-line bounds check closes it.
2. **V-2** — trivially reachable from a hand-written page header, no effective backstop.
3. **V-3** — annotate the six kernels and bind the `scoreBulkOffsets` guard to `count`. The primitive
   is real and demonstrated; only caller discipline is preventing it.
4. **V-7** — a one-line template fix (`hasValue(group)`) covering 24 generated aggregators on a GA
   function pair (`FIRST`/`LAST`); confirmed stale heap on the wire.
5. **V-8** — add the missing seen/range check before a stale doc id can become a DLS/FLS bypass.
6. **V-4** — one capacity check now, before the Arrow ingest path is wired up.
7. **V-5/V-6/V-9** — promote the load-bearing assertions to throwing checks; the `fc.map` size check;
   `clearOnResize = true` in `readArrayVector`.
