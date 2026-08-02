# Monitoring Platform — Specification (PoC)

Status: draft for implementation
Date: 2026-07-31

## 1. Purpose

Devices send arbitrary measurement data — CPU load, memory, GPS position, heart rate, anything —
to a central service that stores it and makes it queryable. The platform is intentionally
schema-agnostic: it does not know what a "gps" measurement looks like, only that one arrived.

Ingestion uses the **OpenTelemetry Protocol over HTTP with protobuf encoding** (`OTLP/HTTP`,
`application/x-protobuf`), and only the **logs** signal. Every data point the platform accepts
arrives as an OTLP `LogRecord`. Internally a data point is called a **measurement**.

More precisely, the platform accepts OTLP **Events**, not general logs: a measurement must carry
`event_name`, which is the field whose presence marks a `LogRecord` as an Event, and which supplies
the measurement's `type`. This is not a general-purpose log sink — records without `event_name` are
rejected (§4.4).

The service listens on a **Unix domain socket** for this PoC. An `iroh` transport for remote
devices is a planned follow-up and the HTTP layer is designed to be transport-agnostic so it can
be added without touching the ingest or storage code.

## 2. Scope

In scope:

- OTLP/HTTP protobuf logs receiver (`POST /v1/logs`).
- Mapping OTLP log records to measurements.
- Persistence in a single SQLite table.
- A read HTTP API (JSON) over the same Unix socket, for listing and filtering measurements.
- Unix domain socket transport with sane lifecycle handling.

Explicitly out of scope for the PoC (see §12 for what this defers):

- OTLP metrics, traces and profiles endpoints.
- Ingesting general log records. Only Events (records with `event_name`) are stored.
- OTLP/gRPC and OTLP/JSON encodings.
- Request compression other than `gzip` (no `zstd`, no `deflate`), and response compression of
  any kind.
- Authentication, authorization, TLS, multi-tenancy.
- Retention, downsampling, compaction. (Deduplication *is* handled — see §6.6.)
- Rate limiting, load shedding and `429` throttling with `Retry-After`. (`503` *is* returned for
  storage failure — see §4.1 — but never as a backpressure signal.)
- The `iroh` transport.
- Storing OTLP fields outside the measurement model (severity, trace/span ids, flags,
  `schema_url`, dropped-attribute counts) — these are parsed and discarded.

## 3. Data model

A **measurement** is the only domain entity.

| Field            | Type                        | Source                                                        |
|------------------|-----------------------------|---------------------------------------------------------------|
| `id`             | 16-byte content hash        | Derived from the four fields below except `processed_time` (§6.6) |
| `event_time`     | nanoseconds since Unix epoch | `LogRecord.time_unix_nano`, else `observed_time_unix_nano` (§5.3) |
| `processed_time` | nanoseconds since Unix epoch | Server clock when the request was received                    |
| `type`           | non-empty string            | `LogRecord.event_name`                                        |
| `body`           | JSON value, nullable        | `LogRecord.body` (`AnyValue`) mapped to JSON (§5.4)           |
| `attributes`     | JSON object                 | Merged resource / scope / record attributes, prefixed (§5.2)  |

`type` is the discriminator devices use to say what kind of data this is (`"cpu"`, `"gps"`,
`"heart_rate"`). The platform never interprets it beyond equality matching.

## 4. Ingest endpoint

### 4.1 Request

```
POST /v1/logs
Content-Type: application/x-protobuf
Content-Encoding: gzip          (optional)
Body: opentelemetry.proto.collector.logs.v1.ExportLogsServiceRequest
```

Validation, in order:

| Condition                                              | Response                                  |
|--------------------------------------------------------|-------------------------------------------|
| Method not `POST`                                      | `405 Method Not Allowed`                  |
| `Content-Type` not `application/x-protobuf`            | `415 Unsupported Media Type`              |
| `Content-Encoding` not absent, `identity` or `gzip`    | `415 Unsupported Media Type`              |
| Wire body larger than `max_body_bytes` (default 4 MiB) | `413 Payload Too Large`                   |
| Decompressed body larger than `max_decompressed_bytes` (default 32 MiB) | `413 Payload Too Large`   |
| Body is not valid gzip, when `gzip` was declared       | `400 Bad Request`                         |
| Body is not a decodable `ExportLogsServiceRequest`     | `400 Bad Request`                         |
| Storage write fails                                    | `503 Service Unavailable`                 |
| Otherwise                                              | `200 OK`                                  |

Storage failure returns `503`, not `500`, because OTLP's retryable-response-code table lists `503`
as retryable and `500` as not. A failed SQLite write — disk full, database locked — is transient, and the
device holding the only copy of that measurement should retry rather than drop it. No `Retry-After`
header is sent, so clients fall back to their own exponential backoff.

#### 4.1.1 Error response body

Every `4xx`/`5xx` from `/v1/logs` carries a protobuf-encoded `google.rpc.Status` with
`Content-Type: application/x-protobuf`, as the OTLP spec requires. Only `Status.message` is set,
holding a developer-facing reason. The spec permits omitting both other fields and says clients do
not act on `code`, so mapping HTTP statuses to canonical gRPC codes would be a table to maintain for
no consumer benefit.

`google.rpc.Status` is not part of `opentelemetry-proto`, and the crate that does ship it
(`tonic-types`) pulls in tonic, which this project otherwise avoids. The one field needed is
therefore declared locally with `prost::Message`:

```rust
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Status {
    #[prost(string, tag = "2")]
    pub message: String,
}
```

Omitting fields `1` and `3` is wire-compatible: proto3 does not emit defaults anyway, so a client
decoding with the full definition sees `code = 0` and empty `details`.

This applies to the OTLP ingest endpoint only. The read API (§7) is not an OTLP surface and returns
its errors as JSON.

Responses generated by the framework rather than by the handler — a `405` from method routing, for
instance — would otherwise carry a non-protobuf body. A `map_response` layer on the ingest route
rewrites any `4xx`/`5xx` that is not already `application/x-protobuf` into a `Status`. Because the
size limits and decompression are handled inside the handler (§4.2) rather than by middleware, that
layer is a backstop for framework responses only, not part of the normal error path.

### 4.2 Compression

`Content-Encoding: gzip` is accepted on ingest. It is worth supporting because protobuf is a
binary encoding, not a compressed one: it does no entropy coding and no cross-record
deduplication, and OTLP logs have no string table for attribute keys, so every record in a batch
repeats its key strings verbatim. Measured on representative batches, gzip gives ~3.7x on
f64-heavy bodies (gps, cpu) and ~8.3x when the body is a scalar and key strings dominate. Devices
on metered links benefit directly, and iroh's QUIC streams have no transport-level compression, so
this is the only compression lever once that transport lands.

Compression only pays off with batching — a single-record request measures 1.1x, where the gzip
header and deflate overhead nearly cancel the gain. Clients should batch; the platform does not
require it.

**Two independent size limits are mandatory**, because a small gzip payload can expand without
bound:

- `max_body_bytes` caps the **wire** body — bytes actually read from the socket.
- `max_decompressed_bytes` caps the **decompressed** stream, enforced during decompression so the
  request is abandoned as soon as the limit is crossed, never after buffering the whole thing.

A 4 MiB payload of gzipped zeros expands to gigabytes; without the inner limit that is a trivial
denial of service on the whole platform.

**Implemented in the handler, not as middleware.** Body reading, both limits and decompression live
in `api/ingest.rs` rather than in a `tower-http` layer stack. Two reasons: the ordering requirement
above ("inner" vs "outer" limit) becomes an explicit sequence rather than a property of how layers
were composed, which is easy to get wrong and hard to see; and every error then originates in our
handler and is already a protobuf `Status`, so the rewrite layer in §4.1.1 is left covering only
genuinely framework-generated responses such as `405`.

The default `max_decompressed_bytes` of 32 MiB is 8x the wire cap — well above the ~4x that
realistic telemetry achieves, and far below anything a bomb needs.

Unrecognized encodings are rejected with `415` rather than silently treated as `identity`, so a
client configured for `zstd` fails visibly instead of having its payload misread as corrupt
protobuf. Responses are never compressed, regardless of `Accept-Encoding`.

### 4.3 Response

`200 OK`, `Content-Type: application/x-protobuf`, body is an
`ExportLogsServiceResponse`.

- All records stored → the response message is empty (no `partial_success` field).
- Some records rejected → `partial_success` is set with `rejected_log_records` = number of
  skipped records and a human-readable `error_message`.

A request whose records are *all* rejected still returns `200` with a full-count
`partial_success`; this is what the OTLP spec prescribes and it prevents client-side retry storms
over data that will never be accepted.

### 4.4 Record rejection

A `LogRecord` is rejected — skipped, counted in `partial_success`, and logged at `warn` — when:

- `event_name` is empty. `type` has no other source; a measurement without a type is not storable.
- `time_unix_nano` **and** `observed_time_unix_nano` are both zero. OTLP requires
  `observed_time_unix_nano` to be set, so this is malformed input, and `event_time` cannot be
  derived from anything the record contains (§5.3).

Both rejections have the same shape: a required value is absent and the platform will not fabricate
one. Everything else is accepted — unknown attribute value shapes and absent bodies are handled by
the mapping rules in §5 rather than rejected.

**`event_name` is `[Optional]` in OTLP, not required.** The proto documents it as "a unique
identifier of event category/type… presence of `event_name` on the log record identifies this
record as an event." So requiring it is a deliberate narrowing: this endpoint accepts OTLP
**Events** only, and a plain log record — which is what a standard OTel logging bridge or appender
emits — is rejected.

That narrowing is intentional and doubles as a filter: the platform stores measurements, not
application logs, and a record with no `event_name` is by definition not a measurement. The
semantics also line up exactly, since OTLP expects all records sharing an `event_name` to conform
to the same body and attribute schema — precisely what a measurement `type` means here.

The practical consequence to be aware of: a device that ships both its application logs and its
measurements to this one endpoint will see every log record counted in `rejected_log_records`, and
a well-behaved exporter will report that as a partial failure. Devices must send measurements to
this endpoint and nothing else. If mixed traffic ever becomes a real deployment shape, the fix is
to silently drop `event_name`-less records instead of counting them as rejections — but staying
loud is the right default, since silence would also hide genuinely misconfigured devices.

The proto recommends `event_name` be short (≤256 characters). That is not enforced; `type` is a
`TEXT` column with no length constraint, and rejecting on length would fail records the platform
can store perfectly well.

Accepted records from one request are written in a **single transaction**. Rejection of some
records does not prevent the rest from being committed.

## 5. OTLP → measurement mapping

The mapping is a pure function:

```
to_measurements(request: ExportLogsServiceRequest, processed_time: i64)
    -> (Vec<Measurement>, Rejections)
```

It walks `resource_logs[] → scope_logs[] → log_records[]`.

### 5.1 `processed_time`

Captured **once per request**, at the moment the handler starts, from the system clock as
nanoseconds since the Unix epoch. Every measurement from that request shares the value, so a
batch is identifiable as one delivery.

### 5.2 Attributes

Attributes from the three OTLP levels are merged into one JSON object with a **flat key space** —
though the values themselves are not necessarily flat, see §5.2.1. Each key is the **structural path
to its source** in the OTLP message, so the prefix mirrors the protobuf field names:

| OTLP source                        | Key in `attributes`         |
|------------------------------------|-----------------------------|
| `ResourceLogs.resource.attributes` | `resource.attributes.<key>` |
| `ScopeLogs.scope.name`             | `scope.name`                |
| `ScopeLogs.scope.version`          | `scope.version`             |
| `ScopeLogs.scope.attributes`       | `scope.attributes.<key>`    |
| `LogRecord.attributes`             | `record.attributes.<key>`   |

Attribute maps live under an `attributes.` segment rather than directly under the level prefix.
This means **key collisions are structurally impossible**, not merely resolved: a scope attribute
named `name` becomes `scope.attributes.name` and cannot shadow the synthetic `scope.name`. There is
no precedence rule to get wrong, and the merge is order-independent.

It also keeps each level's namespace open. `record.severity` or `resource.schema_url` can be added
later without any chance of colliding with a device-supplied attribute — impossible under a flat
`resource.<key>` scheme, where a device sending an attribute named `schema_url` would occupy the
name we need.

`record.` rather than `measurement.` because a measurement is the whole row; these are the
attributes of the OTLP `LogRecord` specifically, and naming them after the source keeps the
distinction visible.

Rules:

- Values are mapped to JSON with the same `AnyValue` rules as the body (§5.4).
- `scope.name` / `scope.version` are synthetic: they are not OTLP attributes but are the only
  identification a scope carries, and they are too useful to drop. They are omitted when empty.
- OTLP requires keys to be unique within one attribute map. Duplicates are malformed input; last
  occurrence wins. This is the only case where write order matters.
- An attribute whose value is absent maps to JSON `null` rather than being dropped, so the key's
  presence is preserved.

The cost is longer keys — `resource.attributes.device.id` instead of `resource.device.id` — which
makes read-API filters more verbose and adds a few bytes per row. Worth it for a namespace that
cannot be corrupted by device input.

Example:

```json
{
  "resource.attributes.service.name": "fleet-agent",
  "resource.attributes.device.id": "dev-7",
  "scope.name": "sensors",
  "scope.version": "0.3.1",
  "record.attributes.unit": "celsius",
  "record.attributes.sensor.index": 2
}
```

### 5.2.1 Attribute values nest

An OTLP attribute is a `KeyValue`, whose `value` is an `AnyValue` — not a scalar. The proto is
explicit: "AnyValue may contain a primitive value such as a string or integer or it may contain an
**arbitrary nested object** containing arrays, key-value lists and primitives." So an attribute may
be `string → map`, `string → array of maps`, or any depth of either.

The platform stores these faithfully: attribute values go through the same §5.4 `AnyValue` → JSON
mapping as the body, so `kvlist_value` becomes a nested JSON object and `array_value` a nested JSON
array, recursively. Nothing is flattened and nothing is dropped.

```json
{
  "resource.attributes.device.id": "dev-7",
  "record.attributes.unit": "celsius",
  "record.attributes.calibration": { "offset": -0.5, "factor": 1.02 },
  "record.attributes.tags": ["rtk", "outdoor"]
}
```

Only the **key space** is flat. Prefixing applies to the top-level key of each attribute; the value
below it keeps whatever shape the device sent.

Two consequences, both spelled out where they bite:

- Nested attribute values are **stored and returned in full, but not filterable** (§7.1). Flattening
  them into dotted keys is not an option: OTLP keys legitimately contain dots (`service.name`), so
  `record.attributes.a.b` would be ambiguous between a literal key `a.b` and a path into a nested
  `a`.
- Note that the OTel semantic conventions for *trace and metric* attributes restrict values to
  primitives and homogeneous arrays. The **logs** data model is where nested values are legitimate,
  and logs is the signal this platform ingests — so nesting is expected input, not abuse.

### 5.3 `event_time`

`event_time` is the device's own statement of when the event happened:

1. `time_unix_nano`, if non-zero.
2. Otherwise `observed_time_unix_nano`, if non-zero.
3. Otherwise the record is **rejected** (§4.4).

This two-step chain is exactly what `logs.proto` prescribes for recipients that store a single
timestamp: *"Use `time_unix_nano` if it is present, otherwise use `observed_time_unix_nano`."* The
chain stops there because the same file requires `observed_time_unix_nano` to be set: *"This field
MUST be set once the event is observed by OpenTelemetry."* A record with both timestamps zero is
therefore malformed OTLP, and is rejected for the same reason a missing `event_name` is — the
platform is not in a position to invent the value.

There is no fall back to `processed_time`, and deliberately so: `processed_time` is **already its
own column**, recorded for every measurement regardless. Substituting it into `event_time` would
not preserve any information that isn't already stored; it would only make "event time unknown"
indistinguishable from "event time genuinely equals arrival time", encoding unknown-ness as an
implicit sentinel that every future query would have to know about. Rejecting keeps `event_time`
`NOT NULL` *and* keeps it honest.

Not validated: whether a non-zero timestamp is *plausible*. A device with no RTC that has not yet
reached an NTP server reports a clock near the Unix epoch — non-zero, conforming, and wrong. Such
records are stored with a 1970 `event_time`. This is the realistic form of a "broken clock", and it
is not detectable from a single record; see §12, which also covers why OTLP offers no relative or
monotonic timestamp to sidestep the problem.

### 5.4 `AnyValue` → JSON

| `AnyValue.value`      | JSON                                                            |
|-----------------------|-----------------------------------------------------------------|
| unset / `None`        | `null`                                                          |
| `string_value`        | string                                                          |
| `bool_value`          | boolean                                                         |
| `int_value` (i64)     | number, JSON integer — exact over the full i64 range (§5.5)      |
| `double_value`        | number, or string `"NaN"` / `"Infinity"` / `"-Infinity"`        |
| `array_value`         | array of mapped values                                          |
| `kvlist_value`        | object of `key` → mapped value                                  |
| `bytes_value`         | base64 string (standard alphabet, padded)                       |
| `string_value_strindex`| `null`, logged at `warn`                                       |

Non-finite doubles are not representable in JSON; encoding them as sentinel strings keeps the
column valid JSON without silently turning them into `null`. `string_value_strindex` only appears
in the profiling signal and the proto comments direct non-profiling receivers to treat it as
absent.

`body` is stored as `NULL` when the `LogRecord.body` message is absent, and as the JSON literal
`null` when the message is present but its `value` is unset — the two are distinguishable.

**Implementation trap:** `serde_json::json!(f64::NAN)` and `Value::from(f64::NAN)` silently yield
`null` — no error, no panic. Building double values through those APIs would quietly defeat the
sentinel-string rule above. Doubles must go through `serde_json::Number::from_f64`, which returns
`Option<Number>` and gives `None` for every non-finite input; that `None` is where the sentinel
string is produced. Verified empirically.

### 5.5 64-bit integrity

OTLP `int_value` is an `int64`, so values beyond 2^53 are legal input — and plausible here, since a
device may well put a nanosecond timestamp, a 64-bit device id or a byte counter in a body or
attribute. Every stage was checked against `i64::MIN`/`i64::MAX` and 2^53+1:

| Stage | Result |
|---|---|
| `serde_json::Value` round-trip | **Exact.** Integers use a dedicated integer variant (`is_i64() == true`, `is_f64() == false`), never f64. |
| `serde_json` f64 round-trip | **Bit-exact**, including `-0.0`, subnormals (`5e-324`) and `f64::MAX` — shortest round-trippable output. |
| SQLite `TEXT` column | No numeric conversion; text in, text out. |
| SQLite JSON1 (`json_extract`, `json()`) | **Exact** for the whole i64 range, returned with `typeof` = `integer`. (Beyond i64 it degrades to `real`, which OTLP cannot produce.) |

So values are exact at rest and through every query path the platform runs. Ingest is structurally
immune too: the device hop is protobuf, where `int_value` is a varint `int64`, so JSON never enters
it.

**The loss is client-side.** A JSON parser that represents all numbers as f64 silently corrupts
integers above 2^53: `9007199254740993` reads back as `9007199254740992`. This is a JavaScript
constraint, not a JSON one — RFC 8259 places no bound on digits and explicitly permits
implementations to set their own limits, and the 2^53 figure appears there only as an
interoperability note. Emitting full-range i64 and coercing it to f64 are *both* compliant, so
compliance guarantees nothing about agreement between them; the hazard can only be closed by
encoding or by client choice.

Two things break exactness before a web frontend does, and neither is prevented by staying in Rust:

- **The access site, not the parse site.** `Value::as_f64()` on a large integer is lossy even though
  the parse was exact, as is deserializing into a struct with an `f64` field. This is the likely
  failure here, because bodies are generic: code asking "give me this measurement's numeric value"
  must treat `int_value` and `double_value` uniformly, and the only uniform type is f64.
- **Aggregation, in any language.** Averages, sums, rates and downsampling are f64 operations, and a
  monitoring platform does them constantly.

So anything that *computes* over measurements has already accepted f64 semantics — fine for
aggregates, a bug for identifiers. Integer ids and counters therefore belong in attributes to be
matched, not in bodies to be averaged.

This is why `event_time_unix_nano` and `processed_time_unix_nano` are emitted as **strings** in §7:
they are fields the platform controls and always large. `body` and `attributes` stay as JSON numbers
because they are opaque passthrough — stringifying every integer would destroy the device's own
`int_value`/`string_value` distinction and make numeric comparison in clients impossible. Clients
needing values above 2^53 need a bigint-aware parser. Documented rather than papered over, since the
failure is silent.

#### Guidance for device instrumentation

Which OTLP value type to use, given all of the above:

- **Measured quantities → `double_value`.** CPU load, memory, temperature, kWh. f64 is bit-exact at
  every stage *including a JavaScript client*, since JS `Number` is binary64 — there is no
  conversion and therefore nothing to lose, at any magnitude. Floats are the unproblematic case.
- **Identifiers → `string_value`, in attributes.** Not merely safer: `AnyValue` has **no unsigned
  integer variant** — the only integer is `int_value`, an `int64` — so a `u64` above `i64::MAX`
  cannot be expressed as an OTLP number at all. This is a hard protobuf-level wall, not the silent
  2^53 rounding discussed above, and it is reached in practice by 64-bit hashes (xxhash64, siphash
  and similar use the full `u64` range). A device that casts `u64 → i64` wraps such values to
  negative: bit-preserving, but the sign is a lie and every query filter must then use the same
  wrapped form. String ids avoid all of it and need no special handling, since §7.1 already compares
  attribute values as text. `bytes_value` also round-trips exactly but leaves callers filtering on
  base64 text, which is worse to use.
- **Counters that will be summed → `int_value` if under 2^53, otherwise `double_value`** and accept
  the precision, or `string_value` and accept that aggregation must happen elsewhere. There is no
  option that is both exactly representable and directly aggregable above 2^53.

## 6. Storage

SQLite, one file, one table.

```sql
CREATE TABLE measurement (
  id             BLOB    PRIMARY KEY, -- content hash (§6.6); INSERT OR IGNORE makes ingest idempotent
  event_time     INTEGER NOT NULL,  -- nanoseconds since Unix epoch
  processed_time INTEGER NOT NULL,  -- nanoseconds since Unix epoch
  type           TEXT    NOT NULL,
  body           TEXT,              -- JSON, NULL when the record had no body
  attributes     TEXT    NOT NULL DEFAULT '{}'
) STRICT;

CREATE INDEX measurement_type_event_time_idx ON measurement (type, event_time DESC, id DESC);
CREATE INDEX measurement_event_time_idx      ON measurement (event_time DESC, id DESC);
```

- `STRICT` so the column types are enforced rather than advisory.
- A **rowid table, not `WITHOUT ROWID`**. Measured over 20 000 realistic rows, `WITHOUT ROWID` is
  *larger* (10176 KiB vs 9956 KiB), because secondary indexes must then carry the full 16-byte
  primary key as the row locator instead of a compact rowid.
- Times are `INTEGER` nanoseconds. i64 nanoseconds covers years 1678–2262; no measurement in this
  system will fall outside that.
- `body` and `attributes` are JSON text, queryable with SQLite's JSON1 functions
  (`json_extract`, `json_each`). Validity is enforced by construction — only the serializer
  writes these columns — not by a `CHECK` constraint, which would cost a parse per insert.
- The two indexes serve the read API's ordering (`event_time DESC, id DESC`), with and without a
  `type` filter.

### 6.1 Connection setup

Applied to every connection on open:

```
PRAGMA journal_mode = WAL;      -- concurrent readers alongside the writer
PRAGMA synchronous = NORMAL;    -- durable enough for a PoC, far faster than FULL
PRAGMA busy_timeout = 5000;
```

(No `foreign_keys` pragma: the schema has one table and no foreign keys, so enabling it would be
noise implying a constraint that does not exist.)

### 6.2 Migrations

Schema version tracked in `PRAGMA user_version`. On startup, migrations run forward from the
current version to the latest inside a transaction. The PoC ships version `1` — the table and
indexes above. A database whose `user_version` is *higher* than the binary knows about is a fatal
startup error, not a downgrade attempt.

### 6.3 Write path

A single dedicated writer owns the write connection; nothing else holds it. Requests reach it over
an mpsc channel carrying the batch plus a oneshot reply channel, so the HTTP handler learns the
real outcome (row count or error) and can answer accurately instead of optimistically.

One writer means no `SQLITE_BUSY` contention between concurrent ingests and no shared mutable
connection state. Inserts use a prepared statement reused across the batch inside one
transaction.

### 6.4 Read path

Reads open a short-lived read-only connection per request and run on
`tokio::task::spawn_blocking`. WAL mode allows these to proceed concurrently with the writer.
Opening a connection per request is measurably wasteful under load and is the first thing to
replace with a pool if the PoC outgrows it; it is chosen here because it holds no shared state.

### 6.5 Portability to Postgres

SQLite is a PoC choice; Postgres is the likely destination. Verified against Postgres 18.4, the
design migrates cleanly: `BIGINT` maps onto the nanosecond columns, and `jsonb` parses numbers into
arbitrary-precision `numeric`, so `i64::MIN`, `i64::MAX` and 2^53+1 all extract exactly. `jsonb` is
the right target for GIN indexing over the attributes map.

Three consequences worth recording now, since they constrain choices made here:

- **The sentinel-string rule for non-finite doubles (§5.4) is a migration prerequisite, not just a
  JSON-validity nicety.** `'{"a":NaN}'::jsonb` is a hard error in Postgres.
- **`jsonb` normalizes**: key order is not preserved, duplicate keys are dropped (matching §5.2), and
  `-0.0` becomes `0.0` since `numeric` has no signed zero. So never rely on attribute ordering.
- **f64 keeps its value but not its text form** — `1.7976931348623157e308` returns as a 309-digit
  expansion that re-parses to the identical f64. Any test asserting on exact JSON *text* would break
  after migration, which is why §11 asserts on parsed values instead.

### 6.6 Content-addressed ids and duplicate handling

**The id is a hash of what the device sent**, so uploading the same measurement twice is a no-op:
`INSERT OR IGNORE` on the primary key. Ingest is idempotent.

This is not decoration. The platform's own design invites retries. §4.1 returns a *retryable* `503`
on storage failure precisely so a device does not discard its only copy, and §6.3 has the handler
await the commit before responding — so if the connection breaks after the commit but before the
response lands, the device retries **correctly** and would otherwise double-store. That is structural
at-least-once delivery, and iroh will make lost acknowledgements far more likely than a local socket
does. OTLP offers no help: there is no request id, sequence number or idempotency key anywhere in
`LogRecord` or `ExportLogsServiceRequest`, so identity has to be derived from content.

Making it the *id* rather than a separate column buys something beyond enforcement: identity becomes
**intrinsic**. The same measurement has the same id on every machine, forever, rather than one
assigned by whichever server happened to store it first — so merging two databases is idempotent by
construction, which is what a device that buffers locally and syncs over iroh will need.

**What is hashed**: `event_time`, `type`, `body`, `attributes` — every column except the id itself
and `processed_time`. Excluding the arrival time is exactly what makes a retry hash identically.

`type` must be included explicitly and is easy to overlook: it comes from `event_name` into its own
column and never appears in the attributes map, so it is not recoverable from the attributes.
Hashing the body alone would be badly wrong — it would collapse `cpu {"usage":0.5}` with
`memory {"usage":0.5}`, collapse two devices reporting the same reading, collapse every idle-CPU
`0.00` into one row forever, and collapse all body-less records together.

**Canonicalisation is done by our own code, not by `serde_json`.** `serde_json::Map` is a `BTreeMap`
today, so its output happens to be key-sorted — but `preserve_order` is an *additive* Cargo feature,
so any crate anywhere in the dependency graph could enable it, turn `Map` into an insertion-ordered
`IndexMap`, and silently change every hash. Old rows would stop matching new ones and deduplication
would quietly stop working with no error. `src/content_id.rs` therefore:

- sorts object keys explicitly, never relying on map iteration order;
- preserves array order, which is semantic;
- type-tags every node, so `1`, `1.0`, `"1"` and `[1]` cannot hash alike;
- length-prefixes every field, so `type="ab", body="c"` cannot collide with `type="a", body="bc"`;
- distinguishes an absent body from a JSON-null body, which §5.4 keeps apart;
- normalises `-0.0` to `0.0`, because Postgres `jsonb` collapses them (§6.5) and an id must not
  change under a backend migration;
- uses `blake3` truncated to 16 bytes — **not** `DefaultHasher`, which is documented as unstable
  across Rust releases and would change every id on a compiler bump.

16 bytes is deliberate: with `INSERT OR IGNORE` a collision silently drops a *distinct* measurement,
a stronger requirement than ordinary hashing. At 128 bits, 10⁹ rows give a collision probability
around 10⁻²¹; at 64 bits, 10⁸ rows give roughly 1 in 3700.

**A suppressed duplicate is silently accepted**: `200`, empty `ExportLogsServiceResponse`, and *not*
counted in `rejected_log_records`. From the device's perspective the measurement is stored — which it
is. Counting it as rejected would turn a correct retry after a lost acknowledgement into a permanent
partial-failure signal.

Two consequences to accept:

- **The duplicate rate is visible only server-side.** A device stuck in a retry loop costs bandwidth
  and CPU while producing no row growth and no error, so it will not show up in the disk-space
  monitoring §12 relies on.
- **Coarse device clocks.** Two genuinely distinct readings sharing an `event_time`, `type`, value
  and attributes collapse into one. Only reachable when a device's clock resolution is coarser than
  its sampling rate — a 1 kHz sensor with a 1-second clock repeating a value. Safe for any device
  whose clock ticks faster than it samples.

## 7. Read API

JSON over the same Unix socket. Times in responses are RFC 3339 UTC with nanosecond precision,
alongside the raw nanosecond value as a string (JSON numbers cannot hold i64 nanoseconds without
loss in most clients). `id` is the content hash (§6.6) as lowercase hex, which also places it
permanently outside the 2^53 concern in §5.5.

### 7.1 `GET /v1/measurements`

Query parameters:

| Parameter      | Meaning                                                                 |
|----------------|-------------------------------------------------------------------------|
| `type`         | Exact match on `type`. Repeatable → matches any of the given types.     |
| `from`         | Inclusive lower bound on `event_time`. RFC 3339 or integer nanoseconds. |
| `to`           | Exclusive upper bound on `event_time`. Same formats.                    |
| `attr.<key>`   | Exact match on an attribute, e.g. `attr.resource.attributes.device.id=dev-7`. |
| `limit`        | Default `100`, maximum `1000`.                                          |
| `cursor`       | Opaque pagination cursor from a previous response.                       |

- `attr.<key>` compares the attribute's JSON value against the parameter as a string, so
  `attr.record.attributes.unit=celsius` and `attr.record.attributes.sensor.index=2` both work.
  Multiple `attr.*` parameters are ANDed.
- **`<key>` is always one whole literal key, never a path.** It is matched as a single quoted JSON
  path segment and never split on `.`. This is forced by the input: OTLP keys legitimately contain
  dots, so `attr.record.attributes.a.b` cannot be disambiguated between a literal key `a.b` and a
  descent into a nested `a`. Both are expressible in SQLite (`$."a.b"` vs `$.a.b`) but only one can
  be meant, and the literal reading is the one that always refers to something the merge in §5.2
  actually produced.
- **The bound parameter is the whole JSON path, not the key.** A path fragment cannot be bound
  inside a path literal, so the path string is assembled in Rust and bound in full:

  ```sql
  json_type(attributes, ?1) NOT IN ('object','array')
  AND CAST(json_extract(attributes, ?1) AS TEXT) = ?2
  ```

  with `?1` = `$."record.attributes.unit"` and `?2` = `celsius`. Verified that SQLite accepts a
  bound path.

  **The `CAST` is required, not cosmetic.** `json_extract` returns an `INTEGER` for a JSON number,
  and SQLite never compares an `INTEGER` equal to the `TEXT` query parameter `'2'` — so
  `attr.record.attributes.sensor.index=2` matches nothing without it. This was caught by test rather
  than by reading: the "compares as a string" semantics above simply do not hold otherwise. With the
  cast, text, integer, real and boolean attributes are all reachable through the one text-valued
  parameter; note booleans extract as `1`/`0`, which is how SQLite represents them. Assembling the path means escaping: `"` and `\` within the key must be
  backslash-escaped when building it. This matters because a malformed path **fails silently** —
  SQLite returns `NULL` rather than an error, so a filter with an unescaped quote in its key would
  match nothing instead of complaining. The path builder is therefore a tested pure function, not
  inline string concatenation.
- **Only scalar attribute values are filterable.** Attribute values nest (§5.2.1), hence the
  `json_type` guard above. Without it, `json_extract` on a nested value returns its *serialized JSON
  text*, which compares equal if a caller happens to type that exact text — verified:
  `json_extract('{"k":{"a":1}}', '$.k') = '{"a":1}'` is true. That would be an accidental API
  resting on SQLite's exact serialization, and §6.5 records that Postgres `jsonb` reorders keys and
  inserts spaces, so it would break silently on migration. Excluding non-scalars makes the behaviour
  defined and portable: a nested attribute is fully stored and fully returned, and simply never
  matches a filter.
- Ordering is always `event_time DESC, id DESC` — newest first, `id` breaking ties so pagination is
  stable when timestamps collide. Since `id` is a content hash (§6.6), ties break in hash order
  rather than arrival order: arbitrary, but total and deterministic, which is all keyset pagination
  requires. SQLite compares blobs with memcmp, so that ordering matches the hex form the API exposes.
- `cursor` is a base64 encoding of the last returned `(event_time, id)` and is applied as a
  keyset predicate. Keyset rather than `OFFSET` so pagination stays correct while data is being
  ingested.
- Unknown query parameters are a `400`, so typos in filter names fail loudly instead of silently
  widening the result set.

Response:

```json
{
  "measurements": [
    {
      "id": "039041fb15b6a5539cc42c9bd709363e",
      "event_time": "2026-07-31T09:14:02.123456789Z",
      "event_time_unix_nano": "1785489242123456789",
      "processed_time": "2026-07-31T09:14:02.170000000Z",
      "processed_time_unix_nano": "1785489242170000000",
      "type": "gps",
      "body": { "lat": 47.4979, "lon": 19.0402, "alt_m": 105.2 },
      "attributes": {
        "resource.attributes.device.id": "dev-7",
        "scope.name": "sensors",
        "record.attributes.unit": "wgs84"
      }
    }
  ],
  "next_cursor": "eyJ0IjoxNzg1NDg5MjQyMTIzNDU2Nzg5LCJpIjo0MX0"
}
```

`next_cursor` is `null` when the page is the last one.

### 7.2 `GET /healthz`

`200` with `{"status":"ok"}` once the socket is bound and migrations have completed. Used by the
integration tests to wait for readiness, and by non-systemd supervisors. Under systemd, readiness is
reported properly via `sd_notify(READY=1)` (§9.2) rather than by polling this endpoint.

## 8. Transport

### 8.1 Unix domain socket

- Path from `--socket`, default `./monitoring-platform.sock`.
- On startup, if the path exists: if it is a socket and no listener accepts a connection, it is a
  stale socket and gets unlinked; if it is a socket with a live listener, startup fails (another
  instance is running); if it is not a socket, startup fails without touching the file. Never
  unlink a path that was not verified to be a dead socket.
- Mode set to `0o660` after bind. Note this is *not* sufficient on its own: between `bind()` and
  `chmod()` the socket carries `0777 & ~umask`, usually `0755`. Access control therefore rests on the
  containing directory being `0750` and group-owned (§9.2 provisions this via `RuntimeDirectory`);
  the `chmod` is defence in depth, not the mechanism.
- `SIGINT`/`SIGTERM` trigger graceful shutdown: stop accepting, let in-flight requests finish,
  drain the writer channel, checkpoint WAL, unlink the socket.

Clients reach it with `curl --unix-socket ./monitoring-platform.sock http://localhost/v1/logs ...`. Note
that OTel language SDK exporters cannot target a Unix socket directly — for the PoC, device
traffic is either produced by a client that speaks HTTP over the socket, or bridged. This is the
gap the `iroh` transport closes.

### 8.2 Planned: iroh

The HTTP layer is built as `fn app(state: AppState) -> Router` and served over an arbitrary
listener; `axum::serve` accepts `tokio::net::UnixListener` directly. Adding iroh means accepting
`iroh::endpoint::Connection` streams and driving the same `Router` over them with
`hyper::server::conn`, in a new `transport/iroh.rs`. No change to `api`, `otlp` or `store`.

## 9. Configuration and deployment

### 9.1 CLI

Single binary, two subcommands:

```
monitoring-platform serve
  --socket <path>            [MP_SOCKET]  default $RUNTIME_DIRECTORY/monitoring-platform.sock
                                                  else ./monitoring-platform.sock
  --db <path>                [MP_DB]      default $STATE_DIRECTORY/measurements.db
                                                  else ./measurements.db
  --max-body-bytes <bytes>   [MP_MAX_BODY_BYTES]  default 4194304   (4 MiB, wire)
  --max-decompressed-bytes <bytes>
                             [MP_MAX_DECOMPRESSED_BYTES]  default 33554432  (32 MiB)
  --log-level <level>        [MP_LOG_LEVEL]       default info

monitoring-platform wait-for-clock       # the §9.4 boot gate; exit 1 if the clock stays bad
  --threshold-micros <us>    [MP_CLOCK_THRESHOLD_MICROS]     default 5000000  (5 s)
  --poll-interval-secs <s>   [MP_CLOCK_POLL_INTERVAL_SECS]   default 5
  --max-polls <n>            [MP_CLOCK_MAX_POLLS]            default 60       (~5 min)
  --consecutive <n>          [MP_CLOCK_CONSECUTIVE]          default 3
  --log-level <level>        [MP_LOG_LEVEL]       default info
```

`wait-for-clock` is run as the service's `ExecStartPre`, and is useful on its own to diagnose a
host that will not start monitoring: it logs the measured error on both the success and the
refusal path.

Resolution order: CLI flag → environment variable → systemd directory (`$RUNTIME_DIRECTORY`,
`$STATE_DIRECTORY`, set by the unit in §9.2) → relative-path default for development. Parsing
produces an immutable `Config` value that is passed down; no global state, no re-reading the
environment after startup.

Deriving the defaults from systemd's directory variables rather than hardcoding `/var/lib/...` means
the binary needs no knowledge of deployment paths, works unprivileged in a checkout, and cannot
disagree with what the unit actually provisioned.

### 9.2 systemd

The service is long-running and supervised. Three details are not merely packaging concerns — they
change the program — so they are settled here rather than left to whoever writes the unit:

**Readiness.** `Type=notify`, with `sd_notify(READY=1)` sent after migrations have completed and the
socket is listening. Under `Type=simple` systemd considers the service started the moment it
forks, so any dependent unit can race a client connection against our `bind()`. `sd-notify` 0.5
depends only on `libc` — no `libsystemd`, no `pkg-config` — so it costs nothing in the Nix build.
A `NOTIFY_SOCKET` that is absent (development, tests, non-systemd hosts) makes the call a no-op.

**Socket permissions.** §8.1 sets mode `0660` *after* `bind()`. Between those two calls the socket
carries `0777 & ~umask` — typically `0755`, i.e. world-connectable. The window is short but real,
and the fix is not a smaller window: the socket lives in `RuntimeDirectory=monitoring-platform`
with `RuntimeDirectoryMode=0750`, so directory traversal gates access regardless of the socket
inode's own mode at any instant. The post-bind `chmod` stays as defence in depth.

**Stale sockets.** `RuntimeDirectory=` is created fresh on start and removed on stop, so the
stale-socket reclamation in §8.1 cannot normally trigger under systemd. It stays for development
runs and non-systemd hosts, where it is the only thing preventing a dead socket from blocking
startup.

```ini
[Unit]
Description=Monitoring platform OTLP receiver
# Deliberately no start rate limit; see §9.4. This is a [Unit] key: in [Service] systemd
# parses it and then drops it with "Unknown key ... ignoring", so the setting does nothing.
StartLimitIntervalSec=0

[Service]
Type=notify
# Fail-closed clock gate (§9.4). No "-" prefix: its failure must fail the unit.
ExecStartPre=/usr/bin/monitoring-platform wait-for-clock
# Must exceed the gate's own poll budget, or the wait is killed mid-flight.
TimeoutStartSec=420
ExecStart=/usr/bin/monitoring-platform serve
Restart=on-failure
RestartSec=60s

StateDirectory=monitoring-platform
StateDirectoryMode=0700
RuntimeDirectory=monitoring-platform
RuntimeDirectoryMode=0750
User=monitoring-platform
Group=monitoring-platform

# hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX
RestrictNamespaces=yes
MemoryDenyWriteExecute=yes
CapabilityBoundingSet=
# NOT ProtectClock=yes, and @clock named explicitly: the gate must read adjtimex(2). See §9.4.
ProtectClock=no
SystemCallFilter=@system-service @clock
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
```

Notes on specific lines:

- `RestrictAddressFamilies=AF_UNIX` enforces the PoC's local-only property in the kernel, not just
  by convention. **This is the line that must change when iroh lands** (it needs `AF_INET`
  `AF_INET6`), and it is deliberately restrictive now so that adding a network transport is a
  visible, reviewed edit rather than something that silently starts working.
- `Group=` is what local clients need membership of to reach the socket. A `DynamicUser=yes` setup
  is tempting for a service holding no long-lived identity, but it makes the owning group transient
  and therefore awkward to grant clients access to; a static system user is simpler here.
- `Restart=on-failure` matters more than it looks: §6.2 makes a database whose `user_version`
  exceeds the binary's a *fatal* startup error, and §8.1 fails startup when the socket path is
  occupied by a live listener or a non-socket file. Those are permanent conditions, and a start
  rate limiter (5 starts / 10 s) is what would turn an infinite restart loop into a failed unit
  that reports the reason. **§9.4 disables that limiter and explains the trade** — fail-closed
  clock gating means a device that boots without a network must be allowed to keep retrying for
  hours, so the unit above is superseded on this point by what the module generates.
- Graceful shutdown (drain the writer, checkpoint WAL, unlink) runs on `SIGTERM`, which is systemd's
  default stop signal, so no `KillSignal=` override is needed. The default `TimeoutStopSec` is
  ample for a WAL checkpoint.

**Socket activation is deliberately not used.** It would fix the permission race declaratively and
avoid `ECONNREFUSED` during restarts, but it adds a second listener-acquisition path for a benefit
that is temporary: iroh, not the Unix socket, is the transport devices will actually use, and iroh
cannot be socket-activated. What the PoC does instead is structural — the listener is **constructed
by the caller and passed into** the serve function (§8.2 already requires this for iroh), so adding
`LISTEN_FDS` support later is a new constructor and no change to the server.

### 9.3 NixOS

The target is NixOS, so the shipped artefact is a **NixOS module, not the `.service` file above**.
On NixOS units are generated from `systemd.services.<name>`; a hand-written unit file has to be
carried in via `systemd.packages` or `environment.etc` and then cannot be typechecked, overridden,
or referenced by other options. The unit in §9.2 is the specification of what the module must
generate — useful as documentation and for non-NixOS hosts, but not the deliverable.

**There is no flake, deliberately.** `nix/module.nix` is a plain NixOS module and
`nix/package.nix` is a plain `callPackage` function, so a target system consumes them as files:

```nix
imports = [ "${monitoring-platform}/nix/module.nix" ];
services.monitoring-platform.enable = true;
```

where `monitoring-platform` is however the system already fetches this repo — a `flake = false`
input, `fetchGit`, a submodule or a path. A flake would add nothing here and would cost something
real: a second pinned nixpkgs that the target system does not deploy, which is a standing invitation
to test against the wrong one. That works directly against the property §11.1 exists to establish.
It also avoids the experimental-features friction noted in §10.3.

The module provides `enable`, `package`, `user`, `group`, `socketPath`, `databasePath`,
`maxBodyBytes`, `maxDecompressedBytes` and `logLevel`, creates the system user and group, and
generates the unit with the hardening above. `socketPath` and `databasePath` default to the
systemd-provisioned directories and exist as options mainly so a second instance can run alongside.

`package` defaults to `pkgs.callPackage ./package.nix { }`, so the binary is built by the **target
system's own nixpkgs** — its `rustPlatform`, its `stdenv`. That is the point rather than a
convenience, and it has one obligation attached: this crate must state an MSRV and fail the build
clearly when the consumer's Rust is older. The tempting fix for such a failure is to pin our own
`rustc`, which would defeat the whole arrangement.

### 9.4 Clock synchronization gating

`processed_time` (§5.1) is read from the system clock on every request, so a host whose clock is
wrong writes rows that look exactly like correct ones. §5.3 already refuses to invent an
`event_time`; this is the same refusal applied to the server's own clock. **The service does not
start until the clock is verifiably synchronized.**

**The check.** `maxerror` from `adjtimex(2)`, the kernel's own estimate of how wrong the clock may
be, compared against a threshold. Two properties make this the right primitive:

- **It is daemon-agnostic.** It reflects kernel state whichever implementation set it, so the gate
  behaves identically under chrony, systemd-timesyncd, ntpd-rs or NTPsec and depends on none of
  them. Referencing `chrony.service` would tie the platform to one deployment's choice.
- **It needs no wait unit.** `time-sync.target` is not depended on either: NixOS enables no unit
  that provides it (`chrony-wait`, `systemd-time-wait-sync`) by default, so the target is reached
  early and means nothing. The poll is authoritative.

`STA_UNSYNC` is deliberately ignored. That bit is set for reasons unrelated to clock quality —
notably to stop the kernel writing back to the RTC — so `maxerror` alone is the test, which is
also what systemd itself uses (it treats `<16 s` as synchronized).

**The threshold** defaults to 5 s and is generous on purpose. `maxerror` grows continuously
between successful NTP updates at the kernel's 500 ppm tolerance — 500 µs per second of wall time
— so with chrony's default `maxpoll 10` (~1024 s between updates) it routinely reaches ~0.5 s in
entirely healthy operation. Tightening to 1 s without also setting `maxpoll 9` on the host would
make the gate flap against that sawtooth rather than detect anything. Three consecutive good polls
are required as further hysteresis against it.

**Gate at start, not continuously.** Stopping and restarting the service whenever the clock
degrades was rejected: it loses in-memory state and creates gaps in telemetry precisely when
something is wrong. The service is a normal unit — `systemctl start`/`stop` behave conventionally —
and once running it is never stopped for clock reasons. Runtime clock handling (tagging records
with a quality field, exporting the error as a metric) belongs in application code and is not in
this PoC.

**Fail-closed.** Implemented as `ExecStartPre` with no `-` prefix, so its non-zero exit fails the
unit. It re-runs on every restart, so the clock is rechecked on each retry and on crash-loop
recovery. `systemctl start` therefore blocks for up to the wait budget on a cold boot, and
`systemctl is-system-running` reports `starting` meanwhile — harmless unless something downstream
polls for `running`.

**The wait is bounded by counting polls, never by a wall-clock deadline.** `SystemTime`, `date` and
the shell's `$SECONDS` all derive from the very clock being waited on: the first successful sync
steps it, and a deadline computed from it jumps unpredictably at exactly the wrong moment. An
iteration counter plus a `CLOCK_MONOTONIC` sleep cannot be moved by a clock step. `TimeoutStartSec`
is derived from `maxPolls × pollIntervalSecs` rather than hard-coded, because it must exceed the
gate's own bound — the systemd default of 90 s would kill the wait mid-flight and turn a
deliberate failure into an accidental one.

**It is a subcommand, not a script.** `monitoring-platform wait-for-clock` makes the syscall
directly rather than shelling out to `adjtimex --print`, which also sidesteps the fact that
`pkgs.adjtimex` does not exist in current nixpkgs (it is not in `util-linux` either). It keeps the
hysteresis and give-up rules as pure functions with ordinary unit tests, and it needs no second
package output.

**Two sandbox consequences**, both in `nix/module.nix`:

- `ProtectClock=` must be **off**. `systemd.exec(5)` is explicit that it cannot allow a read:
  *"the system calls are blocked altogether, the filter does not take into account that some of
  the calls can be used to read the clock state with some parameter combinations."* It kills with
  SIGSYS, and `ExecStartPre` shares the unit's sandbox. Nothing is actually given up:
  `CapabilityBoundingSet=` is empty and `NoNewPrivileges=` is set, so `CAP_SYS_TIME` is
  unavailable and the service still cannot *set* the clock; `PrivateDevices=` already withholds
  `/dev/rtc*`.
- `@clock` must be named in `SystemCallFilter=`. It is not part of `@system-service`, so
  `adjtimex` would otherwise be denied even with `ProtectClock=` off.

**The start rate limiter is disabled** (`StartLimitIntervalSec=0`, a **`[Unit]` key** — NixOS
exposes it as `systemd.services.<name>.startLimitIntervalSec`, not through `serviceConfig`,
where systemd would parse it and then drop it with *"Unknown key … ignoring"*), reversing part
of §9.2. That
limiter existed to turn a permanent startup failure — a schema newer than the binary (§6.2), an
occupied socket (§8.1) — into a failed unit that reports the reason instead of an endless loop.
Fail-closed gating trades it away: a device that boots without a network legitimately fails for
hours, and a limiter would give up permanently during exactly the outage it must survive. The cost
is real — a genuinely permanent failure now retries every 60 s rather than stopping and saying so —
but the journal still names the reason on every attempt.

The section matters more than it looks, and is asserted rather than trusted: a directive in the
wrong section is *accepted by the parser and dropped*, so it fails as "the setting quietly had no
effect" rather than as an error. `nix/tests/cases/hardening.nix` therefore reads
`StartLimitIntervalUSec` back from systemd and greps the boot journal for `Unknown key`, which
catches the whole class.

**Host-side configuration is out of scope for this repo**, and belongs to the system configuration
that deploys it. Recorded here because the gate's behaviour depends on it: chrony is the
recommended daemon for a fleet of laptops that suspend and intermittently-powered Pis; `rtcsync` so
the kernel synchronized state is maintained; `makestep 1.0 3` to limit stepping to the first three
updates, since a clock jumping backwards during operation corrupts time series; `maxpoll 9` if a
tighter gate threshold is wanted; `nocerttimecheck 1` on an RTC-less Pi using NTS, to break the
bootstrap deadlock where TLS certificate validation needs a roughly correct clock; and at least
four time sources.

Approaches considered and rejected, recorded so they are not reinvented:

| Approach | Why rejected |
|----------|--------------|
| `Condition*=` / `Assert*=` | Evaluated once at start, never re-checked; no clock condition exists anyway |
| A separate `clock-good.service` with `Upholds=` + `BindsTo=` | Works, but `Upholds=` makes a manual `systemctl stop` impossible (the unit is revived within seconds); too much machinery for boot-only gating |
| `After=time-sync.target` alone | Pure ordering; vacuous when nothing provides the target |
| `Requires=` on a gate unit | Does not propagate when the dependency exits on its own |
| `WantedBy=` as a persistent intent bit | Evaluated once at target activation; not a standing invariant |
| Stopping the service on clock drift | Loses telemetry during exactly the incidents worth observing |

## 10. Implementation notes

### 10.1 Layout

```
src/
  main.rs              CLI, wiring, signal handling, shutdown ordering
  lib.rs               AppState
  bin/
    mp-make-sample.rs  writes a sample OTLP batch; a shipped bin, not an example, so
                       the VM tests and the §11 manual check get it from the package
  config.rs            Config value + resolution
  clock.rs             §9.4 boot gate: adjtimex(2) read + pure poll/hysteresis rules
  model.rs             Measurement, StoredMeasurement, Rejections
  otlp/
    convert.rs         pure: ExportLogsServiceRequest -> (Vec<Measurement>, Rejections)
    anyvalue.rs        pure: AnyValue -> serde_json::Value
    test_support.rs    OTLP payload builders, shared by unit and integration tests
  store/
    schema.rs          migrations, pragmas
    write.rs           writer task, insert_batch
    read.rs            query building, JSON path builder, row mapping
  api/
    mod.rs             Router construction
    ingest.rs          POST /v1/logs: limits, decompression, conversion
    query.rs           GET /v1/measurements, /healthz
    status.rs          google.rpc.Status + the non-protobuf error rewrite layer
  transport/
    uds.rs             bind, permissions, stale-socket handling, cleanup
tests/
  ingest.rs            router-level OTLP ingest
  read_api.rs          router-level read API
  end_to_end.rs        the compiled binary over a real socket, incl. SIGTERM
nix/                   see §10.3 for this tree
```

`transport/uds.rs` *constructs* a listener and hands it back; it does not run the server. `main.rs`
passes that listener to the serve call. This is what keeps both iroh (§8.2) and a possible future
`LISTEN_FDS` socket-activation constructor (§9.2) additive rather than invasive.

The conversion and query-building layers are pure functions over owned data; all I/O lives in
`store`, `transport` and `main`.

### 10.2 Dependencies

| Crate                | Version | Notes                                                      |
|----------------------|---------|------------------------------------------------------------|
| `tokio`              | 1.53    | `rt-multi-thread`, `net`, `signal`, `sync`, `macros`, `time` |
| `axum`               | 0.8     | implements `Listener` for `tokio::net::UnixListener`       |
| `opentelemetry-proto`| 0.32    | `default-features = false`, features `gen-tonic-messages,logs` — pre-generated prost types, **no `protoc` at build time** |
| `prost`              | 0.14    | decode/encode of the OTLP messages, and the local `Status` |
| `rusqlite`           | 0.40    | feature `bundled` — vendored SQLite, no system lib         |
| `serde` / `serde_json`| 1      | JSON mapping and read-API responses                       |
| `flate2`             | 1.1     | gzip decompression, called directly so both size limits stay explicit (§4.2) |
| `base64`             | 0.23    | `bytes_value` encoding, pagination cursor                  |
| `jiff`               | 0.2     | RFC 3339 ⇄ i64 nanos: `Timestamp::from_nanosecond` / `as_nanosecond` |
| `clap`               | 4.6     | `derive`, `env`                                            |
| `sd-notify`          | 0.5     | `Type=notify` readiness (§9.2); only dep is `libc`, and it is a no-op when `NOTIFY_SOCKET` is unset |
| `anyhow`             | 1       | error context on startup and storage paths                 |
| `tracing` / `tracing-subscriber` | 0.1 / 0.3 | structured logs, `env-filter`                |
| dev: `tower`         | 0.5     | `ServiceExt::oneshot` for router-level tests                |
| dev: `http-body-util`| 0.1     | collecting response bodies in tests                        |
| dev: `tempfile`      | 3       | throwaway databases and sockets                            |
| dev: `libc`          | 0.2     | sending `SIGTERM` in the end-to-end test                    |

Deliberately *not* used: `tower-http` (see §4.2 — the limits are enforced in the handler) and
`tonic-types` (see §4.1.1 — the one `Status` field is declared locally).

`opentelemetry-proto`'s `logs` feature pulls in `opentelemetry` and `opentelemetry_sdk` for its
transform module; that is accepted in exchange for not needing `protoc` or vendored `.proto` files
in the build.

### 10.3 Nix build

No flake (§9.3). The layout follows the `nix-utils` convention in `sashee/dotfiles`: a thin
entrypoint that is the *only* place a channel is fetched, with all logic in files that take `pkgs`
explicitly and have no defaults, so a caller who forgets an argument gets an eval error rather than a
silent channel fetch.

```
nix/
  pkgs.nix           the ONLY fetchTarball; shared by default.nix, the Makefile and CI lint
  default.nix        convenience entrypoint; `nix-build nix`
  package.nix        { lib, rustPlatform, stdenv }: buildRustPackage
  module.nix         the NixOS module (§9.2, §9.3)
  tests/
    default.nix      repo-specific: a minimal machine, then calls ./lib.nix
    lib.nix          generic harness: takes pkgs + machineModules (§11.1)
    cases/*.nix      one file per case
Makefile             the entry points CI uses
```

```sh
make all                         # lint, build, then every VM test one at a time
make build                       # package only (its doCheck runs the Rust suite)
make run-tests                   # every VM test, one nix process each
nix-build nix -A tests.platform  # one test directly
```

Building the bare top level (`nix-build nix`) requires every VM test to pass: `default.nix`
interpolates each test derivation's store path in a `postBuild`, which registers it as a build input.
That is convenient locally but **wrong for CI**: it makes one nix process evaluate every NixOS machine
at once, and each such eval costs 1–2 GiB that the Boehm-GC evaluator never returns to the OS. A
combined eval has OOMed CI runners in sibling repos. `make run-tests` therefore lists the test names
cheaply (`attrNames` forces no derivations) and then evaluates and runs each in its own short-lived
process, so memory stays bounded by one eval plus one VM however many tests are added.

What makes the build unproblematic:

- `rusqlite/bundled` and `opentelemetry-proto`'s pre-generated types mean **no `protoc`, no system
  SQLite, no network access** during the build. Only a C compiler is needed.
- `Cargo.lock` is committed, so `cargoLock.lockFile` works with no vendor hash to maintain.
- `doCheck = true` runs the whole Rust suite in the sandbox, including the end-to-end tests that
  spawn the binary and bind sockets — they need no network and no `/dev/kvm`, only `TMPDIR`.
- `src` is filtered to the Rust sources and manifests, so editing `SPEC.md` or the nix files does not
  invalidate the build.
- Because there is no flake, none of this needs the `nix-command` or `flakes` experimental features —
  worth noting since this machine's `/etc/nix/nix.conf` does not enable them.

### 10.4 CI

`.github/workflows/ci.yml`, following the `sashee/dotfiles` layout: two jobs, both preceded by a
disk-reclaim step and 8 GiB of swap, both calling the Makefile.

| Job | Runner | Runs |
|---|---|---|
| `build` | `ubuntu-latest` | `make ci-lint`, `make build`, `make run-tests` |
| `build-arm` | `ubuntu-24.04-arm` | `make build`, `make run-tests` |

Notes on the choices:

- **The arm runner is real aarch64 hardware**, so the Rust build there is native and only the NixOS
  VMs are emulated. Those run under TCG because the free arm64 runner has no `/dev/kvm` — which is
  exactly why `nix/tests/default.nix` drops the `kvm` requirement rather than merely tolerating it.
  This job is the only thing in the repo that says anything about the architecture the rpi5 runs.
- **Lint runs only on x86**, since clippy findings are architecture independent.
- **`make ci-lint` pins the lint toolchain to `nix/pkgs.nix`**, the same one the package is built with.
  `nix-shell -p clippy` would take the *installer's* channel, so a nixpkgs bump there could introduce
  a new lint and turn CI red with nothing in this repo having changed. Bumping `nix/pkgs.nix` can still
  do that, but then it is a reviewed change.
- Actions are pinned by commit SHA with the version in a trailing comment.
- **No formatting check.** The code is not `rustfmt`-clean (137 sites with defaults, 41 even with
  `use_small_heuristics = "Max"`), so adding one requires a one-time reformat first — a deliberate
  decision, not an oversight.

## 11. Verification

Unit tests (pure functions, no I/O):

- `AnyValue` → JSON for every variant, including nested arrays/kvlists, non-finite doubles, bytes,
  unset values, and `string_value_strindex`.
- 64-bit integrity (§5.5): `i64::MIN`, `i64::MAX` and 2^53+1 as `int_value` in a body and in an
  attribute survive conversion → JSON text → SQLite → read back → `json_extract`, comparing equal
  to the original `i64`. Asserted on the integer, not on the JSON text, so the test stays valid if
  the serializer's formatting changes.
- Non-finite doubles produce the sentinel strings, *not* `null` — the regression test for the
  `json!`/`Number::from_f64` trap in §5.4.
- Content ids (§6.6). The one the whole scheme rests on: the same attributes inserted in **shuffled
  order** produce an identical id, at the top level and nested. Plus: array order *does* matter;
  `processed_time` does not; every other hashed field does, including `event_time` by 1 ns; absent
  body ≠ JSON-null body; `1` ≠ `1.0` ≠ `"1"` ≠ `[1]`; `-0.0` = `0.0`; and
  `type="ab", body="c"` ≠ `type="a", body="bc"` — the length-prefix regression test. A pinned hex
  vector makes an accidental encoding change visible rather than silent.
- Attribute merging: the structural prefix for each level, `scope.name`/`scope.version` synthesis
  and their omission when empty, absent values becoming `null`.
- Collision-freedom: a payload carrying scope attributes literally named `name` and `version`, plus
  record and resource attributes named `attributes`, produces a map where every input is present
  and distinct — the property the `attributes.` segment exists to guarantee.
- `event_time`: taken from `time_unix_nano` when set; from `observed_time_unix_nano` when
  `time_unix_nano` is zero; record rejected when both are zero.
- Rejection of empty `event_name` and of both-zero timestamps, with the surviving records in the
  same batch still converted. A record failing both checks is counted once, not twice.
- Query building: filter combinations, cursor round-trip, `limit` clamping, unknown-parameter
  rejection.
- The JSON path builder (§7.1): keys containing `"`, `\`, `.`, `[`, `]`, `$` and `*` all produce paths
  that match the intended key. Verified that unquoted/unescaped variants fail *silently* in SQLite
  (`NULL`, not an error), which is why this is a unit-tested function rather than inline formatting.
- Nested attributes (§5.2.1): a `kvlist_value` and an `array_value` attribute, including nesting
  inside nesting, convert to the equivalent nested JSON with nothing flattened or dropped, and are
  returned intact by the read API.
- Nested attributes are not filterable: a filter whose value is the attribute's exact serialized
  JSON text does **not** match, which is the regression test for the `json_type` guard. A literal
  key containing dots (`a.b`) *is* matchable, and does not accidentally resolve as a path into a
  nested `a`.

Integration tests:

- Build the router over a temp-file database, `POST` an encoded `ExportLogsServiceRequest` via
  `tower::ServiceExt::oneshot`, assert the stored rows and the `ExportLogsServiceResponse`.
- Mixed batch → `200` with the exact `rejected_log_records` count and the valid rows committed.
- Idempotent ingest (§6.6): re-posting a batch returns `200` with **no** `partial_success` and
  stores nothing; a partly-overlapping batch stores only its new records; the same measurements
  re-framed across different requests still do not duplicate; a duplicate does not move the stored
  `processed_time`, since first arrival wins. And the other direction — two records differing by a
  single nanosecond are both stored, so deduplication cannot be swallowing real data.
- Content-type, content-encoding, body-size and malformed-protobuf rejections.
- Every `4xx`/`5xx` from `/v1/logs` has `Content-Type: application/x-protobuf` and a body that
  decodes as `google.rpc.Status` with a non-empty `message` — asserted for handler-generated errors
  *and* for the middleware-generated ones (body limit, decompression), since those are the cases the
  rewrite layer exists to cover. A table-driven test over every error case, so a newly added error
  path that returns the wrong content type fails.
- The locally declared `Status` round-trips against a decoder that also expects fields `1` (`code`)
  and `3` (`details`), confirming the omissions are wire-compatible.
- Compression: an identical batch sent as `identity` and as `gzip` produces byte-identical stored
  rows; an unrecognized `Content-Encoding` gives `415`; a body declaring `gzip` that is not valid
  gzip gives `400`.
- Both size limits, independently: a wire body over `max_body_bytes` gives `413`; a small gzip
  bomb (a few hundred KB of compressed zeros, expanding past `max_decompressed_bytes`) gives `413`
  **and** the process memory does not grow by the decompressed size — this is the test that proves
  the limit is enforced streaming rather than after buffering.
- Read API: filter by `type`, time range and attribute; paginate to exhaustion and assert no
  duplicates or gaps.
- End-to-end over a real Unix socket in `TMPDIR`: bind, `GET /healthz`, ingest, query, `SIGTERM`,
  assert the socket file is gone.
- Stale-socket handling: leave a dead socket file behind and assert startup reclaims it; leave a
  regular file and assert startup fails without deleting it.

Deployment (§9.3, §10.3):

- Config resolution order (§9.1): flag beats env beats `$STATE_DIRECTORY`/`$RUNTIME_DIRECTORY` beats
  the relative default. Pure-function test over an injected environment map, not the real process
  environment.
- `sd_notify` is a no-op when `NOTIFY_SOCKET` is unset — otherwise every test and every development
  run would fail on a missing socket.
- VM tests that enable the module, wait for the unit to reach active, and then reach `/healthz` and
  `/v1/logs` over the socket. These are the only tests that exercise `Type=notify`, the provisioned
  directories and the hardening set together — in particular they are what would catch
  `RestrictAddressFamilies` or `SystemCallFilter` being too strict, which unit tests cannot see. See
  §11.1 for how they are wired, which matters more than usual here.

Manual check:

```sh
mp-make-sample sample-logs.pb   # 3 records: gps, cpu, heart_rate
monitoring-platform serve --socket /tmp/mp.sock --db /tmp/mp.db &
curl --unix-socket /tmp/mp.sock http://localhost/healthz
curl --unix-socket /tmp/mp.sock -H 'Content-Type: application/x-protobuf' \
     --data-binary @sample-logs.pb http://localhost/v1/logs
# same payload, gzipped
gzip -c sample-logs.pb > sample-logs.pb.gz
curl --unix-socket /tmp/mp.sock -H 'Content-Type: application/x-protobuf' \
     -H 'Content-Encoding: gzip' \
     --data-binary @sample-logs.pb.gz http://localhost/v1/logs
curl --unix-socket /tmp/mp.sock 'http://localhost/v1/measurements?type=gps&limit=5'
sqlite3 /tmp/mp.db 'select id, type, event_time, attributes from measurement;'
```

### 11.1 VM test wiring: injected `pkgs`, real host module

VM tests follow the `nix-utils/tests` pattern from `sashee/dotfiles`: the harness is a **function
taking `pkgs` and the machine under test**, so the consuming system supplies both. The split is:

- `nix/tests/lib.nix` — the generic harness. Knows nothing about how the machine was assembled. It
  layers on what the cases need (a client user in the service group, one outside it, `curl`, `sqlite`,
  the package) and runs the cases via `pkgs.testers.runNixOSTest`.
- `nix/tests/default.nix` — this repo's assembly: a minimal machine that just imports the module,
  then calls `lib.nix`. Also applies `dropKvm` so tests schedule on KVM-less builders.
- `nix/tests/ntp-node.nix` — the time source every test network needs, so the §9.4 clock gate is
  satisfied the way a real host satisfies it. See below.
- `nix/tests/test-cert.nix` — mints a throwaway CA + leaf for a set of SANs, used to impersonate
  the fleet's NTS servers. A copy of the equivalent helper in the consuming repo rather than a
  shared input, since this repo takes none.
- `nix/tests/eval-checks.nix` — does the harness *evaluate* against a real host config? No VM.
- `nix/tests/cases/*.nix` — one file per case, `{ pkgs }: { testScript; isolate ? false;
  machineModules ? []; ntpNodeModules ? []; waitForService ? true; }`, independent of the
  machine. `ntpNodeModules` layers onto the time-source node and `waitForService` opts out of
  the harness's readiness wait; both apply only to isolated cases, and both exist for
  `clock-gate` (below).

A target system tests the service against its **own** configuration by importing the harness directly:

```nix
import "${monitoring-platform}/nix/tests/lib.nix" {
  inherit pkgs;
  machineModules = [ self.nixosModules.common-desktop ];  # the real host config
}
# => { platform = <shared VM>; restart = <own VM>; ... }
```

Each entry is a two-node network: the machine under test plus the time source described below.

`nix-build nix -A tests.platform` in this repo is the weaker run, against a synthetic machine and
whatever channel `nix/default.nix` pins. The authoritative run is the consumer's.

Lightweight cases run as subtests on one shared VM booted once; a case marking `isolate = true` gets
its own VM, for cases that must stop and start the unit. `node.pkgsReadOnly = false` is set so a
consumer's `machineModules` may set `nixpkgs.config` or overlays without a `types.unique` collision.

**Every test network has a real time source.** A VM with no NTP server sits at the kernel's 16 s
unsynchronized `maxerror` ceiling forever, so the §9.4 gate would refuse to start the service in
every case. The harness does not switch the gate off to work around that — that would leave the
production configuration unexercised in exactly the tests meant to validate it. Instead
`nix/tests/ntp-node.nix` adds a second node running chrony as an island (`local stratum 10`,
`allow all`, no upstream). Every case therefore boots through the real gate, and `wait_for_unit`
waits it out. That node does **not** import `machineModules`: it is a helper, not a thing under
test, and importing the consumer's host config would double the closure and drag in whatever
else that config enables.

**The machine's own timekeeping is impersonated, not overridden.** How the machine is pointed at
that node is read off the machine rather than imposed on it, because `lib.nix` is imported by
other repos with their *real* host config:

- **No daemon** (this repo's synthetic machine) — `timesyncd` is forced on and aimed at the node.
- **chrony** — its configuration is left completely alone. Only two things are injected: an
  `/etc/hosts` entry resolving `services.chrony.servers` to the helper, and, for an NTS client,
  the helper's CA in `security.pki.certificateFiles`. The helper then serves **real NTS**
  (`ntsservercert`/`ntsserverkey` from `nix/tests/test-cert.nix`, NTS-KE on 4460), with SANs read
  from that same server list so they cannot drift. The production config runs unmodified and
  performs a genuine NTS-KE handshake — pointing it at a plain local NTP server instead would
  test a configuration nobody deploys.
- **ntpd / openntpd / ntpd-rs** — an assertion naming the daemon. These cannot be aimed at the
  helper, and the alternative is a five-minute gate timeout with no explanation.

The distinction matters more than it looks: writing `services.timesyncd.enable = mkForce true`
next to a daemon that sets `mkForce false` is not a merge but an **evaluation error**, so no VM
is ever built and no VM test can catch it. `nix/tests/eval-checks.nix` is the guard — it runs the
harness against each daemon plus chrony+NTS and forces the module system, in seconds and without
booting anything. `make eval-checks` gives each machine its own nix process, for the same reason
`run-tests` gives each VM one.

Two isolated cases cover the gate itself:

- **`clock-gate`** layers `chronyd.wantedBy = mkForce []` onto the time-source node, so "no
  working NTP" is the machine's genuine state — nothing simulates a bad clock — and starting
  chronyd is what flips it. Asserts both directions at the production threshold. Observed values
  confirm the mechanism: `clock_error_us=16000000` before, `2000` after.
- **`clock-gate-nts`** runs the fleet's shape, chrony with `enableNTS`. Beyond the gate opening,
  it asserts `chronyc -N authdata` reports the source as `NTS` with a non-zero cookie count —
  without that, a silent fallback to plain NTP would synchronise the clock, open the gate and
  look identical.

**Why this matters more here than for a typical service.** §9.2 leans heavily on systemd sandboxing —
`RestrictAddressFamilies=AF_UNIX`, `SystemCallFilter=@system-service`, `ProtectSystem=strict` — and
§11 states that VM tests are the *only* thing that can catch one of those being too strict. That
claim only holds if the VM runs the systemd the target actually runs, because sandbox semantics are
version-dependent and a filter that is permissive enough on one systemd can deny a syscall on
another. A test VM built from this repo's own pinned nixpkgs would validate the hardening against a
systemd nobody deploys. Injected `pkgs` is what makes the hardening test meaningful rather than
decorative.

The same argument applies to the socket group check: `Group=` access is only testable where real
users and groups exist, which is a property of the host configuration, not of a minimal VM that
enables one service.

Two further consequences worth stating:

- Because the harness is called with whatever `pkgs` the caller has, the same cases run unchanged
  against multiple targets (x86 host, Raspberry Pi) exactly as the `doh.nix` / `doh.nix`-for-rpi split
  does in `nixos-test`. For a platform whose whole purpose is collecting from heterogeneous devices,
  an aarch64 run is worth having early.
- It puts an MSRV obligation on this repo (§9.3): the consumer's `rustc` builds the binary, so the
  crate must state its minimum and fail the build clearly when unmet.

The cases. Everything below the first two is unreachable from the Rust suite:

| Case | Asserts |
|---|---|
| `readiness` | `healthz` answers with no retry loop; plus the runtime/state directory modes and that the database is in the StateDirectory |
| `ingest` | protobuf in → rows in SQLite → JSON out, over the real socket as an unprivileged client; gzip and identity store identical rows; the integer attribute filter |
| `socket-access` | a member of the service group connects and a non-member is refused *by the filesystem* — needs real users, so it cannot be expressed on a minimal machine |
| `hardening` | the sandbox options read back from `systemctl show` (catching a silent option rename), then a full ingest cycle with no `seccomp`/`SIGSYS`/`EPERM` in the journal and `NRestarts == 0` |
| `ordering` (isolated) | a oneshot unit ordered `After=` the service curls the socket **once at boot, with no retry**. This is the only case that distinguishes `Type=notify` from `Type=simple`, and therefore the only one that justifies the `sd-notify` dependency (see below) |
| `restart` (isolated) | a clean `Result=success` stop, WAL checkpointed to a single file, rows surviving, and migrations being a no-op on the existing database |
| `crash-recovery` (isolated) | `SIGKILL`, then `Restart=on-failure` recovery: every *acknowledged* row survives, `pragma integrity_check` is `ok`, and the database is writable again |

Two of these need their reasoning stated, because it is not obvious from the assertions:

- **`ordering` is what verifies `Type=notify`, not `readiness`.** `readiness` cannot tell the two
  service types apart: by the time the test driver asks, a `Type=simple` service would have finished
  starting anyway, so it would pass either way. `ordering` puts the probe at boot with no retry, where
  reporting readiness before `bind()` makes the unit fail and nothing later can hide it.
- **`crash-recovery` is what validates `synchronous = NORMAL`** (§6.1). In WAL mode `NORMAL` is durable
  against an application crash — the WAL write has reached the OS — and only concedes durability
  against power loss. `SIGKILL` is exactly the application-crash case, and the acknowledgement rule in
  §6.3 makes the test fair: a `200` means committed, not queued, so no acknowledged row may be lost.
  It deliberately does *not* exercise the stale-socket reclamation in §8.1: systemd removes
  `RuntimeDirectory` on stop and recreates it, so that path is only reachable off systemd, where the
  Rust end-to-end tests cover it.

One property is worth stating explicitly because it shaped the cases: the lightweight cases share one
VM, so they see each other's rows. Every assertion is therefore **relative** — a delta against a count
taken at the start of the case, never an absolute row count. Absolute assertions pass in isolation and
fail as soon as another case is added, which is a needlessly confusing way to find out.

## 12. Open questions

- Implausible-but-conforming timestamps are stored as-is (§5.3). A device without an RTC that has
  not yet synced NTP sends a non-zero clock near the Unix epoch, which passes every check. Options
  when this shows up in practice: reject `event_time` outside a plausible window relative to
  `processed_time`; or store it and expose the skew, since `processed_time - event_time` is already
  computable per row and a large positive skew is exactly the signal. The latter is preferable —
  it is a query, not an ingest policy, and it does not discard data.

  A device with a *stable* offset is already recoverable from stored data, since both clocks are kept.
  The unrecoverable case is a clock that is wrong **and drifting**.

  **OTLP offers no help here: it has no relative or monotonic timestamp representation.** Every
  timestamp field across all ten protos is `*_unix_nano`, absolute since the Unix epoch; the only
  relative value anywhere in the protocol is `duration_nano` in the profiles signal, and even that is
  paired with an absolute anchor. The protocol assumes every producer has a wall clock, and
  `observed_time_unix_nano` — its one concession to clock disagreement — is also absolute, so it
  distinguishes two clocks but does not substitute for a missing one.

  If it becomes necessary, the workable scheme needs no protocol support, because the anchor is
  already server-side. The device sends monotonic clock readings as ordinary attributes — one per
  record for the event, one per batch for the moment of sending — and the platform derives:

  ```
  event_time ≈ processed_time − (monotonic_at_send − monotonic_at_event)
  ```

  Accuracy is bounded by transport and queueing delay between send and receipt: negligible over the
  Unix socket, larger and more variable over iroh.

  Two constraints on doing this, if it is done:

  - **It must not silently overwrite `event_time`.** A derived value indistinguishable from a
    device-reported one is exactly the fabrication §5.3 refuses. It needs a provenance marker
    recording which of `time_unix_nano`, `observed_time_unix_nano` or monotonic derivation produced
    the stored value. The namespacing in §5.2 already accommodates this: device attributes live under
    `record.attributes.*`, so a synthetic `record.event_time.source` cannot collide with device input
    — one of the reasons that scheme was chosen.
  - **Such a device still has to satisfy §5.3.** OTLP requires `observed_time_unix_nano` to be set, so
    a genuinely clockless device is non-conforming by construction and would be rejected. It must
    send its best-effort clock however wrong, and rely on the monotonic attributes for accuracy
    rather than as a substitute.
- **No way to query by `processed_time`.** `from`/`to` and both indexes cover `event_time` only, so
  "what arrived in the last hour" is not answerable through the API, and a device with a wrong clock
  is invisible to every query — the operational counterpart of the clock discussion above. Deferred
  deliberately for the PoC; inspect arrivals with the `sqlite3` CLI meanwhile. Adding it later is
  `received_from`/`received_to` plus an index on `(processed_time DESC, id DESC)`, which leaves the
  pagination cursor keyed on `event_time` and so changes nothing already specified.
- Attribute filtering is exact-match only. Range and prefix queries on attributes will need either
  the JSON1 expression indexes hinted at in §6, or the normalized attribute table that was
  considered and deferred.
- Filtering *into* a nested attribute value is unsupported (§7.1) and needs a syntax decision, not
  just code: because OTLP keys contain dots, a path filter needs either an explicit separate
  parameter (`attr_path=record.attributes.cfg/mode`) or an escaping rule for dots within a key.
  Deferred until there is a real query that needs it, since the wrong syntax is hard to withdraw.
- Aggregation endpoints (averages, rates, downsampling) are not in the PoC, and adding them is the
  point at which the platform stops being exact and starts being f64 — see §5.5. That is the right
  trade for aggregates, but it means such an endpoint must not be the only way to read a value, or
  64-bit identifiers become unreadable.
- `zstd` beats gzip on both ratio and CPU and is gaining traction in OTel exporters. Adding it is a
  second decoder behind the same `Content-Encoding` dispatch and the same two size limits; deferred
  only to keep the PoC's dependency surface small.
- `iroh` will introduce device identity (node public keys). Whether that becomes a first-class
  measurement column or a `resource.attributes.*` entry is a decision for that step. Note the
  namespacing in §5.2 leaves a third option open: a synthetic `transport.node_id` alongside
  `scope.name`, provably free of collision with anything a device can send.
