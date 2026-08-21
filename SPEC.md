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
- A browser interface on that same socket — login, the recent measurements, and the credential
  tables — for one operator (§14).
- Unix domain socket transport with sane lifecycle handling.

Explicitly out of scope for the PoC (see §12 for what this defers):

- OTLP metrics, traces and profiles endpoints.
- Ingesting general log records. Only Events (records with `event_name`) are stored.
- OTLP/gRPC and OTLP/JSON encodings.
- Request compression other than `gzip` (no `zstd`, no `deflate`), and response compression of
  any kind.
- Authorization, TLS, multi-tenancy. (Authentication *is* handled — API keys in §13, an operator login
  in §14. A key is either valid or not; there are no scopes, no roles, and no key or user is tied to a
  device or a tenant.)
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

Schema version tracked in `PRAGMA user_version` as **`major.minor`**. On startup, migrations run
forward from the current version to the latest inside a transaction.

**Why the version has two components.** A blanket "a newer database is fatal" rule is right for a
change that rewrites data — version 2 dropped and recreated `measurement` — and wrong for one that
only adds a table. Applying it to both makes *every* schema bump an irreversible deployment, and
reverting to an older binary is routine on the deployed host rather than exceptional: it runs
`system.autoUpgrade` nightly, so a hand-switched generation is replaced by whatever the pipeline last
delivered. Under a single version number that revert turned into a permanent startup failure retrying
every 60 s, with `/healthz` down and nothing reporting it (§9.2, §9.4).

The split confines the fatal case to the changes that genuinely are fatal:

| Database vs. binary | Outcome |
|---|---|
| newer major | **Fatal.** It may have rewritten data this binary cannot read. |
| same major, newer minor | **Runs**, with a `warn!` naming both versions. Applies nothing, writes nothing. |
| equal | No-op. Nothing is written. |
| older | Migrated forward, in one transaction. |

**What may be a minor bump.** Nothing in code can enforce this; it is a discipline on the content of
a migration, and accepting a newer minor is only sound while it holds. A minor bump may only:

- `CREATE TABLE` — a table an older binary neither reads nor writes;
- `CREATE INDEX`;
- `ALTER TABLE … ADD COLUMN` that is nullable or has a default, on a table an older binary writes.
  That binary's `INSERT` does not name the column, so the column must be satisfiable without it. (On a
  STRICT table `ADD COLUMN` requires a declared type, and a `NOT NULL` addition requires a non-null
  default — consistent with this rule.)

Everything else is a major bump: dropping or renaming a table or column, changing a column's type,
adding a constraint an older binary's writes could violate, adding `NOT NULL` without a default, or
changing the meaning of existing data.

The test is not "is it additive in SQL" but **"would the previous binary still behave correctly
against it"**. Version 2 is the illustration of the answer being no.

**Encoding.** `user_version` is a 32-bit signed integer, so the two components pack into it — and the
packing is chosen so that introducing the scheme rewrote nothing:

```
encode(major, 0)     = major                  # the legacy form, unchanged
encode(major, minor) = major * 1000 + minor   # minor > 0
decode(raw)          = if raw < 1000 then (raw, 0) else (raw / 1000, raw % 1000)
```

A bare `N` therefore reads as `N.0`, which is what every database written before this scheme already
holds, and a version with no minor component is written back in that same bare form. So a deployed
3.0 database still has `user_version = 3` literally, and a binary from before major.minor still reads
it. That property is the point: a scheme whose own arrival broke the binary it replaced would have
been self-defeating. `decode` is total over the whole range regardless, since `user_version` can be
hand-edited to anything; `3000` also reads as 3.0 even though nothing writes it. Both components are
bounded below 1000, or a major of 1000 would be indistinguishable from 1.0.

**The first three versions are grandfathered.** They shipped as the single numbers 1, 2 and 3 and so
denote 1.0, 2.0 and 3.0. Under the rule above, 3.0 only added `api_key` and *would* have been 2.1 —
but it is already deployed, and renumbering a database in the field buys nothing. The scheme applies
from here on; this is not an inconsistency to go and fix.

The versions that exist:

| | added | kind |
|---|---|---|
| 1.0 | `measurement`, keyed by rowid | — |
| 2.0 | content-addressed ids (§6.6): `measurement` dropped and recreated | major, and the illustration of why majors exist |
| 3.0 | `api_key` (§13) | additive, but shipped as a single number |
| 3.1 | `web_user`, `web_session` (§14) | **minor** — the first under this scheme |
| 3.2 | `series` + a nullable `measurement.series_id` + the backfill index (§6.7) | **minor**, and phase one of a two-phase change |
| 3.3 | `measurement_series_event_time_idx`, for the read path's move onto the join (§6.7) | **minor** — the risky half of 4.0, done where it can be reverted |
| 4.0 | `measurement` rebuilt without `type`/`attributes`, `series_id NOT NULL` + foreign key, `web_session.username` foreign key, foreign keys enabled (§6.7) | **major**, and the second in this project's life |

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

### 6.7 The `series` table

`measurement` carries `type` and `attributes` on every row, and those two columns identify *the time
series* rather than describing what was measured. Measured on the deployed database:

| | |
|---|---|
| rows | 117,952 |
| distinct `(type, attributes)` | **1,458** |
| replication | **81×** overall; 428× for `bms.status.cell` (47,904 rows over 112 series) |
| `attributes` text | 60.85 MB — **50.1% of the file** |

So half the database is 1,458 distinct strings written out 81 times each, growing at ~516 bytes of
duplicated JSON per row against a projected ~8.9M rows/year (§9.3).

`series` holds each combination once, keyed by a hash of it, and `measurement.series_id` points at it.

**Identity.** `series_id` is the 128-bit blake3 prefix of a canonical encoding of `type` +
`attributes`, under the domain `monitoring-platform/series/v1`. It shares the encoder in
`crate::content_id` with §6.6's measurement id rather than copying it, so it inherits the explicit key
sort — a device sending the same attributes in a different order lands in the same series — and the
length prefixing and type tagging. A distinct domain prefix means a series id and a measurement id
cannot coincide. 128 bits for the same reason as §6.6: a collision under `INSERT OR IGNORE` silently
merges two distinct series, which is worse than an error.

Timestamps and the body are **not** in the key. They are what a measurement measured; including
either would mint a new series per measurement, which is the failure this table exists to prevent.

**Bookkeeping, and why every one of those columns is named `added_*`.**

| column | means |
|---|---|
| `added_measurements` | rows this database has ever *stored* for this series |
| `added_event_time_min` / `_max` | the device-time extent of those rows |
| `added_processed_time_min` / `_max` | the arrival-time extent of those rows |

The prefix scopes all five to the **insert stream**: monotonic, never revised downward, explicitly not
a description of what the table currently holds. Today they happen to agree with `count(*)` and
`min(event_time)` over `measurement`. The day something starts deleting rows — expiration, retention —
they stop agreeing, and only these columns still know what the series ever carried. A column called
`num_measurements` or `min_event_time` would quietly become a lie at that point, and a stale timestamp
reads as data in a way a stale count does not. So the naming carries the guarantee, and nothing ever
recomputes these from the table: a recompute would replace "ever added" with "currently present",
which is the exact substitution the names rule out.

`added_measurements` counts rows **stored, not presented**. §6.6 makes a re-upload a no-op, so the
write path folds a measurement into the bookkeeping only after its `INSERT OR IGNORE` reports a row —
otherwise a device retrying after a lost acknowledgement would inflate the count. Both writes share
one transaction, so a measurement can never be stored uncounted or counted unstored.

**This is deliberately a two-phase change.**

- **Phase one, 3.2.** Add `series`, add a *nullable* `measurement.series_id`, write both. Nothing is
  dropped and nothing reads `series` yet, so a 3.1 binary works against the result unchanged.
- **Phase one and a half, 3.3.** Point the **read** path at the join, and add the index it needs. Still a
  minor: `measurement.type` and `measurement.attributes` are still written and still present, so a
  reverted binary reads them exactly as before.
- **Phase two, 4.0.** Rebuild `measurement` without `type` and `attributes` and with `series_id NOT NULL`
  referencing `series`, and delete the backfill machinery entirely. This is what reclaims the ~62 MB, and
  it cannot be a minor: dropping a column a running 3.2 binary selects is precisely what §6.2's majors are
  for. It required 3.3 to have reached the host through the pipeline first — see below.

**Why the read path moves in 3.3 rather than in 4.0.** 4.0 is the only migration that cannot be
rehearsed on the deployed host: it must arrive through the pipeline, and once applied there is no
reverting to a binary that expects the dropped columns. Rewriting every read *and* dropping the columns
in that one step would put the risky half — a hundred lines of query construction — where it can neither
be tested live nor rolled back. Doing the reads first, in a revertible minor, leaves 4.0 as pure DDL
with **no accompanying code change at all**.

That is also why `read.rs` has exactly one `FROM` constant. `measurement` still carries both columns, so
the only thing keeping a query off the stale copy is that no query names it — and one constant is what
makes that checkable rather than hoped for. A test de-synchronises the two copies and demands the
`series` answer from every read: rows, the type list, both filter halves, facet discovery, the extent
query and the aggregated chart query.

The rollback story still holds, and it is what makes 3.3 safe: a revert takes the *code* back too, so a
3.2 binary reads `measurement.type` as it always did. A revert followed by an update is fine as well —
the older binary leaves rows with no `series_id`, and the next 3.3 startup's sweep assigns them before
the socket is bound.

**The join is inner, so an unassigned row is invisible** — which turns the sweep from a tidiness concern
into a correctness precondition, and is why a failed backfill is **fatal** from 3.3 on (§6.7 below, and
`main.rs`). It is skipped entirely for queries that read neither `type` nor `attributes`: the join cannot
remove a row, so omitting it is result-preserving, and it saves ~85 ms on a landing-page render.

**The fill is a convergence sweep, not a migration step**, and that is the load-bearing decision. A
one-shot fill inside the 3.2 migration would leave a hole, and not at the head of the table where it
would be noticed:

1. 3.2 migrates and fills every row.
2. The nightly `system.autoUpgrade` reverts to the 3.1 binary. It *starts fine* — the entire point of
   a minor version — but its `INSERT` does not name `series_id`, so every row it writes gets NULL and
   no `series` row.
3. Rolling forward leaves an arbitrary interior range unfilled, with nothing marking it.

So the invariant is not "the migration filled it" but **a 3.2 binary running drives the gap to zero**.
`store::series::backfill` runs on **every startup**.

`measurement_backfill_idx`, partial on `series_id IS NULL`, **is the work queue**. It costs
O(unfilled) rather than O(table), collapses to nothing once the fill converges, makes "how many are
left" an index probe cheap enough for a page render, and — the point — a row written by a reverted 3.1
binary enters it automatically. It is deliberately temporary; 4.0 drops it.

**The fill is per-series, not per-measurement**, and that is what makes it affordable. One grouped scan
(`GROUP BY type, attributes` over the queue) yields the 1,458 distinct pairs with their `count`/`min`/
`max` computed by SQL; the hashing and the upserts then run 1,458 times rather than 118,718. A single
set-wise `UPDATE`, correlated on `(type, attributes)` through `series_type_attributes_idx`, assigns
every row in one statement.

The first implementation did it the obvious way — read each row, hash it, update it, in resumable
2,000-row chunks — and took **168 s** on the deployed database against **19 s** for the form above:
118,718 single-row updates across 60 committing transactions, with a WAL checkpoint every few. That
does not fit the startup budget, so the whole fill is now **one transaction**. The failure mode
chunking protected against — a power cut mid-fill — now costs a clean rollback and a repeat on the next
start, which at ~20 s is a better trade than three minutes of startup every time.

Because the fill is one transaction, its bookkeeping is atomic with its assignment by construction: a
row is counted and leaves the queue in the same commit, or neither happens. No row can be filled twice,
and nothing sets `series_id` back to NULL.

**One case is refused rather than half-done.** SQL must group by the attribute *text*, since it cannot
compute the hash — so two spellings of the same object (differing key order) arrive as two groups,
share a series id, and the second finds no matching `series.attributes` and stays NULL. The fill
re-checks the queue inside the transaction and rolls back with an error naming the count. Nothing the
write path emits can produce this: it serialises from a sorted map. So it is a report that something
else wrote the column, and leaving those rows queued is the honest outcome.

The unit allows `TimeoutStartSec = maxPolls × pollIntervalSecs + 120` = 420 s, of which the clock gate
claims 300, so the fill has 120 s of slack. Measured at **41.7 s** on the deployed database, once; every
startup after is one index probe (`starting` → `ready` in 1.1 ms). It logs `filled` and `elapsed`, and if
that ever approaches the slack it moves behind `sd_notify(READY)`. It runs in `serve` rather than in
`migrate` or `open_write`, because `create-api-key` and `create-user` open the database the same way and
have no business running a backfill.

**A failed fill is fatal**, and the contrast with the api-key count two paragraphs up is deliberate. A
missing key degrades a *feature*: requests are refused, loudly, and nothing reported is wrong. An
unassigned measurement is different — since 3.3 the read path joins `series`, so such a row is invisible
to `/v1/measurements` and to every chart. Quietly under-reporting is the worst failure available to a
monitoring system: an empty chart reads as "nothing happened", which is the one answer it must never give
wrongly. Being down and saying so is strictly better.

The precondition is exact rather than approximate, because the fill is one transaction that re-checks the
queue before committing: **`backfill` returning `Ok` means the queue is empty.** Nothing can refill it
afterwards — only the writer stores measurements, it is spawned after, and it always sets `series_id`.
Reachable only from data this receiver did not write, or from I/O failure; both need a human, and
`Restart=on-failure` retries every 60 s meanwhile.

**Phase two needed no fill at all, because 3.3 reached the host through the pipeline first.** Once the
pipeline delivered 3.3, every binary that could run wrote a `series_id`: the nightly upgrade could only
revert to 3.3, and a locally-switched generation was 3.3 or newer. So the queue converged once and stayed
empty, and 4.0 arrived at a database where every row was already assigned. The sweep, `pending`, the
partial index and the UI note were **pure deletion**.

That ordering was a real precondition, not a hope, and `NOT NULL` is what enforces it: a database that
never passed through 3.3 has unassigned rows, so 4.0's `INSERT … SELECT` fails on them, the migration
rolls back whole, `user_version` stays at 3.3 and the previous generation still boots. **The constraint
being added and the precondition being checked are the same thing**, so it costs nothing extra. The
practical consequence is that restoring a pre-3.2 backup means running a 3.3 binary over it first; there
is no path where 4.0 repairs it, because minting a series row needs blake3 and SQL cannot hash.

Getting the fill *out* of 4.0 is what left it as SQL only. A 4.0 that had to fill would have needed a Rust
step ordered before its own DDL — in the one migration that cannot be rehearsed on the deployed host, and
that cannot be reverted once applied, since every 3.x binary then refuses the database as a newer major.
The only rollback 4.0 has is a database backup taken immediately before it.

4.0 is therefore a **table rebuild**, the way 2.0 was: `CREATE` the new shape, `INSERT … SELECT`, `DROP`,
`RENAME`. A rebuild rather than `DROP COLUMN` for three reasons — SQLite cannot `ALTER TABLE … ADD NOT
NULL`, it cannot add a foreign key to an existing table at all, and `DROP COLUMN` rewrites every row
without producing a compact table. The rebuild gets all three in the one pass the data has to make anyway.
`measurement_type_event_time_idx` and `measurement_backfill_idx` die with the old table;
`series_type_attributes_idx` is kept, because the read path's type filter uses it.

No `VACUUM`: it cannot run inside a transaction. So 4.0 frees the ~62 MB of duplicated text *within* the
file rather than returning it to the filesystem — later rows reuse it at ~150 bytes each instead of ~1 KB.
A one-off manual `VACUUM` with the service stopped reclaims it if the file size itself matters.

### 6.7.1 Foreign keys

Enabled from 4.0. They were not before, and the reason given was that no genuine referential relationship
existed — `api_key` does not own the measurements ingested with it, so declaring one would have implied a
constraint that was not real. That reasoning expired when `measurement.series_id` arrived.

**The key is what makes the read path's inner join total.** `NOT NULL` forbids an *absent* series;
only the key forbids a *dangling* one, which a write-path bug computing the wrong hash would produce and
which would make those measurements silently invisible to every read — the same under-reporting a NULL
would cause, from a different mistake. Both halves are needed and neither substitutes for the other.

`ON DELETE RESTRICT` by omission: a series still holding measurements cannot be deleted. That becomes
load-bearing when retention arrives.

**`DEFERRABLE INITIALLY DEFERRED`, and that is load-bearing.** `store::write::insert_batch` inserts each
measurement *before* upserting its series row, because `added_measurements` may only count rows the
`INSERT OR IGNORE` actually stored — folding first would let a retried batch inflate the count. An
immediate constraint would forbid that order, and reversing it reintroduces exactly that bug. Deferred
checks at `COMMIT`, so the write order stays free and the guarantee is identical. A violation therefore
fails the whole batch rather than one row, surfacing as a retryable 503 rather than a silent gap.

`web_session.username` references `web_user(username)` with `ON DELETE CASCADE`. `store::users::delete`
still performs the cascade by hand and keeps doing so: it works whether or not the connection enforced
the key, and deleting a user *must* invalidate their sessions. The migration filters orphan sessions
rather than failing on them — a session whose user no longer exists is a credential that should already
be invalid, so dropping it is the same repair.

**Enforcement is per-connection and not stored in the file**, which is the hazard that made the original
decision cautious, and it does not go away: a write path that forgets `PRAGMA foreign_keys = ON` is
silently unenforced. So it is set in `apply_pragmas`, in `open_write_existing`, and — the belt — in
`migrate` itself, since a connection that just built or upgraded the schema is precisely the one that must
have the constraints live. `apply_foreign_keys` then *reads the pragma back* and fails if it did not take,
because it is a silent no-op inside a transaction. `open_read` deliberately does not set it: a read-only
connection cannot violate a constraint.

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

Single binary. `serve` and `wait-for-clock` are the deployment surface and are specified below; the
credential commands belong to the sections that define what they manage — API keys in §13.3, web users
and sessions in §14.7.

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

```
monitoring-platform create-api-key --label <name>   # §13.3; prints the token to stdout once
monitoring-platform create-user --username <name>   # §14.7; password on stdin, never in argv
monitoring-platform list-users                      # §14
monitoring-platform list-sessions                   # §14
monitoring-platform delete-user --username <name>   # §14; removes their sessions too
```

`list-api-keys` was removed when §14.1 grew a page that lists and revokes them. `create-api-key` was
**kept**, and the reason is worth stating because it looks like an oversight: it is the only one of the
three that works with the service *down*. `nix/tests/lib.nix` provisions the collector's key before the
receiver has ever started — it has to, since the collector reads its key once at startup and is ordered
before nearly everything (§7 of the collector design) — and it is also the way back when there is no web
session to log in with. Issuing is the bootstrap; listing and revoking are not.

All five take `--db` and `--log-level` with the same defaults as `serve`, and all six log to **stderr**
rather than stdout: for `create-api-key` stdout *is* the token, so `TOKEN=$(… create-api-key …)` must not
capture migration lines, and the rest follow it so the set is consistent. The listings print to stdout,
since that is their output.

Sharing `--db`'s resolution with `serve` is what stops a key or a user being written to a different file
from the one the receiver reads — with `--db` unset and `STATE_DIRECTORY` exported for the service but
not for an operator's shell, that is exactly the mistake available to make, so both creation commands
warn when the database does not already exist.

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
- `Restart=on-failure` matters more than it looks: §6.2 makes a database whose *major* schema version
  exceeds the binary's a fatal startup error (a newer *minor* runs, which is what confines this to the
  changes that genuinely cannot be served), and §8.1 fails startup when the socket path is
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
  works under chrony, systemd-timesyncd, ntpd-rs or NTPsec and depends on none of them.
  Referencing `chrony.service` would tie the platform to one deployment's choice.

  Daemon-agnostic is not the same as *identical*, and the distinction matters for anyone reading
  the threshold as an accuracy claim. The three write three different quantities into the field:
  chrony the true root distance (`root_delay/2 + root_dispersion`), ntpd-rs `root_delay`, and
  systemd-timesyncd sets `ADJ_MAXERROR` in its modes but never assigns the field, so it writes
  **zero** — recency, not accuracy. The magnitudes are not comparable across daemons. What the
  test reliably distinguishes is *disciplined* from *never touched*, which is precisely the
  question this gate needs answered. `collector-clock-correction-design.md` §4.4 depends on the
  same field and documents the per-daemon behaviour in full.
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
limiter existed to turn a permanent startup failure — a schema *major* newer than the binary (§6.2),
an occupied socket (§8.1) — into a failed unit that reports the reason instead of an endless loop.
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
  lib.rs               AppState, random_bytes
  auth.rs              pure: API key, session token and password identity (§13, §14)
  bin/
    mp-make-sample.rs  writes a sample OTLP batch, posts one with --post, or stamps a
                       different --device-id; a shipped bin, not an example, so the VM
                       tests and the §11 manual check get it from the package
  config.rs            Config value + resolution
  clock.rs             §9.4 boot gate: pure poll/hysteresis rules over mp-host's read
  model.rs             Measurement, StoredMeasurement, Rejections
  otlp/
    convert.rs         pure: ExportLogsServiceRequest -> (Vec<Measurement>, Rejections)
    anyvalue.rs        pure: AnyValue -> serde_json::Value
    test_support.rs    OTLP payload builders, shared by unit and integration tests
  store/
    schema.rs          version encoding, migrations, pragmas
    write.rs           writer task, insert_batch
    read.rs            query building, JSON path builder, row mapping
    series.rs          the series table (§6.7): the fold, the upsert, the backfill sweep
    keys.rs            the api_key table (§13)
    users.rs           the web_user table (§14)
    sessions.rs        the web_session table (§14)
  api/
    mod.rs             Router construction, and which credential guards what
    auth.rs            API key middleware (§13)
    ingest.rs          POST /v1/logs: limits, decompression, conversion
    query.rs           GET /v1/measurements, /healthz
    status.rs          google.rpc.Status + the non-protobuf error rewrite layer
  web/                 the browser interface (§14)
    mod.rs             routers and handlers
    html.rs            pure: escaping and page rendering
    session.rs         pure cookie format + the session middleware
  transport/
    uds.rs             the receiver's name for mp-host::uds
tests/
  ingest.rs            router-level OTLP ingest
  read_api.rs          router-level read API
  auth.rs              router-level API key enforcement (§13)
  web.rs               router-level login, guard and credential separation (§14)
  end_to_end.rs        the compiled binary over a real socket, incl. SIGTERM
crates/                see collector-clock-correction-design.md for these two
  mp-host/             clock and socket primitives shared by both binaries
  mp-collector/        the on-host clock-correcting OTLP collector
nix/                   see §10.3 for this tree
```

**This is a workspace with the receiver at its root**, not moved under `crates/`. Every path above,
and every reference to one in this document, therefore stays valid; only the two new members are
new paths. `crates/mp-host` exists so the receiver and the collector cannot drift onto different
definitions of "what time is it" — one rewrites the timestamps the other stores, so they have to
agree on `adjtimex(2)`, on `CLOCK_BOOTTIME`, and on the socket lifecycle.

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
- Schema versions (§6.2). `encode`/`decode` round-trip; a bare integer decodes as that major at minor
  zero, which is what every deployed database holds; a zero minor encodes back to the bare major —
  asserted on the integer, because that integer is the compatibility promise; the packed form of a
  zero minor still decodes, since `user_version` can be hand-edited to anything; and ordering is
  numeric, so 3.9 < 3.10 rather than the reverse a lexical comparison would give. Plus a guard that
  `MIGRATIONS` ascends and its last entry is exactly `SCHEMA_VERSION`, which catches both adding a
  migration without bumping the constant and bumping it without adding one.
- Migrating (§6.2): forward from empty, from 1.0 and from 2.0, and idempotent. **A pre-3.2 database with
  rows refuses to reach 4.0** and rolls back whole, leaving the version and the rows untouched; the same
  database with no rows migrates all the way. A 3.0 database's other tables survive both of 4.0's
  rebuilds. A newer **major** is refused. A newer **minor** is *accepted* — it
  applies nothing, leaves the stored version alone rather than silently downgrading the file, and
  leaves the newer binary's extra table intact. A database already at the current version is not
  written to at all, which is what keeps a deployed 3.0 database readable by a binary from before
  major.minor existed.
- **An older binary's writes are refused by the 4.0 schema** (§6.2) — the inverse of the test it
  replaced, and the definition of a major. Through 3.3 the asserted property was that the verbatim
  pre-3.2 `INSERT` still succeeded, which is what made those bumps minors and kept the nightly revert
  survivable. 4.0 ends it deliberately, so the refusal is asserted rather than left implied by a deleted
  test. The tables 4.0 did not touch still take the same writes.
- STRICT survives the 4.0 rebuild — a rebuilt table that forgot it would silently start accepting
  anything.
- Series identity (§6.7): attribute order and nested-object order do not change a `series_id`; both
  halves of the key do; a series id is domain-separated from the measurement id of the same inputs;
  field boundaries are unambiguous, so `("ab", {"c":…})` and `("a", {"bc":…})` differ; and the encoding
  is pinned to a fixed hex value, because changing it invalidates every stored `series_id`.
- The series fold (§6.7): rows of one series collapse into one delta; the extents are `min`/`max`, so
  they do not depend on the order rows are folded — a batch is not time-ordered.
- Series bookkeeping through the write path (§6.7). **A re-uploaded batch does not inflate
  `added_measurements`** — the regression test for folding before the insert rather than after it,
  which is the specific untruth the `added_` naming promises against. A partly-overlapping batch
  counts only what it stored. Extents widen in both directions and are never narrowed, which is what a
  spool drained after a reboot requires. `added_processed_time_*` tracks `processed_time` and not
  `event_time`, catching a transposed parameter that is otherwise invisible. Timestamps are **not**
  part of the key, so two measurements differing only in time share a series. A 16-series batch
  attributes each row to its own series. And `series` stores the type and attributes verbatim, since it
  is now their only record.
- **The referential guarantee** (§6.7.1). A measurement cannot reference a series that does not exist,
  and cannot have none at all — the two halves of what makes the read path's inner join total, each
  asserted separately because neither constraint substitutes for the other. The write path satisfies the
  key *despite inserting the measurement before its series row*, which only the deferred mode permits and
  which the count's correctness depends on. A series still holding measurements cannot be deleted. A
  session cannot be created for a user who does not exist. These are worth pinning precisely because
  enforcement is per-connection and therefore forgettable.
- **`measurement` has no `type` or `attributes` of its own** (§6.7), asserted on `pragma_table_info`.
  Through 3.3 this was covered by de-synchronising the two copies and demanding the `series` answer — the
  only way to tell the sources apart while both existed. 4.0 deleted the columns, so the guard became
  structural, and asserting the structure is what stops a future migration quietly putting a second copy
  back. The seven read shapes are still swept as a group, since they are what would have to change if the
  source ever moved again.
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
- **Startup refuses to serve against a database that skipped the assigning release** (§6.7), asserting a
  non-zero exit, that the message names the constraint, and that `user_version` and the rows are untouched
  — a partial migration would be unrecoverable, since every 3.x binary refuses a 4.0 database.
- Schema compatibility, against the spawned binary rather than only `migrate` (§6.2): a database at a
  newer **major** exits non-zero with the reason on stderr; one at a newer **minor** starts, serves
  `/healthz` *and* `/v1/measurements`, and leaves `user_version` untouched. The end-to-end shape is
  the point on the second one — what has to hold is that the process comes up and serves, which is
  the case a reverted deployment lands in.

Web interface (§14), at the router level over a temp-file database:

- The login form and `/healthz` answer with no credential at all; every other page redirects to
  `/login` and its body does **not** contain what it would have shown.
- A correct password answers `303` with a cookie and a row; a wrong one answers `401` with neither.
  An unknown username and a wrong password produce byte-identical responses, so the form is not an
  oracle for which usernames exist.
- The cookie carries `HttpOnly`, `SameSite=Strict`, `Path=/` and a `Max-Age` matching the row — and
  **not** `Secure`, which is pinned in both the unit and the integration tests because adding it would
  silently make every request after login anonymous (§14.2).
- A cookie is refused when it names no session, when it names a real session with the wrong secret
  (so the public id on the sessions page is not itself a credential), when it is malformed, and when
  the session has expired. Logging in sweeps what expired; logging out deletes the row and the same
  cookie stops working. `GET /logout` is `405` and leaves the session intact.
- A password containing `&`, `+` and `%` survives form encoding, so a login that works from `curl`
  also works from a browser.
- **The credentials do not cross, in both directions** (§14.4): a session cookie gets `401` on
  `/v1/measurements` *and* on `/v1/logs` with nothing written, and a valid API key gets `303` on every
  page with no user data in the body. Plus the control — that the same key still works on `/v1` — so
  the previous assertion cannot pass merely because the key was invalid.
- A measurement whose `type`, body and attribute key are all `<script>alert('x')</script>` renders
  escaped, with no `<script>` anywhere in the page. Unit tests cover `escape` directly, including that
  it cannot be broken out of either quote form in an attribute and that it does not double-escape.
- The three credential domains are mutually distinct, and an API key and a session token from the same
  source bytes hash differently — the database-level half of the separation above.

The origin check (§14.3.1), as pure functions over the two header values plus router-level tests:

- A matching host:port passes; **a different port on the same host fails**, which is the loopback case the
  check exists for and the one `SameSite` cannot see. An absent or `null` `Origin` fails, an empty `Host`
  matches nothing, a default port is not normalised away, and the scheme is ignored.
- Router level: each mutation is refused with a bad or missing `Origin` **and the database is unchanged**;
  `/login` is refused as forged rather than as wrong credentials, so the check demonstrably runs first;
  `GET` is unaffected.

User and session management (§14.1):

- A created user can then **log in** — which is what proves the form stored a hash the login path accepts,
  since a create that wrote an unusable one looks identical up to that point. A duplicate username is a
  message, not a 500. A blank or whitespace-only username is refused.
- Deleting the last user is refused and it survives. Deleting your own user logs you out, and the cascade
  leaves no session behind. Ending another session invalidates that cookie and leaves yours working;
  ending your own logs you out.

The explorer (§14.9):

- An attribute filter narrows the table. A numeric field renders a line; an all-text type renders the
  timeline and offers no chart field at all. Sixteen groups render exactly eight series, use all eight
  slots and never a ninth, and the legend lists them in **numeric** order (1–8, not 1, 10, 11 …).
- Switching type drops the previous type's filters and the new type's rows appear.
- Partial coverage is reported whether or not markers were drawn, since markers are dropped on precisely
  the dense charts that have most buckets to be partially covered.
- An empty range says so rather than rendering an axis with nothing on it. Device-supplied group labels
  cannot break out of the SVG.
- Rendering is checked as well as asserted: the generated SVG is parsed as XML, and the plots are read
  against a copy of the deployed database rather than only against synthetic rows — the validator checks
  colour, not layout.
- **A filtered attribute still offers its other values.** The regression test for a one-way filter: a
  key's options are discovered with that key's own filter excluded, so choosing `cell=2` does not leave
  `2` as the only thing selectable. The other filters still apply, so an option can never match nothing.
- Two ticked fields render two plots with two headings and three SVGs in total; the control is checkboxes,
  not a multi-select. "One line per" appears only once something is being charted.
- `/chart` renders **both** geometries and exactly one pair; each mark is a link carrying its own bucket
  window, and following one lands on the table. Link parameters are percent-encoded, so an attribute key
  containing `&` cannot change what the link means. The page is behind the session guard like every other.
- Structured cells render as `key: value` lines, never as stringified JSON; object keys are sorted;
  nothing renders as `null` or `{}`.
- The geometry presets differ where it counts — asserted at **compile time**, since they are constants and
  the media-query swap is decoration if they ever converge.
- **A dense chart is still clickable although it has no markers** — the regression test for linking marks
  rather than a hit layer, which made the drill-down vanish on exactly the charts worth drilling into.
  Slivers are merged into targets that clear a minimum width, and the merged link still spans whole buckets.
- Every group is plotted: twelve groups render twelve lines, four of them dashed, with no "showing 8 of"
  note; no two slots inside the bound share both hue and pattern; past twenty-four the note appears.
- A legend entry toggles its series, a hidden one is still listed with a link that restores it, and
  **hiding one series does not recolour the others** — the appearance follows the full-list position.
- Fields in either half (§14.9): a body leaf can be the series dimension *and* a filter; the two halves AND
  together without crossing columns, and a value from the wrong half matches nothing; a filtered body leaf
  still offers its other values, like an attribute. `FieldRef` round-trips, and a bare reference means an
  attribute so older links keep working.
- **`range=all` includes the newest row.** The upper bound is exclusive, so a window taken straight from the
  data's extent dropped the last row every time — invisible at a thousand rows, which is why it is pinned.
- **The `all` window does not depend on the value filters**, so the axis does not rescale as filters change
  and widening a facet still has rows in range to offer.
- API keys (§13, §14.1): the page lists and issues; an issued token is rendered **once** and is absent from
  the next load; a key issued from the page authenticates on `/v1`; revoking one stops it working; a label
  is required; the pages are behind the session guard and the origin check.

Collector clock attributes (`collector-clock-correction-design.md` §9.1): an ordinary corrected record
carries **no** `mp.clock.*` attributes at all, asserted on the whole set rather than key by key; a record
that was not corrected keeps its `resolution`, so a silent degradation to `passthrough` is still visible
per row; an uncertain flush keeps `uncertain`. Asserted in the collector's unit tests, in its end-to-end
tests over a real socket, and in the `collector` VM case.

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
  the harness's readiness wait; both apply only to isolated cases. `ntpNodeModules` exists for
  `clock-gate`, `waitForService` for it and `clock-gate-minsources` (both below).

A target system tests the service against its **own** configuration by importing the harness directly:

```nix
import "${monitoring-platform}/nix/tests/lib.nix" {
  inherit pkgs;
  machineModules = [ self.nixosModules.common-desktop ];  # the real host config
}
# => { platform = <shared VM>; restart = <own VM>; ... }
```

**The clock-correcting collector is included by default and needs nothing from the caller**:
`lib.nix` imports `nix/collector-module.nix` into the machine itself, so a consumer picks up the
collector cases on its next update with no change on its side. `collector = false` leaves it out
entirely — the module is not imported, so its options do not exist either. A consumer that already
imports the module is unaffected: NixOS keys modules by path and deduplicates, which
`nix/tests/eval-checks.nix` covers with a `collector-preimported` shape.

This defaulted-on rather than opt-in for a reason worth stating, since the opposite was tried
first: an opt-in flag means a consumer that does not know about it gets less coverage than this
repo does, silently — and the consumer's run is the authoritative one.

**Every assertion is scoped to the harness's own rows.** The machine under test is a consumer's
real one, so it normally runs a producer of its own writing to the same receiver over the same
socket, at times the harness does not control. `mp-make-sample` stamps
`resource.attributes.device.id = dev-7`; `row_count` and `sample_rows` filter on it, and a case
must not reach past them to a bare `select count(*)`. The collector cases hold to the same rule —
the collector corrects a batch in place rather than rebuilding it, so `device.id` survives the
extra hop. The one exemption is `mp.collector.health`, which the collector synthesizes itself and
so carries no `device.id`; its type is already the narrower filter.
`nix/tests/cases/foreign-producer.nix` pins the property by posting a second batch as
`--device-id other-device` and asserting the scoped counts do not move.

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
- **chrony** — its configuration is left completely alone. Only two things are injected:
  `/etc/hosts` entries resolving `services.chrony.servers` to the helper — **one address per
  name**, with the helper carrying an alias per name on its vlan interface — and, for an NTS
  client, the helper's CA in `security.pki.certificateFiles`. The helper then serves **real NTS**
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

**One address per server name, not one address for all of them.** chrony allocates a source slot
per `server` line and resolves each slot's name separately; a slot whose name resolves to an
address another slot already holds is refused (`NSR_AlreadyInUse`) and left permanently
unresolved, which `chronyc activity` counts under "sources with unknown address". So N names on
one address yield exactly **one** usable source. That is invisible at chrony's default
`minsources 1` and fatal above it: the machine can never select a source, `maxerror` stays at the
16 s ceiling, and every case fails on a readiness timeout — which is what a fleet setting
`minsources 2` would hit. Distinct addresses on the *same* chronyd are sufficient (it binds all
of them and the helper sets `allow all`), so this costs no extra nodes; one helper VM per name
would be unaffordable under aarch64 TCG.

Three isolated cases cover the gate itself:

- **`clock-gate`** layers `chronyd.wantedBy = mkForce []` onto the time-source node, so "no
  working NTP" is the machine's genuine state — nothing simulates a bad clock — and starting
  chronyd is what flips it. Asserts both directions at the production threshold. Observed values
  confirm the mechanism: `clock_error_us=16000000` before, `2000` after. It drives the transition
  through whichever client the machine actually runs, resolved at runtime from systemd, and
  observes it with `wait-for-clock` itself rather than timesyncd's marker file — otherwise the
  case would silently only work on a machine that brings no NTP daemon of its own.
- **`clock-gate-nts`** runs the fleet's shape, chrony with `enableNTS`. Beyond the gate opening,
  it asserts `chronyc -N authdata` reports the source as `NTS` with a non-zero cookie count —
  without that, a silent fallback to plain NTP would synchronise the clock, open the gate and
  look identical. It also asserts each server name resolved to its *own* helper address.
- **`clock-gate-minsources`** adds `minsources 2`, the one chrony setting the harness's own
  impersonation can break. It asserts on the source table — `0 sources with unknown address` and
  at least `minsources` online — so a regression to one-address-for-all names fails there,
  naming the unresolved sources, instead of as an unexplained readiness timeout. Neither
  `clock-gate-nts` (default `minsources 1`, where one usable source suffices) nor
  `eval-checks.nix` (evaluation only; this failure is purely at runtime) can catch it.

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
| `collector` | the collector's units, its sandbox (the three settings that differ from the receiver's and fail *silently* if regressed), a record from the sending process arriving corrected, and a relayed one passing through |
| `collector-clock` (isolated) | with no NTP: the collector starts where the receiver refuses to, journald's backfill supplies the history, records are held, and the timeout ships them marked `mp.clock.uncertain` rather than dropping them. Then NTP arrives, a real `date -s` step is observed, and the §9 health event lands as a measurement |
| `collector-step` (isolated) | the design's central case: a record held while the clock is untrusted is **released and corrected by a real step**, marked corrected and *not* uncertain. Also that the socket survives a service restart, which is what `RuntimeDirectoryPreserve=` exists for |

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

  **This is now addressed device-side rather than here.** `collector-clock-correction-design.md`
  and `crates/mp-collector` implement an on-host collector that keeps a history of
  `realtime − boottime`, maps each arriving timestamp back into that frame at receipt, and
  rewrites it once the clock is trustworthy. It needs no protocol support and no application
  change, and it satisfies both constraints below: corrections are marked with
  `record.attributes.mp.clock.*` rather than applied silently, and the device still sends its
  best-effort wall clock so §5.3 is satisfied by construction. The scheme sketched below remains
  the description of what it does; the collector is where it happens.

  The workable scheme needs no protocol support, because the anchor is
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

## 13. API keys

Every HTTP endpoint except `/healthz` is authenticated with an API key. `/healthz` is not, and must
not be: it has to answer during a deploy, from an `ExecStartPre`, and from a probe that holds no
credential, and it discloses nothing but liveness.

**This was introduced in two steps, and both have now shipped.** The first release verified the key
and recorded what it concluded while still serving every request; this one refuses. Doing it in that
order is what made it safe: shipping verification and enforcement together would have meant
discovering a misconfigured device by losing its telemetry, which for a device holding the only copy
of a measurement is not a recoverable mistake. A journal free of the first release's `warn` lines was
the precondition for this one.

There is no switch to turn enforcement off. A flag for that would be one more thing that has to be
right, and the rollout it would have served is over.

### 13.0 What a refusal looks like

| Outcome | Status | Level |
|---|---|---|
| valid key | — | `debug`, so one line per request does not drown the handler's own |
| no key, malformed key, unknown id, wrong secret | `401` + `WWW-Authenticate: Bearer` | `warn`, naming which way it failed |
| key could not be checked | `503` | `error` |

Three properties of that table are deliberate:

- **An unverifiable key is not a wrong key.** A database that cannot be read answers `503`, which is
  retryable. `401` is not, and answering it would tell a device to discard the only copy of a
  measurement because *our* storage was broken.
- **Every wrong key gets the same body.** The log distinguishes an unissued id from a bad secret; the
  response does not, so it cannot be used to discover which ids exist.
- **A refusal is shaped like its route.** Protobuf `google.rpc.Status` on the OTLP side (§4.1.1
  requires it of every 4xx), JSON on the read side. A client that cannot decode the refusal cannot
  report it.

The layer sits *outside* method routing, so an unauthenticated `GET /v1/logs` is `401` rather than
`405`: a caller with no credential learns nothing about which methods a route accepts.

Nothing reaches a handler without a key, so a refused batch is never decompressed, never parsed and
never stored.

Two operational consequences worth knowing. A receiver holding **no keys at all** can serve nothing
but `/healthz`; it says so with an `error` at startup naming the `create-api-key` command, but it does
start, because refusing to would take `/healthz` down with it and turn a recoverable state into a
restart loop. And a collector with a **wrong** key retries indefinitely rather than discarding, so its
outbox grows for as long as the misconfiguration lasts — see §13.4.

### 13.1 The token

A token has two halves, `mpk_<id>.<secret>`:

- **id** — 8 bytes, 16 lowercase hex digits. Public. It is what a request is looked up by, so a token
  bearing an id nobody issued is refused after one index probe, with no hashing at all.
- **secret** — 32 bytes, 64 lowercase hex digits, from `/dev/urandom`. Never stored.

The `mpk_` prefix exists so a leaked key is greppable and recognisable on sight. Hex is lowercase and
parsed strictly: uppercase is refused rather than normalised, because one secret with two spellings
would be one secret with two hashes, only one of which is in the database.

The two halves come from disjoint randomness. The public id therefore says nothing about the secret.

### 13.2 What is stored, and why the hash is a fast one

`api_key` holds the id, a label, a creation time, and `blake3(domain || secret)` — never the secret.
A stolen database yields no credential.

**The hash is deliberately not argon2, scrypt or bcrypt.** Those exist to make guessing *low-entropy
human* passwords expensive. A secret here is 32 bytes of CSPRNG output: an attacker holding the hash
faces 2^256 candidates, which no hash speed makes searchable. A slow KDF would buy nothing and would
tax the receiver, which runs on the same class of hardware as the devices. What a fast hash still
needs is domain separation, and it has it — the same `blake3` also produces measurement content ids
(§6.6), and the two must never be confusable.

Verification compares `blake3::Hash` values, whose `PartialEq` is constant-time. That is cheap
insurance rather than the thing holding the scheme up: leaking hash bytes by timing would still leave
an attacker needing a preimage.

Revocation is deleting the row.

### 13.3 Issuing a key

    monitoring-platform create-api-key --label pi-7

Prints the token to stdout, once, and nothing else on stdout — so `TOKEN=$(… create-api-key …)`
captures the token alone. It cannot be recovered afterwards; losing it means issuing another and
deleting the old row. `monitoring-platform list-api-keys` shows ids and labels, never secrets, because
none are stored.

The command opens the database for writing, which also migrates it — so it works on a receiver that
has been upgraded but not yet restarted. It warns when the database file did not already exist: a
mistyped `--db` would otherwise cheerfully store a key in a second database that the receiver never
reads.

### 13.4 How a collector presents one

`Authorization: Bearer mpk_<id>.<secret>`, on every batch.

The collector reads the key from a **file**, not an environment variable, because that is the shape
systemd credentials come in. The source path is read by PID 1 as root before the service's sandbox
exists, then re-exposed to the service alone at mode 0400 on a private tmpfs. The same value in the
environment would be readable through `/proc/<pid>/environ` and echoed by `systemctl show`. The
collector looks for `mp-api-key` under `$CREDENTIALS_DIRECTORY` without being told where that is, so
`services.mp-collector.apiKeyFile` is the whole configuration.

By default the file is expected to be an **encrypted** credential, as produced by `systemd-creds
encrypt`, and is loaded with `LoadCredentialEncrypted=`; `apiKeyEncrypted = false` selects plaintext
and plain `LoadCredential=`. The two must not be confused, which is why it is an explicit option rather
than a guess: pointing `LoadCredential=` at an encrypted file would hand the collector the *ciphertext*
to present as its key. Getting it wrong is loud in either direction — the unit fails to decrypt, or the
collector's own startup check refuses a key that is not printable ASCII.

One interaction to keep in mind: this unit starts very early (see `orderBeforeTimeDaemons`), so a
credential encrypted against the TPM may be loaded before the TPM is ready, leaving `Restart=on-failure`
to retry. Encrypting with the host key in `/var/lib/systemd/credential.secret` has no such race, since
the unit already orders itself after `/var/lib` is mounted.

A collector with no key configured sends no `Authorization` header at all — not an empty one, which the
receiver would have to tell apart from a real attempt. Since the receiver now enforces, that also means
it delivers nothing.

The collector validates only that the key *can be sent*: non-empty, and legal in an HTTP header value.
Whether the receiver recognises it is the receiver's business, and it says so in its log for every
batch — a better place to learn it than a startup check that would duplicate the token format across
two crates.

**A wrong key is retried, not discarded.** `Forwarder::send` treats a `401` like any other failure, so
the batch stays at the front of the outbox and is retried on the backoff. That is the right choice for
a fixable misconfiguration — the telemetry survives being wrong about a key — but it means the outbox
grows for the duration, bounded only by `buffer_max_records` counted in *batches* and by memory. A
device left misconfigured long enough will be OOM-killed rather than shed.

## 14. Web interface

A browser-facing view of the data, and the login that guards it. Server-rendered HTML on the same
router and the same socket as everything else, sharing the database and **nothing else — in particular
not the credential**.

This exists because there was no way to look at the measurements without a shell and `curl`. It is one
operator's own view, not a product surface: no dashboards, no charts, no JavaScript, no build step.

### 14.1 Pages

| Route | Method | Auth | |
|---|---|---|---|
| `/login` | `GET` | none | the form |
| `/login` | `POST` | none | success → `303` to `/` with a session cookie; failure → the form again, `401` |
| `/logout` | `POST` | session | delete the row, clear the cookie, `303` to `/login` |
| `/` | `GET` | session | the measurement explorer (§14.9) |
| `/chart` | `GET` | session | one chart, full page, with clickable points (§14.9) |
| `/users` | `GET` | session | the `web_user` table, with a create form |
| `/users/create` | `POST` | session | `username` + `password` → a new user |
| `/users/delete` | `POST` | session | `username` → that user and their sessions |
| `/keys` | `GET` | session | the `api_key` table, with an issue form (§13) |
| `/keys/create` | `POST` | session | `label` → a new key, **shown once** |
| `/keys/delete` | `POST` | session | `id` → revoke, i.e. delete the row |
| `/sessions` | `GET` | session | the `web_session` table |
| `/sessions/end` | `POST` | session | `id` → delete that session |

Every mutation is a `POST` and answers `303` back to the page it came from, so a reload does not
resubmit. None is a link: a `GET` that changes something is a URL a prefetcher or an `<img src>` can
fire. All of them additionally require a matching `Origin` (§14.3.1).

Three guard rails, none of them about privilege — a session is full authority (§14.3) — and all about
not locking yourself out:

- **The last remaining user cannot be deleted.** Checked in the handler on the same connection as the
  delete, not merely hidden in the rendering: the page whose button was pressed may be minutes old.
  Recovery would otherwise mean ssh.
- **Deleting your own user ends your own session**, since `web_user` deletion cascades to `web_session`
  in code (§14.8). The response is the login form, because a redirect to a page the browser can no
  longer load would read as a loop.
- **Ending your own session is allowed** and is simply logout by another route. It is on the list like
  any other, and it is the one a reader is most likely to want gone; refusing it would be surprising.

**An issued API key is rendered on the response to the `POST`, not after a redirect.** Only its hash is
stored, so the token exists exactly once and a redirect would lose it — and a token carried in a URL would
land in browser history and in any log that records paths. That is the same one-shot contract
`create-api-key` has on the command line (§13.3), and this is the only place in §14 where a secret is ever
rendered.

**There is no last-key guard**, unlike the last-user one. Revoking every key stops devices delivering and
is recoverable from this very page; deleting the last *user* locks the operator out of the page itself.
Different failure, different answer.

A failed mutation renders its page with the message rather than redirecting — a `303` cannot carry one
without a query parameter or server-side flash state, and `?error=…` is a reflected string in a URL that
gets pasted around.

**Every URL the server emits is root-relative.** The receiver listens on a unix socket and the browser
reaches it through a tunnel and a local TCP shim (§14.5), so the `Host` it sees is whatever that shim is
bound to. An absolute URL would work from exactly one vantage point.

### 14.2 Sessions and the cookie

A session token has the same two-half shape as an API key (§13.1) and for the same reasons — public id
looked up first, only `blake3(domain ‖ secret)` stored — with a distinct `mps_` prefix and a distinct
domain. Both distinctions are load-bearing. The prefix means a secret scanner can tell which credential
leaked and that a cookie can never be mistaken for a key; the separate domain means the same 32 bytes
presented as a cookie and as a bearer token hash *differently*, so one stored hash cannot authenticate on
both surfaces. Without that, §14.4's separation would hold in the router and leak through the database.

```
Set-Cookie: mp_session=mps_<id>.<secret>; HttpOnly; SameSite=Strict; Path=/; Max-Age=2592000
```

- `HttpOnly` — script cannot read it, so an injection anywhere in these pages cannot exfiltrate the
  session. Escaping (§14.6) is the first line of that; this is the second.
- `SameSite=Strict` — not sent on any cross-site request, which is what makes a forged submission from
  another origin arrive with no session at all. This is also the entire CSRF story; see §14.3.
- `Max-Age` — matched to the row's `expires_at`, so the browser stops presenting a cookie at the same
  moment the server stops accepting it. Without it the cookie dies with the window, which is a
  different lifetime.
- **No `Secure`, and that is deliberate.** The browser reaches this over plain HTTP on loopback
  (§14.5). `Secure` would tell it to withhold the cookie from an `http://` origin, so login would
  appear to succeed and every subsequent request would be anonymous — a failure that looks like a bug
  in the session layer. What stands in for it is the shape of the path: the only network hop is iroh's
  QUIC, encrypted and authenticating the far endpoint by its id, and either end of it is loopback or a
  unix socket inside a 0750 group-owned directory. **Adding `Secure` is what to do the day this is
  served over TLS, and not before.**

**Expiry is absolute**, thirty days from creation, and never moves. A sliding window would mean writing
to the database on every page load to record activity nothing reads — turning the read path into a
writer, which for a receiver whose single storage writer carries measurement throughput is a poor trade
for a one-operator UI. There is no `last_seen_at` column for the same reason.

Expired rows are swept opportunistically at the next login, not by a timer: a login is the only moment
the table can grow. An expired row left lying around is inert regardless — the expiry check is what
decides, not the row's presence.

The TTL is a constant in code, not a module option. Nothing depends on the value, and `nix/module.nix`
gaining a knob nobody turns is a thing to explain later; `sessionTtlDays` beside `logLevel` is where it
goes if a host ever needs to differ.

### 14.3 What is *not* defended, and why

Stated rather than left implicit, because each of these is a deliberate stop and would otherwise read as
an oversight:

- **No login rate limiting, and no lockout.** The password is 2^n of the operator's own choosing, not a
  human-memorable string, so online guessing is not the threat model (§14.7). A lockout would also be a
  denial-of-service on the only account.
- **Username existence is observable by timing.** An unknown username returns before any hashing
  happens, so it is measurably faster than a wrong password. The *response* is identical either way —
  one message for every failure, so the form is not an oracle — but the timing is not equalised. With
  one operator whose username is not secret, closing that would be machinery guarding nothing.
- **No password change page.** `create-user` and `delete-user` are the interface; a form would need the
  old password, a confirmation field and a re-login path, for something done about once.
- **A session is full authority.** Creating and deleting users needs nothing beyond being logged in — no
  re-entered password. So a stolen cookie can mint a second login and make its access outlive the
  session. Accepted deliberately for a single operator: that cookie already reads every measurement and
  every credential id, and the realistic ways it leaks (a shared laptop, a local process) are ones a
  re-auth prompt on one form does not close. Re-authentication is the thing to add first if this ever
  serves more than one person.

### 14.3.1 CSRF: an origin check, because `SameSite` is not enough here

The previous revision of §14.3 rested the whole CSRF story on `SameSite=Strict`, on the grounds that a
forged cross-site request then carries no cookie, and noted that a token would be needed *"the moment a
page grows a form that changes something worth forging"*. §14.1's user and session mutations are that
moment — and re-examining it turned up a reason that is specific to how this service is reached, not
merely a matter of diligence:

**`SameSite` does not consider the port.** The browser reaches these pages at `http://127.0.0.1:8080`
through the tunnel shim (§14.5), so *anything else* served from `127.0.0.1` — any port, any other
development server on the same laptop — is **same-site**. A page on `127.0.0.1:3000` can therefore
`POST /users/delete` and the browser will attach the session cookie. On a real domain this attack needs
control of a subdomain; on loopback it needs any local process that can serve a page.

**Every state-changing request must prove its origin.** `Origin` must be present, and its host:port must
equal the `Host` header. Enforced by one middleware over all `POST` routes, `/login` and `/logout`
included — login CSRF is a real if minor attack, and *"every state-changing request proves its origin"*
stays true as routes are added, where *"the mutating ones do"* is a rule someone has to remember to
extend. `GET` is not checked: it changes nothing, and a browser following a bookmark sends no `Origin`.

**Why this rather than a synchronised token**, which is the conventional answer:

- **There is no canonical origin to compare against.** The receiver listens on a unix socket and is
  reached through whatever port the shim happens to bind, so any expected origin baked into the
  configuration would be wrong for some legitimate way of reaching it. `Origin` against `Host` needs no
  such constant — both headers describe the same hop, so the check is self-consistent however the
  request arrived, and it is sufficient because an attacker's page carries *its own* origin.
- **It is stateless.** Nothing to mint, store, expire, or thread through every form.

The scheme is deliberately not compared: `Host` carries none, requiring `https` would break the
plain-HTTP loopback path this is reached over today, and requiring `http` would break TLS tomorrow. What
matters for CSRF is the authority.

The cost is that a command-line client must now send the header:

```sh
curl -H 'Origin: http://localhost' --unix-socket … -X POST …
```

A token becomes worth adding only if a client that cannot send `Origin` ever needs to `POST`.

### 14.4 The two credentials do not cross

There are now two credentials, and each works only on the surface it belongs to:

| routes | credential | a refusal looks like |
|---|---|---|
| `/v1/logs` | API key | protobuf `google.rpc.Status`, as §4.1.1 requires |
| `/v1/measurements` | API key | JSON, matching the read API's own errors |
| `/`, `/users`, `/sessions`, `/logout` | session cookie | `303` to `/login` |
| `/login`, `/healthz` | none | — |

Enforced structurally rather than by a check: each group carries its own middleware, applied to that
router and not around the merge. The session layer never reads `Authorization`; the API-key layer never
reads `Cookie`. So a session cannot reach an OTLP endpoint and a device's key cannot open the
operator's pages. **Hoisting either layer out to wrap the merge would quietly end that**, which is why
`tests/web.rs` and `nix/tests/cases/web-ui.nix` both assert it in both directions.

The web layer answers `303` where the API layer answers `401`, and the divergence is deliberate: a
`401` with a `WWW-Authenticate` challenge makes a browser show its native basic-auth dialog, which for
a form-based login is a dead end. §13's clients are not browsers, so they keep the challenge RFC 7235
requires.

A database that cannot be *read* answers `503`, not a redirect — the same distinction §13.0 draws.
Bouncing to a login form that would fail the same way is a redirect loop.

### 14.5 How a browser reaches it

The receiver does not listen on TCP. `RestrictAddressFamilies=AF_UNIX` (§9.2) is unchanged by this
section, and no new listener appears on the host. The browser reaches the socket through machinery that
already exists on the deployment side:

```
browser → http://127.0.0.1:PORT
socat TCP-LISTEN:PORT → UNIX-CONNECT:<tunnel socket>
  iroh-uds-connect ══ iroh QUIC ══> iroh-uds-listen (on the host)
    → /run/monitoring-platform/monitoring-platform.sock
```

That the origin is plain `http://` on loopback is what §14.2 turns on. Serving this over TLS instead
would mean a reverse proxy or a TCP listener, and either is a change to §9.2's sandbox — a reviewed
edit, not a consequence of this section.

### 14.6 Rendering

Hand-written HTML in `format!`, with inline CSS and no static-file route. A templating crate would be a
dependency, a build-time asset path and a second language to debug, for string interpolation `format!`
already does — the same trade §4.1.1 makes in declaring one protobuf message by hand rather than
pulling in `tonic-types`. A `/static/` route would be a path-handling surface (traversal, content
types, caching) for a page whose entire styling is a monospace font and some borders.

The cost is that escaping is the application's job, so `web::html::escape` is the load-bearing function
and is unit-tested as such — the same reasoning as §7.1's JSON path builder. It escapes all five of
`& < > " '`, so one function is correct in element content *and* in an attribute value; a function safe
in only one position is an invitation to use it in the other.

This is not hypothetical. A device is free to send `<script>` as an `event_name` or an attribute key,
and §5.2 stores both verbatim by design — nothing upstream of the rendering rejects it.

### 14.7 Passwords

Stored as `blake3(password domain ‖ password)`. §13.2's argument for a fast hash carries over, **but
only because of how the password is chosen**: it is one operator's own high-entropy secret, not a
human-memorable string, so there is no small space to search and nothing a slow KDF would buy. The
moment a second user picks a password they can remember that stops being true, and `auth::hash_password`
is where argon2 belongs. Written down rather than left as an inherited assumption.

Hashed as exactly the bytes supplied — no trimming, no Unicode normalization. A trailing space is part
of the secret. A hash that silently disagreed with what was typed would be unrecoverable, since only
the hash is kept.

`create-user` reads the password from **stdin, never from a flag or an environment variable**:
`/proc/<pid>/cmdline` and `/proc/<pid>/environ` are world-readable, so either would publish it to every
process on the host for as long as the command runs, and land it in shell history besides. The same
reasoning as the collector's `apiKeyFile` (§13.4).

```sh
printf %s "$PASSWORD" | monitoring-platform create-user --db <path> --username sashee
```

There is no terminal echo suppression: that needs `termios` raw-mode handling with a restore-on-signal
path, or a Ctrl-C leaves the operator's shell echo-less, and piping is the documented usage precisely so
the password need not be typed where it can be seen.

### 14.8 Schema

Version **3.1** — the first minor bump under §6.2, and the reason that scheme was introduced before this
section was written. **Everything in §14.1's mutations and §14.9's explorer is queries and rendering over
these same two tables**, so the version has not moved since: nothing after 3.1 has needed a schema change,
and a deploy of that work is a plain binary swap. Two new tables and one index; nothing that a 3.0 binary reads or writes is touched,
so a receiver reverted to 3.0 by the nightly upgrade starts against this database, ignores both tables,
and serves measurements exactly as before.

```sql
CREATE TABLE web_user (
  username      TEXT    PRIMARY KEY,
  password_hash BLOB    NOT NULL,
  created_at    INTEGER NOT NULL
) STRICT;

CREATE TABLE web_session (
  id          TEXT    PRIMARY KEY,
  secret_hash BLOB    NOT NULL,
  username    TEXT    NOT NULL,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL
) STRICT;

CREATE INDEX web_session_expires_at_idx ON web_session (expires_at);
```

`web_`-prefixed rather than `user`/`session` because §6.5 keeps a Postgres migration open and `user` is
reserved there. No `revoked_at` on `web_session`: logging out deletes the row, exactly as revoking a key
does (§13). No foreign key from `web_session.username`, because §6.1 sets no `foreign_keys` pragma — the
constraint would be parsed and never enforced, which is worse than not declaring it, so `delete-user`
does the cascade by hand and says so.

Sessions are created and deleted on the request path, not through the storage writer: they are single
statements on their own tables rather than measurement batches, so teaching the writer a second kind of
work would buy nothing. A second writer against a live receiver is already established as safe — §13.3's
`create-api-key` does exactly this — because WAL admits one and `busy_timeout` covers the overlap. Those
writes use a connection that **does not migrate**, so a login can never be the thing that discovers the
schema needs upgrading.

### 14.9 The measurement explorer

`GET /` with everything driven by the query string. With no parameters it shows the newest measurements
across all types; with a type chosen it offers that type's attributes as filters and its numeric body
leaves as chartable fields.

```
/?type=bms.status.cell&range=24h&attr.record.attributes.cell=3&field=voltage_volts&group=record.attributes.cell
```

**State is in the URL, not the browser.** With no scripting, "which type is selected" is a fact about
the query string, re-read and re-rendered into the controls on every request. Every view is therefore a
link that can be bookmarked or pasted, which is worth more here than it costs.

**One filter row, above everything it scopes.** Range first (presets `15m … 30d`, `all`, or explicit
`from`/`to`), then type, then that type's attributes, then the chart field and the split-by key. Both
plots and the table re-render against the same slice, so the numbers below always agree with the picture
above; per-chart filters would let them disagree.

Two details that only exist because there is no JavaScript:

- **An empty value is not a filter.** A `GET` form submits every control it holds, so an unset `<select>`
  arrives as `field=`. Treating that as "filter where the field is empty" would make clearing a filter
  impossible.
- **A hidden `t0` field carries the type the form was rendered for.** The filter row is one form, so
  changing the type resubmits the *previous* type's attribute selects — keys the new type does not have,
  which would return an empty page with no hint why. A `t0` mismatch means the reader just changed the
  type, and the attribute filters, field and grouping are dropped with it.

Unknown parameters are **ignored** here, unlike §7.1's read API which rejects them. A device with a typo
in a filter name deserves an error; a person following a stale bookmark deserves a page.

#### Facets: what there is to filter on

Discovery reads the newest `FACET_SCAN_LIMIT` (2000) rows **matching the current type, window and
already-applied filters** — not the whole table, and not globally.

Scoping to the current slice is more useful *and* cheaper than a global list: a dropdown can never offer
an option that matches nothing in view, and the cost is bounded by the window already being queried.
Sampling rather than scanning is about growth, not about today — a full scan of the largest type measures
145 ms now, but this host projects millions of rows a year, and the same page would take seconds within a
year of running. What makes it sound is that **attribute keys are uniform per type**: all 32,112
`bms.status.cell` rows carry the same twelve keys, so a few hundred rows reveal every one.

**Only discovery is sampled. Filtering is always exact** over the whole window — facets populate the
controls, they never restrict what a query returns. When the cap is reached the page says so, because
distinct *values* can be missed where keys cannot: a device that stopped reporting early in a long
window.

A key with more distinct values than a dropdown can carry (`MAX_FACET_VALUES`, 40 — a boot id, a clock
correction in nanoseconds) is offered as a text box instead. Nested attributes are not offered at all,
since §7.1 makes them unfilterable and an option that cannot work is worse than none.

#### Both halves of a measurement are fields

Filtering and grouping work on **attributes and body leaves alike**. The distinction between them is an
OTLP artifact, not something a reader should have to hold: `detected-devices.wifi_bss` keeps `bssid` in its
attributes and `ssid` in its body, and the second is the more interesting identity of a wifi network. Before
this, `ssid` was visible only in the table — chartable by nothing.

They stay separate in the URL, because the two namespaces can legitimately collide and they are different
columns: `attr.<key>=v` and `body.<leaf>=v` for filters, and `group=<key>` or `group=b:<leaf>` for the series
dimension. A bare `group` value means an attribute, so links made before body fields existed keep working.
In the controls they are presented as one list of fields, with a `(body)` suffix added only where a name
appears in both.

Admission is by cardinality rather than by type: a field is offered when it has more than one distinct value
in the sample and few enough to be a dropdown. One value narrows nothing and would draw a single line
identical to the ungrouped chart; hundreds cannot be a dropdown at all and become a text box. That rule also
keeps a *value* field like `signal_dbm` out of the grouping list on its own merits, without special-casing
numbers.

**Filtering by a body field is what makes grouping by one usable.** Past the series cap the chart says
"narrow the filter to see the rest", and that instruction has to be followable for the field being grouped
by — otherwise grouping by `ssid` with twelve networks would have no way to reach the last four.

#### The plots

Two, stacked, sharing an x axis and **never a y axis**. Two measures on one plot means two arbitrary
scales and an invented correlation; two measures means two plots.

- **Timeline — always.** A column chart of matching measurements per bucket. It works for every type
  including the all-text ones (`system.unit` state changes, BLE scans), and answers "when did these
  arrive", which is the only question such a type can be asked.
- **Value chart — when a numeric field is chosen.** A 2 px line of the **average per bucket**, with a
  translucent **min/max band** behind it in the same hue. The band is not decoration: every point is an
  average, and a bare line would imply a smoothness the samples never had.

**Bucketing is what makes this bounded.** 24 h of `bms.status.cell` is ~23,000 rows, far past `MAX_LIMIT`
and far past useful pixel density. Instead `SERIES_BUCKETS` (240) buckets span the window and SQLite
aggregates to `count(*)`, `count(<field>)`, `avg`, `min`, `max` — output bounded by buckets × series
regardless of window, measured at 131 ms for 16 series over 24 h.

Two guards in that query carry most of the correctness:

- **The field is aggregated only where it is numeric.** `json_extract` on a text leaf returns text and
  SQLite's `avg()` coerces text to 0, so without a `json_type` guard a chart of a text field would render
  a confident flat line at zero rather than nothing at all.
- **`count(*)` and `count(<field>)` are both returned**, and where they differ the page says so.
  `system.unit.active_enter_seconds_ago` is null on more than half its rows; an average over 5,652 of
  12,166 rows is a different claim from an average over all of them. This is stated as a note under the
  chart rather than only in a mark's tooltip, because marks are dropped on a dense chart — exactly when
  there are most buckets to be partially covered.

#### Series, colour and the cap

| Series | Treatment |
|---|---|
| 1 | one hue, **no legend** — the heading names it |
| 2–8 | the palette's slots in fixed order, legend always present, ≤4 also direct-labelled at the line end |
| 9–24 | the same eight hues, **paired with a line pattern** — dashed for 9–16, dotted for 17–24 |
| >24 | the first 24 by sorted group value, and a visible "showing 24 of N" note |

**Never a ninth generated hue.** Past eight, adjacent colours are indistinguishable under colour-vision
deficiency and the palette's separation guarantees stop holding. What carries identity past eight is
therefore *composite encoding* — hue × pattern — which is the sanctioned third option alongside folding
into "Other" and small multiples. Within each pattern the eight hues clear their gates unchanged, and two
series sharing a hue never share a pattern, so no two of the twenty-four look alike.

A bound is still needed: a scan finding four hundred networks is not a chart. Past twenty-four the page says
how many it left out rather than truncating silently.

#### Hiding a series

Every legend entry is a **link** that hides its series, or restores it if already hidden; the hidden set
rides in the URL as repeated `hide=` parameters, so a decluttered view is still something to bookmark or
paste. This is the no-JavaScript form of clicking a legend, and it is what makes a twelve-line plot
workable: hide what is not being compared.

Two properties hold it together:

- **A hidden series is still listed**, struck through, with a link that brings it back. A legend that
  dropped what it had hidden would give no way to undo, which is the same trap as a filter with no "any".
- **Hiding does not repaint anything.** A series' hue and pattern come from its position in the *full*
  sorted group list, not from its position among the ones currently drawn — so a reader who learned that
  `NemSnet` is the dashed aqua line still finds it dashed and aqua after hiding something else. Assigning
  appearance by visible rank would be the recolour-on-filter mistake with extra steps.

Hidden series are not queried at all, so hiding is also cheaper than showing.

**Colour follows the group, not its rank.** Slots are assigned by position in the *sorted* list of group
values, so filtering one group out cannot repaint the others — a reader who learned that cell 3 is aqua
must not find it orange after narrowing. Sorting is **numeric when every value is a number**, which is
not cosmetic: lexicographically the sixteen BMS cells order 1, 10, 11 … 16, 2, 3, so "the first eight"
would be cells 1 and 10–16 rather than 1–8.

The palette is a documented instance used unchanged and in its published order — the order *is* the
CVD-safety mechanism — and it was validated with a checker rather than by eye: all gates pass for eight
slots in both modes (worst adjacent CVD ΔE 9.1 light / 8.4 dark against a ≥8 target; worst normal-vision
19.6 / 19.3 against a ≥15 floor). Three light-mode slots sit below 3:1 on the light surface, which
obliges *relief* — the values must be legible without the colour. **The measurements table under the
plots is that relief**, which is why it is not collapsible.

Colours are emitted as `var(--series-N)`, never as hex, so the light and dark values live in the
stylesheet and a plot cannot be rendered in the wrong mode's palette. Dark is a selected set of steps for
the dark surface, not an inversion of the light values.

#### The table under the plots

With a type selected every row has the same body shape, so **each body leaf gets its own column**, and so
does each attribute whose value *differs* across the rows on screen. The attributes that are identical on
every row move to one line underneath. That last part is what made the old table unreadable: every
`bms.status.cell` row carries the same twelve attributes and eleven of them — host name, boot id, scope,
service — are the same on every row in view, so rendering all twelve per row spent the whole width
restating constants. Without a type selected the rows are unrelated shapes, so body and attributes stay in
single columns; a column per key across twenty-nine types would be mostly empty cells.

Whatever lands in one cell as a structure renders as indented `key: value` lines rather than stringified
JSON. `{"voltage_volts":3.29,"wire_resistance_ohms":0.069}` is a shape a machine reads; down a column the
braces and quotes are most of the characters and none of the information. It is deliberately **not** YAML
and not reversible — nothing parses it back, keys are printed plainly rather than quoted-when-necessary,
and a round-trip guarantee would cost exactly the punctuation this exists to remove. Object keys come out
sorted, because a table whose rows reorder their own keys between renders is unreadable.

On a narrow screen the table becomes **one card per row**: the header row is hidden and each cell labels
itself from a `data-label` attribute. A wide table with structured cells is unreadable on a phone whichever
way it is turned, and scrolling a table sideways means losing the row being read.

#### Reading a chart on a phone, and drilling into a point

An inline plot **fits its container**; it does not scroll sideways. That costs the legibility of its axis
labels at phone width — a `viewBox` is scaled by the browser, text included, so a 960-unit plot in a 360px
viewport renders an 11px label at about 4px — so below the breakpoint those labels are **hidden** rather
than shrunk. A 4px tick is not information; it is noise with a size. The inline plot then reads as a
shape, and the readable version is one tap away.

`GET /chart` is that version: one chart, its own page, and **the same chart rendered at two geometries**
with a media query choosing between them. The duplication is the point rather than an accident — no single
`viewBox` can be legible at both 360px and 1200px, so the page whose only job is legibility ships one
sized for each. One extra copy of one chart is cheap; a scrollbar or 4px text is not.

**Each mark on that page is a link.** A point is an average over a bucket, not a measurement, so "show me
this point" can only honestly mean "show me the rows behind it" — the link carries *that bucket's* window
(`range=custom` plus explicit `from`/`to`) back to the explorer, where the table lists them. Building those
links is why §14 needs a percent-encoder at all: attribute keys are device-supplied and may contain
anything, so interpolating one raw would produce a URL that means something else.

#### Three departures from what an interactive chart would do

All follow from §14.6's no-JavaScript rule, and each is a trade rather than an omission:

- **No crosshair or hover readout.** Each mark carries an SVG `<title>`, which browsers render as a
  native tooltip with no scripting. The property that matters — *a tooltip must never be the only way to
  read a value* — holds because the table below carries every value.
- **No fullscreen overlay and no zoom.** `/chart` is a page, not an overlay: bookmarkable, needs no
  scripting, and free to use a geometry an overlay could not. Zooming a bucketed plot would only show more
  pixels of the same averages; the range control re-queries instead.
- **Toggling a series is a navigation, not a click handler.** Each legend entry is a link that re-renders
  without that line. It costs a request, and buys a decluttered view that is still a URL.
- **Monospace rather than a UI sans.** It is the established look of these pages, suits the hex-id and
  JSON-heavy tables, and gives tabular figures on axis ticks for free.

#### Rendering

`web::svg` is pure — data in, a `String` of markup out — so scales, tick selection and path building are
ordinary unit-tested functions. Ticks are round: values on a 1 / 2 / 5 × 10ⁿ ladder, instants on a fixed
ladder of 1 s … 30 d steps aligned to the epoch, because those are the only intervals that land on round
wall-clock times.

**A bucket with no value breaks the line rather than being interpolated across.** Joining across a gap
draws a straight line through a period when nothing was reported, which is the most common way a
time-series chart lies.

SVG is XML, so the same escaping applies as in §14.6: an unescaped `<` in a group label — and group
labels are device-supplied — is as dangerous in a `<title>` as in an element body.
