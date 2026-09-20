# State Movement Fabric

**State Movement Fabric (SMF) 1.0.2** is an open-source, vendor-neutral C++20 runtime for
governing the cross-network movement of reusable AI state: model weights, adapters, tensors,
KV caches, prefix caches, checkpoints, derived artifacts, and opaque blobs.

The question it answers is deliberately narrow:

> For this exact state object and generation, may it move from this source to this destination
> now, under what compatibility, locality, integrity, network, and authority conditions, and
> when does the destination become usable?

The destination is **not** authoritative because bytes exist there. Value exists only when the
coordinator has independently re-hashed the stored bytes and the destination has written a
commit marker at the coordinator's explicit request.

## Exact boundary

SMF owns the movement transaction across a network boundary:

* canonical state identity and content-digest binding;
* source and destination endpoint and incarnation binding;
* compatibility **evidence** (never a compatibility opinion of its own);
* chunked transfer with bounded buffers and windowed flow control;
* resumable transfers, but only over a verified, journalled prefix;
* explicit non-repeatable / ambiguous-outcome handling;
* destination integrity verification performed by the coordinator itself;
* an atomic commit marker as the completion barrier;
* supersession when a source state generation changes;
* cancellation, bounded retry, provenance, and deterministic reason codes;
* persistence that keeps completed history and never restores endpoint liveness.

SMF does **not** own, and makes no attempt to interpret:

* the internal semantics, layout, dtype, or quantization of KV caches, tensors, or models;
* model repositories or checkpoint formats;
* generic route planning or cluster scheduling;
* final reuse authority beyond reporting a verified destination candidate;
* authentication of end users, or key distribution (the shared secret is supplied by the
  operator);
* device memory management. CUDA appears only in one proof path and one source helper; the core
  library has no accelerator dependency.

## Core model

| Type | Meaning |
| --- | --- |
| `StateObjectId` | SHA-256 over a domain separator, the state kind, and the logical name. Stable across generations. |
| `StateGeneration` | Monotonic content generation of one object. Zero is never valid. A bump makes every in-flight movement for the older generation stale. |
| `StateKind` | `MODEL`, `ADAPTER`, `TENSOR`, `KV`, `PREFIX`, `CHECKPOINT`, `ARTIFACT`, `GENERIC_BLOB`, `UNKNOWN`. `UNKNOWN` is a real distinct kind, not a synonym for any other. |
| `MovementId` | Identity of one movement transaction. |
| `MovementGeneration` | Fencing token that advances on every accepted transition, so a late report computed against an older revision is refused. |
| `TransferAttemptId` | Identity of one transfer session within a movement. |
| `SourceIncarnation`, `DestinationIncarnation` | `(endpoint, fresh boot id, monotonic epoch)`. A restarted process can never be mistaken for the one it replaced. |
| `CompatibilityGeneration` | Generation of the published compatibility-evidence set. |
| `TopologyGeneration` | Generation of the coordinator's live view. Advances on every registration and on restart. |
| `PolicyGeneration` | Generation of the active policy set. |

Every movement record stores the topology, policy, and compatibility generations it was decided
under, so a stale decision is recognised rather than re-derived.

### Authority rules

* Observation is not authority. Eligibility is not authority. Planning is not authority.
* Dispatch is not completion. Completion is not authoritative commit.
* Persistence is not currentness. A reachable peer is not a current peer.
* A matching identifier is not a current generation.
* A successful backend call is not proof that the requested effect exists.
* `UNKNOWN` stays distinct from `SUPPORTED` and `UNSUPPORTED`. Missing evidence never becomes
  positive evidence.
* A coordinator restart resurrects nothing: the topology generation advances, every registration
  is dropped, every transfer grant is gone, the announced-version inventory is not restored, and
  anything that was mid-flight returns as `OUTCOME_UNKNOWN` or `FAILED` and must be reconciled.

### Stale completions

A late report from an earlier attempt is never consumed as the current attempt's outcome. The
coordinator matches an attempt result on both the movement identity and the attempt identity,
discards anything else into provenance, and waits past it. Verification responses must name the
movement and object version that were asked about, and a commit result must answer the movement
generation that was committed. A response that no longer has a waiter is a late or duplicate
completion of an already resolved exchange: it is counted and dropped, never re-applied and never
treated as a protocol violation.

## Movement state machine

```
PLANNED -> AUTHORIZED -> TRANSFERRING -> BYTES_ARRIVED -> VERIFIED -> COMMITTED
   |            |              |               |            |
   +------------+--------------+---------------+------------+--> CANCELLED
   |            |              |               |            |
   +------------+--------------+---------------+------------+--> FAILED
   |            |              |               |            |
   +------------+--------------+---------------+------------+--> SUPERSEDED
   |            |              |               |            |
   +------------+--------------+---------------+------------+--> OUTCOME_UNKNOWN
                                                                     |
                              OUTCOME_UNKNOWN -> COMMITTED / FAILED / CANCELLED / SUPERSEDED
                                                 (only by reconciliation, with proof)
```

`OUTCOME_UNKNOWN` is not terminal: it is a statement about knowledge, not about outcome, and only
reconciliation may resolve it. A retry after `BYTES_ARRIVED` is a legal transition back to
`TRANSFERRING`, because bytes that failed independent verification are not authority.

## Decisions and reason codes

Every decision is a code plus an explanation; there is no boolean authority answer in the public
API. Codes are stable uppercase strings, and their numeric values are part of the durable store
format and the wire protocol. Examples:

| Code | Meaning |
| --- | --- |
| `STALE_INCARNATION` | The endpoint restarted, so the decision that named it is void. |
| `STALE_POLICY_GENERATION` | A grant or decision was issued under a different policy generation. |
| `STALE_ATTEMPT` | A completion or probe names a movement or attempt that is no longer current. |
| `AUTHORITY_MISMATCH` | A grant nonce is unknown, already consumed, or binds a different subject. |
| `CHUNK_OUT_OF_ORDER` | A chunk arrived that is not the next expected one. |
| `CHUNK_CONFLICT` | A replayed chunk does not match the bytes already stored at its index. |
| `CONTENT_DIGEST_MISMATCH` | Stored bytes do not hash to the authorised content digest. |
| `COMMIT_ALREADY_EXISTS` | A different commit marker already exists for that object version. |
| `OUTCOME_UNKNOWN` | The effect may have happened and cannot be proven either way. |
| `REVALIDATION_REQUIRED` | The binding went stale and must be re-established before retrying. |

## Compatibility semantics

The fabric draws a hard line between two different permissions:

* **Permission to move bytes.** This is what the fabric decides. It is about identity, integrity,
  locality, generations, incarnations, and policy.
* **Permission to treat destination state as reusable.** This is what compatibility evidence is
  about, and the fabric does not form that opinion.

`CompatibilityProvider` is the seam. `CompatibilityRegistry` is a concrete provider that stores
only what an operator explicitly publishes; it never infers. The query contract is explicit:

* no published evidence returns `NO_EVIDENCE` — the verdict is unknown, not positive;
* evidence that does not bind the exact object version, content digest, and destination returns
  `COMPATIBILITY_STALE_EVIDENCE`, not a positive result;
* a published `UNKNOWN` verdict is **not** support, and is refused when the policy requires
  evidence;
* publishing `UNSUPPORTED` refuses the movement.

When a coordinator is started without a provider, it records an explicit
`COMPATIBILITY_UNKNOWN` note in the movement's provenance and proceeds. That is a deliberate,
visible statement that the fabric has no compatibility opinion — it is not a claim that the state
is compatible. An embedder that needs enforcement supplies a provider and sets
`MovementPolicy::require_compatibility_evidence`.

There is deliberately no wire path for publishing compatibility evidence. Compatibility is a
property of the systems on either side of the fabric, so it enters through the embedding library
or an operator channel, never through a peer that benefits from a positive verdict.

## Processes and protocol

Three executables are built:

* `smf_coordinator` — the authority. Owns movements, generations, topology, and the durable store.
* `smf_endpoint` — holds state objects, serves them to peers holding a grant, and receives objects
  under the same authority.
* `smf` — the operator command line, speaking the coordinator's admin channel.

The data plane is **peer to peer**: the destination connects directly to the source over TCP and
pulls the object. The coordinator issues a signed, single-use transfer grant to both endpoints over
their own authenticated sessions; the grant never travels through a peer. The data connection runs
the same mutual-authentication handshake as the control plane, so the source knows exactly which
endpoint is asking and checks it against the grant.

A grant is authority delegated by one coordinator incarnation over one session. When the control
session ends, every grant and cancellation the endpoint holds is dropped with it, so a stale token
cannot be presented to a later incarnation.

Frames are fixed-layout, versioned, length-delimited, and authenticated:

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 4 | magic `SMF1` |
| 4 | 1 | protocol version |
| 5 | 1 | flags |
| 6 | 2 | reserved, must be zero |
| 8 | 2 | message type |
| 10 | 2 | reserved, must be zero |
| 12 | 4 | payload length |
| 16 | 8 | session sequence number |
| 24 | 16 | truncated HMAC-SHA-256 tag |
| 40 | N | payload |

Decoders reject a wrong magic, an unsupported version, non-zero reserved fields, unknown flag bits,
an oversized payload, a repeated or skipped sequence number, a non-canonical boolean, invalid UTF-8,
an absurd collection count, and trailing bytes. All input is treated as untrusted.

### Verification the coordinator performs

The destination reports its own digest; that report is **not** accepted as authority. The
coordinator additionally:

1. asks for a full-content digest recomputation and compares it with the authorised digest and byte
   count;
2. samples chunk indices derived from the movement identity, asks for the **raw bytes** of each
   sampled chunk, and hashes them in the coordinator process;
3. compares its own hash with the digest the destination claimed for that chunk;
4. only then asks the destination to write the commit marker.

## Persistence

The coordinator store is a versioned, checksummed, append-only record log with a fixed header.
Recovery rules:

* a record is applied only when it is completely present, its sequence number is strictly greater
  than the previous one, and its SHA-256 checksum matches;
* a trailing incomplete record is discarded and reported as `STORE_PARTIAL_TAIL`, never silently;
* a checksum failure on any record that is not the final one, an unknown magic, an unsupported
  version, an unknown record type, a duplicate or regressing sequence, or an absurd declared length
  is fatal: the store refuses to open rather than partially applying a damaged file;
* a refused open never modifies the file and always releases the exclusive lock.

An acknowledgement never precedes the durability point it claims: the coordinator persists a
transition before it reports it.

Deliberately **not** durable: endpoint liveness, topology membership, transfer grants, the
announced-version inventory, and in-flight attempt state.

Destination-side layout:

```
staging/<movement-id>/data.part          bytes received so far
staging/<movement-id>/journal            verified prefix and per-chunk digests
objects/<object-id>/<generation>/data    verified bytes, promoted after the digest check
commits/<object-id>/<generation>.marker  the atomic commit marker
quarantine/<movement-id>/...             residue that must not be reused
```

The commit marker is written as write-temp, flush, atomic rename, so a partially written marker can
never be observed. The staging journal is written after every accepted chunk, independently of
whether device syncing is enabled, because the journal is what makes an interrupted attempt
resumable at all. A resumed transfer re-reads and re-hashes the whole verified prefix from disk
before appending, so a journal that claims more progress than the bytes support is discarded.

## Restart and recovery semantics

Restart is **supervisor-owned**, and this is a deliberate boundary rather than an omission.

* An endpoint does not silently re-attach to a restarted coordinator. It detects the loss of the
  control session, drops every grant and cancellation it was holding, and logs the event. A
  supervisor starts a fresh endpoint process, which acquires a new boot id and a higher
  incarnation epoch and registers again.
* This keeps a single source of session authority. An automatic reconnect would create a second
  one, and the fabric prefers an explicit, observable restart to a quiet re-attachment.
* The coordinator side of the same boundary is proven: after a restart the topology contains no
  live endpoints, the topology generation has advanced, the incarnation epoch has advanced, the
  announced-version inventory is empty, and the submission that previously succeeded is refused.

## Bounded resources

Worker and session counts, queue depth, in-flight movements, payload sizes, chunk counts, retry
state, retained history, provenance events, and store growth are all bounded by policy or by
structural limits, and every externally supplied length or count is checked before it can reach a
loop or an allocation. Every path that acquires staging bytes, object bytes, markers, directory
locks, sessions, or threads is exercised back to a baseline by the resource-closure suite.

## Proof surfaces

Labelled honestly:

| Surface | Status |
| --- | --- |
| Loopback TCP transport, framing, mutual authentication, replay rejection | **REAL**, validated on this host |
| Independent source/destination/coordinator **processes** moving real bytes | **REAL**, validated on this host |
| Process kill at named barriers, reconciliation, no double commit | **REAL**, validated on this host |
| Coordinator restart conservatism, incarnation fencing, stale completion rejection | **REAL**, validated on this host |
| Durable append-only store: torn tails, corruption, version and sequence rejection | **REAL**, validated on this host |
| Concurrency, repeated lifecycle, session and thread closure | **REAL**, validated on this host |
| Scale to 100 000 durable records with keyed lookup | **REAL**, validated on this host |
| **CUDA device memory** as a state source, moved over loopback TCP between independent processes | **REAL**, validated on this host on an RTX 5090 |
| x64 MSVC AddressSanitizer, instrumented and independently verified | **REAL**, validated on this host |
| Multi-host, RDMA, GPUDirect, NVLink, InfiniBand, RoCE, SmartNIC/DPU, programmable switch | **UNSUPPORTED** and not claimed; no such hardware was exercised |
| Peer-to-peer device transfer, multi-GPU, device-to-device movement | **UNSUPPORTED** and not claimed |
| Linux/POSIX build | **UNSUPPORTED** as validated: the socket layer has a POSIX branch, but it was not built or run on this host |

Every transfer proof in this repository runs real processes over loopback TCP on one host. No
multi-host, remote-network, or accelerator-interconnect claim is made anywhere.

## Build

Requirements: CMake 3.20 or newer, a C++20 compiler, and the platform thread and socket libraries.
There are no third-party dependencies. CUDA is optional and used only by the device proof.

```
cmake -S . -B build/release -DCMAKE_BUILD_TYPE=Release
cmake --build build/release --config Release --parallel
```

On Windows with Visual Studio 2022 the multi-config generator is used:

```
cmake -S . -B build/release -G "Visual Studio 17 2022" -A x64
cmake --build build/release --config Release --parallel
```

Options:

| Option | Default | Meaning |
| --- | --- | --- |
| `SMF_BUILD_APPS` | ON | Build the coordinator, endpoint, and command line. |
| `SMF_BUILD_TESTS` | ON | Build the proof suites. |
| `SMF_BUILD_EXAMPLES` | ON | Build the examples. |
| `SMF_WARNINGS_AS_ERRORS` | ON | `/W4 /WX` on MSVC, `-Wall -Wextra ... -Werror` elsewhere. |
| `SMF_SANITIZE` | empty | `address` or `undefined`. |
| `SMF_ENABLE_CUDA` | OFF | Build the device-memory proof and the endpoint's device publication path. |

### Building the device proof

The CUDA configuration needs a generator whose toolchain CMake can drive with `nvcc`. If the
Visual Studio installation has no CUDA build customizations, use Ninja from a Visual Studio
environment:

```
cmake -S . -B build/cuda -G Ninja -DCMAKE_BUILD_TYPE=Release ^
      -DSMF_ENABLE_CUDA=ON -DCMAKE_CUDA_ARCHITECTURES=native ^
      -DCMAKE_CUDA_COMPILER="<cuda>/bin/nvcc.exe"
cmake --build build/cuda --parallel
ctest --test-dir build/cuda --output-on-failure -L cuda
```

## Test

```
ctest --test-dir build/release -C Release --output-on-failure
```

No test carries a timeout and no watchdog fails a test on elapsed time. A hanging proof is a defect
to diagnose. Seeded property suites print the reproduction seed and iteration on failure and accept
`--seed=<n>`; the same value can be supplied through `SMF_TEST_SEED`.

| Suite | Surface |
| --- | --- |
| `smf_unit_digest`, `smf_unit_codec`, `smf_unit_ids` | Deterministic unit proofs; SHA-256 and HMAC vectors generated independently. |
| `smf_protocol_transport` | Real loopback TCP, blocked-reader release, repeated lifecycle cycles. |
| `smf_protocol_wire_adversarial` | Every message round-tripped, then attacked: bad magic and version, zero and oversized lengths, every truncated prefix, corrupted domains and integrity fields, replayed and regressed sequences, forged and contradictory grants, invalid enums and Unicode, absurd counts, trailing garbage. |
| `smf_persistence_adversarial` | Valid reopen, torn final record, truncated header and payload, corrupt checksums, impossible payloads with valid checksums, absurd declared lengths, unsupported versions, invalid record types, duplicate and non-monotonic sequences, trailing garbage, stale replay, repeated reopen, compaction interruption, refused-open lock release, exclusive locking. |
| `smf_concurrency_lifecycle` | Deterministic latches over coordinator start/stop, idle-client shutdown, concurrent store mutation and query, concurrent compatibility publishing, topology lifecycle, repeated endpoint start/stop. |
| `smf_scale_store` | 1 000 / 10 000 / 100 000 durable records with measured insert, reopen, and keyed lookup; retention bounds; keyed topology lookup. |
| `smf_resource_closure` | Staging released on promotion, targeted cleanup, quarantine, failed-transfer residue, repeated store and endpoint lifecycles, coordinator session and thread accounting. |
| `smf_multiprocess_movement` | Real coordinator and endpoint processes, real byte transfer, kills at chosen barriers, reconciliation, cancellation, restart conservatism. |
| `smf_cuda_device_state` | Real device memory as a state source, moved over loopback TCP and committed exactly once. |

## Scale and benchmark results

Measured on this host with the store configured without per-write device syncing, so the numbers
describe the data structures rather than the disk. Every figure is taken after the work has
completed and been read back.

| Records | Insert | Log size | Reopen |
| --- | --- | --- | --- |
| 1 000 | 11.5 ms | 0.7 MB | 7.6 ms |
| 10 000 | 119.4 ms | 6.9 MB | 69.6 ms |
| 100 000 | 1 215.4 ms | 68.6 MB | 610.3 ms |

Insert and reopen both scale by roughly ten for every tenfold increase in records, which is the
linear behaviour the format promises. Keyed lookup does not depend on history size: 4 000 lookups
took 0.8 ms over 1 000 records and 1.7 ms over 100 000, a ratio of 2.24 where a linear scan would
have shown a factor of one hundred. Topology indexing is keyed as well: 2 000 endpoints inserted in
2.5 ms and 20 000 lookups completed in 4.3 ms.

## Install and consume

```
cmake --install build/release --config Release --prefix /some/prefix
cmake -S consumers/find_package_consumer -B build/consumer -DCMAKE_PREFIX_PATH=/some/prefix
cmake --build build/consumer --config Release
```

The consumer is an independent project: it shares no build tree with the library and uses only
`find_package(SMF 1.0 REQUIRED)` and the exported `smf::core` target.

Only static linkage is produced and validated; shared-library linkage is not built, because the
public API uses standard-library types in class layouts and no C++ ABI boundary is claimed.

## Public API sketch

```cpp
#include <smf/coordinator.hpp>   // authority: movements, generations, topology
#include <smf/endpoint_agent.hpp> // a process that holds and moves state
#include <smf/movement.hpp>       // records, decisions, the state machine
#include <smf/state_object.hpp>   // canonical identity, descriptors, segmentation
#include <smf/object_store.hpp>   // staging, verification, commit markers
#include <smf/compatibility.hpp>  // the compatibility evidence seam
#include <smf/wire.hpp>           // canonical message codecs

// Identity and content binding.
auto object_id = smf::derive_state_object_id(smf::StateKind::KV, "model/layer-3/kv");
auto descriptor = smf::StateObjectDescriptor::create(
    smf::StateKind::KV, "model/layer-3/kv", smf::StateGeneration(4), content_digest,
    total_bytes, chunk_bytes, smf::system_clock().unix_millis(), "producer");

// Authority.
smf::CoordinatorConfig config;
config.state_directory = "/var/lib/smf";
config.shared_secret = /* 32 bytes */;
config.compatibility = std::make_shared<smf::CompatibilityRegistry>();
auto coordinator = smf::Coordinator::start(config);

smf::SubmitMovement request;      // object version, source, destination
auto accepted = coordinator.value()->submit(request);
auto record = coordinator.value()->query(accepted.value().movement_id);

// Publishing bytes that already exist in host memory.
smf::EndpointAgentConfig endpoint_config;
auto agent = smf::EndpointAgent::start(endpoint_config);
agent.value()->publish_bytes(smf::StateKind::KV, "model/layer-3/kv", smf::StateGeneration(4),
                             host_bytes, "producer", /*repeatable=*/true);
```

## Device memory

The device proof is a source of state, not a property of the movement transaction. A source
endpoint can be started with:

```
smf_endpoint ... --publish-cuda KIND:NAME:GENERATION:BYTES:SEED
```

It allocates real device memory, fills it with a deterministic pattern using a kernel that runs on
the device, copies the result to the host, publishes those exact bytes as an ordinary state object,
frees the allocation, and prints a report line containing the device name, the runtime version,
the bytes staged, the free-memory baseline before and after, and the digest of what was published.
That report is what the proof parses; it is not a claim about how the bytes travelled. The bytes
travel over ordinary loopback TCP like any other state object.

## Fault injection

Named injection points exist so that a process can be made to die at an exact barrier. Injection is
off unless a process is started with `--fault-inject <spec>`:

```
--fault-inject destination.after_commit_marker=hold,source.after_chunk_send@2=exit
```

Actions are `exit` (abrupt death, no unwinding, no flush, no destructors) and `hold` (park so an
external killer can land there). Points: `source.after_chunk_send`, `source.before_end`,
`destination.after_chunk_write`, `destination.before_commit_marker`,
`destination.after_commit_marker`, `coordinator.before_commit_request`,
`coordinator.after_authorize`, `endpoint.after_register`.

## Limits actually observed

* Validated on Windows 11 with MSVC 19.44, CMake 4.3, and loopback TCP on a single host.
* The POSIX socket branch exists but was not compiled or run on this host.
* The CUDA configuration is built with Ninja because this machine's Visual Studio Build Tools
  installation carries no CUDA build customizations, so CMake's Visual Studio generator cannot
  drive `nvcc` here.
* An AddressSanitizer-built executable needs the MSVC sanitizer runtime directory on `PATH`; the
  runtime DLL is not copied next to the binary.
* Chunk resumption is journalled per chunk and is not offered above 65 536 chunks per object, where
  the journal would grow without bound; such a transfer simply restarts cleanly.
* The coordinator has no compatibility provider by default. It then records
  `COMPATIBILITY_UNKNOWN` explicitly and proceeds, rather than treating silence as support.
* Endpoints do not reconnect to a restarted coordinator automatically. Restart is supervisor-owned
  and the boundary is documented and tested above.
* Endpoint processes exit when their coordinator link ends and they are not asked to reconnect;
  a supervisor is expected to notice and restart them.
* The scale figures above were taken without per-write device syncing, which is the configuration
  that isolates data-structure behaviour from storage latency.

## License

Apache License 2.0. Copyright 2026 Summon Software Labs. No telemetry transmission.
