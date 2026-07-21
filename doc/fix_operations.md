# FIX Protocol Operations Specification

This document defines all operations that IronFix servers should support. It covers session-level messages, application-level messages, and the expected behavior for each operation.

## Table of Contents

1. [Session Layer Messages](#session-layer-messages)
2. [Pre-Trade Messages](#pre-trade-messages)
3. [Trade Messages](#trade-messages)
4. [Post-Trade Messages](#post-trade-messages)
5. [Market Data Messages](#market-data-messages)
6. [Error Handling](#error-handling)

---

## Session Layer Messages

These messages are required for establishing and maintaining FIX sessions.

### Logon (MsgType = A)

**Direction**: Bidirectional (Initiator → Acceptor, Acceptor → Initiator)

**Purpose**: Establish a FIX session between two parties.

**Required Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 8 | BeginString | FIX version (e.g., "FIX.4.4", "FIXT.1.1") |
| 9 | BodyLength | Message body length |
| 35 | MsgType | "A" |
| 49 | SenderCompID | Sender identifier |
| 56 | TargetCompID | Target identifier |
| 34 | MsgSeqNum | Message sequence number |
| 52 | SendingTime | Timestamp (UTC) |
| 98 | EncryptMethod | Encryption method (0 = None) |
| 108 | HeartBtInt | Heartbeat interval in seconds |
| 10 | CheckSum | Message checksum |

**Optional Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 141 | ResetSeqNumFlag | Reset sequence numbers (Y/N) |
| 553 | Username | Authentication username |
| 554 | Password | Authentication password |
| 1137 | DefaultApplVerID | Default application version (FIX 5.0+) |

**Server Behavior**:
1. Validate SenderCompID and TargetCompID
2. Authenticate credentials if provided
3. Initialize session state
4. Respond with Logon message
5. Begin heartbeat monitoring

---

### Logout (MsgType = 5)

**Direction**: Bidirectional

**Purpose**: Gracefully terminate a FIX session.

**Required Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 35 | MsgType | "5" |
| 49 | SenderCompID | Sender identifier |
| 56 | TargetCompID | Target identifier |
| 34 | MsgSeqNum | Message sequence number |
| 52 | SendingTime | Timestamp |

**Optional Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 58 | Text | Logout reason |

**Server Behavior**:
1. Send Logout response
2. Wait for acknowledgment (optional)
3. Close TCP connection
4. Persist session state for recovery

---

### Heartbeat (MsgType = 0)

**Direction**: Bidirectional

**Purpose**: Maintain session connectivity and detect connection failures.

**Required Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 35 | MsgType | "0" |
| 49 | SenderCompID | Sender identifier |
| 56 | TargetCompID | Target identifier |
| 34 | MsgSeqNum | Message sequence number |
| 52 | SendingTime | Timestamp |

**Optional Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 112 | TestReqID | Echo of TestRequest ID |

**Server Behavior**:
1. Send Heartbeat at configured interval if no other messages sent
2. When responding to TestRequest, include TestReqID (tag 112)
3. Monitor for missing heartbeats from counterparty

---

### Test Request (MsgType = 1)

**Direction**: Bidirectional

**Purpose**: Request a Heartbeat from counterparty to verify connectivity.

**Required Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 35 | MsgType | "1" |
| 49 | SenderCompID | Sender identifier |
| 56 | TargetCompID | Target identifier |
| 34 | MsgSeqNum | Message sequence number |
| 52 | SendingTime | Timestamp |
| 112 | TestReqID | Unique request identifier |

**Server Behavior**:
1. Send TestRequest if no message received within HeartBtInt + tolerance
2. Expect Heartbeat response with matching TestReqID
3. If no response, consider session disconnected

---

### Resend Request (MsgType = 2)

**Direction**: Bidirectional

**Purpose**: Request retransmission of messages within a sequence range.

**Required Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 35 | MsgType | "2" |
| 7 | BeginSeqNo | First sequence number to resend |
| 16 | EndSeqNo | Last sequence number (0 = infinity) |

**Server Behavior**:
1. Retrieve messages from message store
2. Resend with PossDupFlag = Y
3. Use SequenceReset-GapFill for admin messages
4. Maintain original SendingTime with OrigSendingTime

---

### Reject (MsgType = 3)

**Direction**: Bidirectional

**Purpose**: Reject a malformed or invalid message at the session level.

**Required Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 35 | MsgType | "3" |
| 45 | RefSeqNum | Sequence number of rejected message |

**Optional Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 371 | RefTagID | Tag number causing rejection |
| 372 | RefMsgType | Message type of rejected message |
| 373 | SessionRejectReason | Reason code |
| 58 | Text | Human-readable explanation |

**Session Reject Reasons**:
| Code | Description |
|------|-------------|
| 0 | Invalid tag number |
| 1 | Required tag missing |
| 2 | Tag not defined for message type |
| 3 | Undefined tag |
| 4 | Tag specified without value |
| 5 | Value incorrect for tag |
| 6 | Incorrect data format |
| 7 | Decryption problem |
| 8 | Signature problem |
| 9 | CompID problem |
| 10 | SendingTime accuracy problem |
| 11 | Invalid MsgType |
| 99 | Other |

---

### Sequence Reset (MsgType = 4)

**Direction**: Bidirectional

**Purpose**: Reset sequence numbers or fill gaps in message sequence.

**Required Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 35 | MsgType | "4" |
| 36 | NewSeqNo | New sequence number |

**Optional Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 123 | GapFillFlag | Y = Gap Fill, N = Reset |

**Server Behavior**:
- **Gap Fill Mode**: Skip sequence numbers for admin messages during resend
- **Reset Mode**: Force sequence number reset (use with caution)

---

## Pre-Trade Messages

### Security Definition Request (MsgType = c)

**Purpose**: Request security/instrument definitions.

**Key Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 320 | SecurityReqID | Unique request identifier |
| 321 | SecurityRequestType | Type of request |
| 55 | Symbol | Security symbol (optional) |
| 48 | SecurityID | Security identifier (optional) |

**Server Response**: Security Definition (MsgType = d)

---

### Security List Request (MsgType = x)

**Purpose**: Request a list of available securities.

**Key Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 320 | SecurityReqID | Unique request identifier |
| 559 | SecurityListRequestType | Type of list request |

**Server Response**: Security List (MsgType = y)

---

## Trade Messages

### New Order Single (MsgType = D)

**Direction**: Client → Server

**Purpose**: Submit a new order.

**Required Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 35 | MsgType | "D" |
| 11 | ClOrdID | Client order identifier |
| 21 | HandlInst | Handling instructions |
| 55 | Symbol | Security symbol |
| 54 | Side | Buy (1) / Sell (2) |
| 60 | TransactTime | Order creation time |
| 38 | OrderQty | Order quantity |
| 40 | OrdType | Order type |

**Optional Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 44 | Price | Limit price |
| 99 | StopPx | Stop price |
| 59 | TimeInForce | Order duration |
| 18 | ExecInst | Execution instructions |
| 1 | Account | Account identifier |

**Order Types (Tag 40)**:
| Value | Description |
|-------|-------------|
| 1 | Market |
| 2 | Limit |
| 3 | Stop |
| 4 | Stop Limit |
| P | Pegged |

**Side (Tag 54)**:
| Value | Description |
|-------|-------------|
| 1 | Buy |
| 2 | Sell |
| 5 | Sell Short |
| 6 | Sell Short Exempt |

**Server Response**: Execution Report (MsgType = 8)

---

### Order Cancel Request (MsgType = F)

**Direction**: Client → Server

**Purpose**: Request cancellation of an existing order.

**Required Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 35 | MsgType | "F" |
| 11 | ClOrdID | New client order ID |
| 41 | OrigClOrdID | Original client order ID |
| 55 | Symbol | Security symbol |
| 54 | Side | Order side |
| 60 | TransactTime | Request time |

**Server Response**: 
- Execution Report with ExecType = 4 (Canceled)
- Order Cancel Reject (MsgType = 9) if rejection

---

### Order Cancel/Replace Request (MsgType = G)

**Direction**: Client → Server

**Purpose**: Modify an existing order (price, quantity, etc.).

**Required Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 35 | MsgType | "G" |
| 11 | ClOrdID | New client order ID |
| 41 | OrigClOrdID | Original client order ID |
| 55 | Symbol | Security symbol |
| 54 | Side | Order side |
| 60 | TransactTime | Request time |
| 38 | OrderQty | New quantity |
| 40 | OrdType | Order type |

**Optional Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 44 | Price | New limit price |

**Server Response**:
- Execution Report with ExecType = 5 (Replaced)
- Order Cancel Reject if rejection

---

### Order Status Request (MsgType = H)

**Direction**: Client → Server

**Purpose**: Request current status of an order.

**Required Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 35 | MsgType | "H" |
| 11 | ClOrdID | Client order ID |
| 55 | Symbol | Security symbol |
| 54 | Side | Order side |

**Server Response**: Execution Report with current order status

---

### Execution Report (MsgType = 8)

**Direction**: Server → Client

**Purpose**: Report order status, fills, and rejections.

**Required Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 35 | MsgType | "8" |
| 37 | OrderID | Server order identifier |
| 11 | ClOrdID | Client order identifier |
| 17 | ExecID | Execution identifier |
| 150 | ExecType | Execution type |
| 39 | OrdStatus | Order status |
| 55 | Symbol | Security symbol |
| 54 | Side | Order side |
| 151 | LeavesQty | Remaining quantity |
| 14 | CumQty | Cumulative filled quantity |
| 6 | AvgPx | Average fill price |

**Execution Types (Tag 150)**:
| Value | Description |
|-------|-------------|
| 0 | New |
| 1 | Partial Fill |
| 2 | Fill |
| 3 | Done for Day |
| 4 | Canceled |
| 5 | Replaced |
| 6 | Pending Cancel |
| 7 | Stopped |
| 8 | Rejected |
| 9 | Suspended |
| A | Pending New |
| C | Expired |
| D | Restated |
| E | Pending Replace |
| F | Trade |
| H | Trade Cancel |
| I | Trade Correct |

**Order Status (Tag 39)**:
| Value | Description |
|-------|-------------|
| 0 | New |
| 1 | Partially Filled |
| 2 | Filled |
| 3 | Done for Day |
| 4 | Canceled |
| 5 | Replaced |
| 6 | Pending Cancel |
| 7 | Stopped |
| 8 | Rejected |
| 9 | Suspended |
| A | Pending New |
| B | Calculated |
| C | Expired |
| D | Accepted for Bidding |
| E | Pending Replace |

---

### Order Cancel Reject (MsgType = 9)

**Direction**: Server → Client

**Purpose**: Reject a cancel or cancel/replace request.

**Required Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 35 | MsgType | "9" |
| 37 | OrderID | Server order ID |
| 11 | ClOrdID | Client order ID of request |
| 41 | OrigClOrdID | Original order ID |
| 39 | OrdStatus | Current order status |
| 434 | CxlRejResponseTo | 1 = Cancel, 2 = Cancel/Replace |
| 102 | CxlRejReason | Rejection reason code |

---

### Order Mass Cancel Request (MsgType = q)

**Direction**: Client → Server

**Purpose**: Cancel multiple orders at once.

**Key Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 530 | MassCancelRequestType | Scope of cancellation |
| 11 | ClOrdID | Request identifier |

**Server Response**: Order Mass Cancel Report (MsgType = r)

---

## Post-Trade Messages

### Allocation Instruction (MsgType = J)

**Purpose**: Allocate trades to sub-accounts.

**Key Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 70 | AllocID | Allocation identifier |
| 71 | AllocTransType | Transaction type |
| 626 | AllocType | Allocation type |

---

### Confirmation (MsgType = AK)

**Purpose**: Confirm trade allocation.

**Key Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 664 | ConfirmID | Confirmation identifier |
| 666 | ConfirmStatus | Status |

---

### Position Report (MsgType = AP)

**Purpose**: Report current positions.

**Key Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 721 | PosMaintRptID | Report identifier |
| 710 | PosReqID | Request ID (if requested) |
| 55 | Symbol | Security symbol |
| 704 | LongQty | Long position quantity |
| 705 | ShortQty | Short position quantity |

---

## Market Data Messages

### Market Data Request (MsgType = V)

**Direction**: Client → Server

**Purpose**: Subscribe to or request market data.

**Required Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 35 | MsgType | "V" |
| 262 | MDReqID | Request identifier |
| 263 | SubscriptionRequestType | 0=Snapshot, 1=Subscribe, 2=Unsubscribe |
| 264 | MarketDepth | Depth of book (0 = full) |
| 267 | NoMDEntryTypes | Number of entry types |
| 269 | MDEntryType | Entry type (repeating) |
| 146 | NoRelatedSym | Number of symbols |
| 55 | Symbol | Security symbol (repeating) |

**MD Entry Types (Tag 269)**:
| Value | Description |
|-------|-------------|
| 0 | Bid |
| 1 | Offer |
| 2 | Trade |
| 3 | Index Value |
| 4 | Opening Price |
| 5 | Closing Price |
| 6 | Settlement Price |
| 7 | Trading Session High |
| 8 | Trading Session Low |
| 9 | Trading Session VWAP |
| A | Imbalance |
| B | Trade Volume |
| C | Open Interest |

---

### Market Data Snapshot/Full Refresh (MsgType = W)

**Direction**: Server → Client

**Purpose**: Provide complete market data snapshot.

**Key Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 262 | MDReqID | Request identifier |
| 55 | Symbol | Security symbol |
| 268 | NoMDEntries | Number of entries |
| 269 | MDEntryType | Entry type |
| 270 | MDEntryPx | Price |
| 271 | MDEntrySize | Size |

---

### Market Data Incremental Refresh (MsgType = X)

**Direction**: Server → Client

**Purpose**: Provide incremental market data updates.

**Key Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 262 | MDReqID | Request identifier |
| 268 | NoMDEntries | Number of entries |
| 279 | MDUpdateAction | 0=New, 1=Change, 2=Delete |
| 269 | MDEntryType | Entry type |
| 270 | MDEntryPx | Price |
| 271 | MDEntrySize | Size |

---

### Market Data Request Reject (MsgType = Y)

**Direction**: Server → Client

**Purpose**: Reject a market data request.

**Key Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 262 | MDReqID | Request identifier |
| 281 | MDReqRejReason | Rejection reason |
| 58 | Text | Explanation |

---

## Error Handling

### Garbled Messages and Transport Resynchronization

**Scope**: `ironfix-transport::FixCodec` — the framing layer that turns a byte
stream into complete FIX frames. This subsection is the codec's contract; it
does not describe session-level rejection.

**FIX convention**: a *garbled* message — one whose framing cannot be trusted:
BeginString (8) is not the first field, BodyLength (9) is missing or does not
agree with the frame layout, or CheckSum (10) is absent or malformed — is
**ignored**. The receiver does **not** send a Reject, does **not** send a
ResendRequest for it, and does **not** increment the inbound MsgSeqNum, because
the sequence number of a garbled message cannot be trusted either. Recovery is
left to the normal gap-detection path on the next well-formed message.

**What IronFix implements today**

The codec detects garbling and, for the errors where a frame boundary can be
inferred, decides how many bytes to discard so that a caller which keeps reading
can make progress. The remaining variants consume nothing and a caller must
treat them as fatal. Consumption per error:

| `CodecError` | Bytes consumed from the read buffer |
|---|---|
| `InvalidBeginString` | up to and including the `<SOH>` of the next `<SOH>8` pair, so the buffer restarts at the `8` (the whole buffer when there is no such pair, minus a trailing `<SOH>` that may still be the first half of one) |
| `InvalidTrailer` | the same resync as above — the trailer is absent from the offsets BodyLength implies, so BodyLength is not corroborated and its declared length is not trusted to bound the discard |
| `InvalidChecksumFormat`, `ChecksumMismatch` | the whole declared frame (`BodyLength` + header + 7-byte trailer) |
| `MissingBodyLength`, `InvalidBodyLength`, `HeaderTooLong`, `MessageTooLarge`, `Io` | none — no frame boundary can be inferred |

Rationale for the two policies:

- After `InvalidBeginString` the stream position is unknown, so the only safe
  anchor is the next byte sequence that can legally start a frame: an SOH
  followed by `8`. Scanning to it is bounded by the buffer length and never
  allocates.
- After a checksum error the trailer literal is exactly where BodyLength said it
  would be, so the declared boundary is corroborated by the frame's own
  structure: consuming `BodyLength`-worth of bytes keeps a stream of otherwise
  well-formed frames aligned.
- A missing trailer is the opposite case — nothing corroborates BodyLength, and
  trusting it to size the discard hands an attacker a lever. A short header
  declaring a large body would otherwise consume every well-formed frame that
  merely follows it (tens of thousands, at the default ceiling) and report the
  loss as a single error. So this case resyncs instead.
- Recovery is best-effort, not lossless: because the anchor is `<SOH>8` rather
  than a bare `8=` (which occurs inside ordinary tags such as `18=` and `58=`),
  a well-formed frame arriving immediately after garbage is normally discarded
  with it, unless the garbage happens to end on an SOH. Recovery resumes at the
  frame after that one.
- Before the header is complete no boundary exists at all, so the codec keeps
  the bytes and bounds them instead: the header region `8=…<SOH>9=…<SOH>` is
  capped at 64 bytes and the whole frame at `max_message_size` (1 MiB by
  default). Exceeding either is an error, never a request for more data — this
  is what stops a peer from growing the read buffer without bound.

**What IronFix does not implement**

- **The MsgSeqNum half of the convention is the session layer's
  responsibility and is not implemented.** The codec has no access to session
  state and never touches sequence numbers; nothing in `ironfix-session` or
  `ironfix-engine` currently distinguishes "garbled, do not count" from any
  other failure.
- **The resynchronization above is not reachable from the engine as built, and
  not only because `ironfix-engine::Initiator` treats every codec error as
  fatal.** `tokio_util::Framed` terminates its stream after *any* decoder error:
  it latches an internal error flag and returns `None` on the next poll, so the
  well-formed frame the resync had just aligned onto is discarded along with the
  stream. No way of writing the caller changes that. Honouring the convention
  from the engine would require either the codec to report garbling as
  `Ok(None)` while skipping the bad bytes internally — which is itself a change
  to framing semantics — or the engine to drive `Decoder::decode` by hand
  instead of using `Framed`. The consumption policy above is therefore
  observable today only by a caller that drives the codec directly, which is how
  it is tested.

---

### Business Message Reject (MsgType = j)

**Purpose**: Reject an application-level message.

**Key Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 45 | RefSeqNum | Rejected message sequence |
| 372 | RefMsgType | Rejected message type |
| 380 | BusinessRejectReason | Reason code |
| 58 | Text | Explanation |

**Business Reject Reasons**:
| Code | Description |
|------|-------------|
| 0 | Other |
| 1 | Unknown ID |
| 2 | Unknown Security |
| 3 | Unsupported Message Type |
| 4 | Application not available |
| 5 | Conditionally required field missing |
| 6 | Not authorized |
| 7 | DeliverTo firm not available |
| 18 | Invalid price increment |

---

## Implementation Priority

### Phase 1: Core Session Layer (Required)
- [x] Logon / Logout
- [x] Heartbeat / Test Request
- [x] Reject
- [x] Sequence Reset
- [x] Resend Request

### Phase 2: Order Entry (High Priority)
- [ ] New Order Single
- [ ] Execution Report
- [ ] Order Cancel Request
- [ ] Order Cancel/Replace Request
- [ ] Order Cancel Reject
- [ ] Order Status Request

### Phase 3: Market Data (Medium Priority)
- [ ] Market Data Request
- [ ] Market Data Snapshot
- [ ] Market Data Incremental Refresh
- [ ] Market Data Request Reject

### Phase 4: Extended Order Types (Lower Priority)
- [ ] Order Mass Cancel Request/Report
- [ ] Order Mass Status Request
- [ ] List Orders (New Order List)

### Phase 5: Post-Trade (Lower Priority)
- [ ] Allocation Instruction
- [ ] Confirmation
- [ ] Position Report

---

## Version-Specific Considerations

### FIX 4.0 - 4.2
- No DefaultApplVerID
- Limited execution report fields
- Tag 20 (ExecTransType) required in Execution Reports

### FIX 4.3 - 4.4
- Enhanced execution report
- More order types supported
- Tag 150 (ExecType) replaces Tag 20

### FIX 5.0 / FIXT.1.1
- Separate transport and application layers
- DefaultApplVerID (tag 1137) in Logon
- ApplVerID (tag 1128) in application messages
- Enhanced market data support

---

## References

- [FIX Protocol Specification](https://www.fixtrading.org/standards/)
- [FIX 4.4 Specification](https://www.fixtrading.org/standards/fix-4-4/)
- [FIX 5.0 SP2 Specification](https://www.fixtrading.org/standards/fix-5-0-sp-2/)
- [FIXT 1.1 Transport](https://www.fixtrading.org/standards/fixt-1-1/)
