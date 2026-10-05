//! LFCP-TEST-VECTORS-01 Have Vectors through the anti-entropy structures:
//! DATA_HAVE_with_hole, RESOURCE_OPEN / RESOURCE_OPENED, the SNAPSHOT-01/02
//! frontiers, and the DATA_GET / DATA_BATCH and CONTROL_GET exchanges.
//!
//! Only pairings the vectors state are asserted as pairings: a correlation
//! ID, or a case title such as "answering DATA_GET". Checks that combine
//! cases the vectors do not pair are labelled as derived. Every assertion
//! names its case.

mod support;

use lfcp::base::PrincipalId;
use lfcp::cbor;
use lfcp::wire::frontier::Frontier;
use lfcp::wire::have::{control_sync, difference, missing_after, ControlSync, HaveVector};
use lfcp::wire::message::{Body, DataRange, DecodeOptions, Message};
use support::vectors::{hex, Suite};

fn message(suite: &Suite, case_id: &str) -> Message {
    Message::decode(
        &hex(case_id, &suite.case(case_id)["expected"]["message_cbor"]),
        &DecodeOptions::default(),
    )
    .unwrap_or_else(|err| panic!("{case_id}: decode failed: {err}"))
}

fn principal(suite: &Suite, name: &str) -> PrincipalId {
    *suite.principals()[name].descriptor().id()
}

#[test]
fn data_have_with_hole() {
    let suite = Suite::load();
    let case_id = "DATA_HAVE_with_hole";
    let original = message(&suite, case_id);
    let Body::DataHave { have, .. } = &original.body else {
        panic!("{case_id}: not a DATA_HAVE")
    };
    let vector = HaveVector::from_wire(have).unwrap();
    let bob = principal(&suite, "BOB");
    for (seq, held) in [
        (1, true),
        (100, true),
        (101, false),
        (104, false),
        (105, true),
        (107, true),
        (108, false),
    ] {
        assert_eq!(vector.contains(&bob, seq), held, "{case_id}: BOB {seq}");
    }
    // Already normalized: our emitter reproduces the message byte for byte.
    assert_eq!(&vector.to_wire(), have, "{case_id}: normalized form");
    let mut rebuilt = original.clone();
    if let Body::DataHave { have, .. } = &mut rebuilt.body {
        *have = vector.to_wire();
    }
    assert_eq!(rebuilt.encode(), original.encode(), "{case_id}: re-encode");
    // The hole is exactly 101..104 against a peer holding 1..107.
    let mut full = HaveVector::new();
    full.insert_ranges(&[DataRange {
        principal: bob,
        start: 1,
        end: 107,
    }])
    .unwrap();
    assert_eq!(
        difference(&vector, &full).request,
        vec![DataRange {
            principal: bob,
            start: 101,
            end: 104
        }],
        "{case_id}: hole"
    );
}

#[test]
fn resource_open_and_opened() {
    let suite = Suite::load();
    let (open, opened) = (
        message(&suite, "RESOURCE_OPEN"),
        message(&suite, "RESOURCE_OPENED"),
    );
    // Stated pairing: RESOURCE_OPENED correlates to RESOURCE_OPEN.
    assert_eq!(
        opened.correlation_id,
        Some(open.message_id),
        "RESOURCE_OPENED: correlation"
    );
    let Body::ResourceOpen {
        have: client_have,
        control_heads: client_heads,
        ..
    } = &open.body
    else {
        panic!("RESOURCE_OPEN: wrong body")
    };
    let Body::ResourceOpened {
        have: server_have,
        control_heads: server_heads,
        snapshot,
        ..
    } = &opened.body
    else {
        panic!("RESOURCE_OPENED: wrong body")
    };
    let client = HaveVector::from_wire(client_have).unwrap();
    let server = HaveVector::from_wire(server_have).unwrap();
    assert_eq!(
        &client.to_wire(),
        client_have,
        "RESOURCE_OPEN: normalized form"
    );
    assert_eq!(
        &server.to_wire(),
        server_have,
        "RESOURCE_OPENED: normalized form"
    );

    // The client asks for what the server announced and it lacks.
    let carol = principal(&suite, "CAROL");
    let diff = difference(&client, &server);
    assert_eq!(
        diff.request,
        vec![DataRange {
            principal: carol,
            start: 1,
            end: 1
        }],
        "RESOURCE_OPENED: request"
    );
    assert!(diff.offer.is_empty(), "RESOURCE_OPENED: offer");

    // One head, the same on both sides: the Control Plane is up to date.
    assert_eq!(
        control_sync(client_heads.first().copied(), server_heads),
        ControlSync::UpToDate,
        "RESOURCE_OPENED: control"
    );

    // Stated: the summary is SNAPSHOT-01, whose frontier covers everything
    // the server announced, so nothing is missing after loading it.
    let summary = snapshot
        .as_ref()
        .expect("RESOURCE_OPENED: snapshot summary");
    assert_eq!(
        summary.snapshot_id.as_bytes().as_slice(),
        hex(
            "SNAPSHOT-01",
            &suite.case("SNAPSHOT-01")["expected"]["snapshot_id"]
        ),
        "RESOURCE_OPENED: summary is SNAPSHOT-01"
    );
    let summary_frontier = HaveVector::from_wire(&summary.frontier)
        .unwrap()
        .to_frontier();
    assert_eq!(
        cbor::encode(&summary_frontier.to_value()).unwrap(),
        hex(
            "SNAPSHOT-01",
            &suite.case("SNAPSHOT-01")["expected"]["frontier_cbor"]
        ),
        "RESOURCE_OPENED: summary frontier"
    );
    assert!(
        missing_after(&summary_frontier, &HaveVector::new(), &server).is_empty(),
        "RESOURCE_OPENED: catch-up after SNAPSHOT-01"
    );
}

#[test]
fn snapshot_frontiers_round_trip() {
    let suite = Suite::load();
    for case_id in ["SNAPSHOT-01", "SNAPSHOT-02"] {
        let bytes = hex(case_id, &suite.case(case_id)["expected"]["frontier_cbor"]);
        let frontier = Frontier::from_value(&cbor::decode_strict(&bytes).unwrap()).unwrap();
        let vector = HaveVector::from_frontier(&frontier);
        assert_eq!(vector.to_frontier(), frontier, "{case_id}: frontier");
        assert_eq!(
            cbor::encode(&vector.to_frontier().to_value()).unwrap(),
            bytes,
            "{case_id}: bytes"
        );
        for entry in vector.to_wire() {
            entry
                .canonical()
                .unwrap_or_else(|e| panic!("{case_id}: {e}"));
        }
    }
}

#[test]
fn data_batch_answers_data_get_and_repeats_are_no_ops() {
    let suite = Suite::load();
    let (get, batch) = (message(&suite, "DATA_GET"), message(&suite, "DATA_BATCH"));
    // Stated pairing: DATA_BATCH answers DATA_GET.
    assert_eq!(
        batch.correlation_id,
        Some(get.message_id),
        "DATA_BATCH: correlation"
    );
    let Body::DataGet { ranges, .. } = &get.body else {
        panic!("DATA_GET: wrong body")
    };

    // Inserting the answered units covers exactly the requested ranges.
    let mut received = HaveVector::new();
    for unit in batch.body.units().expect("DATA_BATCH: units") {
        let header = unit.expect("DATA_BATCH: unit parses").header().clone();
        assert!(
            received.insert(&header.actor, header.sequence).unwrap(),
            "DATA_BATCH: new unit"
        );
    }
    let mut requested = HaveVector::new();
    requested.insert_ranges(ranges).unwrap();
    assert_eq!(received, requested, "DATA_BATCH: covers DATA_GET");
    assert!(
        difference(&received, &requested).request.is_empty(),
        "DATA_BATCH: nothing left"
    );

    // Delivering the batch again changes nothing (§70).
    let before = received.clone();
    for unit in batch.body.units().unwrap() {
        let header = unit.unwrap().header().clone();
        assert!(
            !received.insert(&header.actor, header.sequence).unwrap(),
            "DATA_BATCH: duplicate"
        );
    }
    assert_eq!(received, before, "DATA_BATCH: idempotent");
}

#[test]
fn d1_to_d4_holdings() {
    // Derived (no vector pairs these): holdings built from D1–D4 against
    // the server's RESOURCE_OPENED Have. D3 is past the C6 cutoff, so the
    // server does not announce it.
    let suite = Suite::load();
    let mut ours = HaveVector::new();
    for case_id in [
        "D1_bob_epoch0_seq1",
        "D2_bob_epoch0_seq2",
        "D3_bob_epoch0_seq3_stale",
        "D4_carol_epoch1_seq1",
    ] {
        let bytes = hex(case_id, &suite.case(case_id)["expected"]["cose_sign1"]);
        let header = lfcp::wire::data_unit::ReceivedDataUnit::parse(&bytes)
            .unwrap()
            .header()
            .clone();
        ours.insert(&header.actor, header.sequence).unwrap();
    }
    let Body::ResourceOpened { have, .. } = message(&suite, "RESOURCE_OPENED").body else {
        panic!("RESOURCE_OPENED: wrong body")
    };
    let server = HaveVector::from_wire(&have).unwrap();
    let diff = difference(&ours, &server);
    assert!(diff.request.is_empty(), "D1-D4: nothing to request");
    let bob = principal(&suite, "BOB");
    assert_eq!(
        diff.offer,
        vec![DataRange {
            principal: bob,
            start: 3,
            end: 3
        }],
        "D1-D4: D3 to offer"
    );
}

#[test]
fn control_get_follows_control_have() {
    // Derived (CONTROL_HAVE and CONTROL_GET are not correlated): a replica
    // with no records that sees CONTROL_HAVE asks for exactly CONTROL_GET.
    let suite = Suite::load();
    let Body::ControlHave { control_heads, .. } = message(&suite, "CONTROL_HAVE").body else {
        panic!("CONTROL_HAVE: wrong body")
    };
    let Body::ControlGet { start, end, .. } = message(&suite, "CONTROL_GET").body else {
        panic!("CONTROL_GET: wrong body")
    };
    assert_eq!(
        control_sync(None, &control_heads),
        ControlSync::Fetch { start, end },
        "CONTROL_GET"
    );

    // Stated: CONTROL_BATCH answers CONTROL_GET with records start..=end.
    let batch = message(&suite, "CONTROL_BATCH");
    let records = batch.body.control_records().unwrap();
    let sequences: Vec<u64> = records
        .into_iter()
        .map(|r| r.unwrap().header().sequence)
        .collect();
    assert_eq!(
        sequences,
        (start..=end).collect::<Vec<_>>(),
        "CONTROL_BATCH: sequences"
    );
}
