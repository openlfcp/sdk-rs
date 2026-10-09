use std::time::Instant;
use automerge::ActorId;
use lfcp::shared_objects::framing;
use lfcp::shared_sections::{self, NewNode, SectionsDoc, SectionsReplica};

fn uuid(n: u32) -> String { format!("0192e4a0-0000-7000-8000-{n:012x}") }
fn main() {
    let resource = lfcp::base::ResourceId::from_bytes([0x2d; 32]);
    let p0 = lfcp::base::PrincipalId::from_bytes([0x3a; 32]);
    let actor = shared_sections::actor_id(&resource, &p0);
    let section = uuid(1);
    let (mut doc, genesis) = SectionsDoc::create(actor, &section, "S", &p0).unwrap();
    let n: u32 = std::env::args().nth(1).map(|s| s.parse().unwrap()).unwrap_or(2000);
    let mut changes = vec![genesis];
    let mut prev: Option<String> = None;
    let t = Instant::now();
    for i in 0..n {
        let id = uuid(1000 + 2 * i);
        let c = doc.create_node(&id, NewNode::Item { text: "x" }, &section, prev.as_deref(), &uuid(1001 + 2 * i), &p0).unwrap();
        changes.push(c);
        prev = Some(id);
    }
    println!("authoring {n} nodes: {:?}", t.elapsed());
    let mut replica = SectionsReplica::new(resource, ActorId::from([1u8; 32]));
    let t = Instant::now();
    let mut last = Instant::now();
    for (i, c) in changes.iter().enumerate() {
        let v = replica.receive(&p0, &framing::encode_change(c.raw_bytes()));
        assert!(!matches!(v, shared_sections::Received::Refused(_)), "{v:?}");
        if (i + 1) % (changes.len() / 5).max(1) == 0 { println!("  received {:5}: total {:?}, last block {:?}", i + 1, t.elapsed(), last.elapsed()); last = Instant::now(); }
    }
}
