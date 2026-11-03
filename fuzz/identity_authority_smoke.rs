//! Dependency-free driver for the same stateful assertions as libFuzzer.
#[path = "src/identity_authority.rs"]
mod identity_authority;

fn main() {
    let seeds = identity_authority::seeds();
    let mut runs = 0;
    for seed in seeds {
        identity_authority::check(&seed);
        runs += 1;
        for i in 0..seed.len() {
            // A byte mutation in a program still gets freshly signed records.
            let mut changed = seed.clone();
            changed[i] ^= 0xff;
            identity_authority::check(&changed);
            runs += 1;
        }
    }
    let mut random = 0x404u64;
    for _ in 0..96 {
        let mut program = vec![3];
        for _ in 0..8 * 16 {
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            program.push(random as u8);
        }
        identity_authority::check(&program);
        runs += 1;
    }
    println!("{runs} stateful identity programs/raw mutations passed");
}
