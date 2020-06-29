use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dataonion::*;

pub fn criterion_benchmark(c: &mut Criterion) {
    let input5 = read_input("input5.txt").unwrap();
    let input4 = read_input("input4.txt").unwrap();
    let input3 = read_input("input3.txt").unwrap();
    let input2 = read_input("input2.txt").unwrap();
    let input1 = read_input("input1.txt").unwrap();
    let input = read_input("input.txt").unwrap();
    c.bench_function("peeling all layers", |b| {
        b.iter(|| black_box(peel_all_layers2(&input)))
    });
    // c.bench_function("raw peeling layer 5", |b| {
    //     b.iter(|| black_box(only_peel_layer5(&input5)))
    // });
    // c.bench_function("raw peeling layer 4", |b| {
    //     b.iter(|| black_box(only_peel_layer4(&input4)))
    // });
    // c.bench_function("raw peeling layer 3", |b| {
    //     b.iter(|| black_box(only_peel_layer3(&input3)))
    // });
    // c.bench_function("raw peeling layer 2", |b| {
    // b.iter(|| black_box(only_peel_layer2(&input2)))
    // });
    // c.bench_function("raw peeling layer 1", |b| {
    //     b.iter(|| black_box(only_peel_layer1(&input1)))
    // });
    // c.bench_function("raw peeling layer 0", |b| {
    //     b.iter(|| black_box(ascii85_decode(&input)))
    // });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
