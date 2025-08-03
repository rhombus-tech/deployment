use criterion::criterion_main;

// Import the benchmark groups from the main benchmarks module
use pcd::benchmarks::benches;

// This is the entry point for Criterion benchmarks
criterion_main!(benches);
