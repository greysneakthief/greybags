fn main() {
    std::fs::write(
        std::env::args().nth(1).unwrap(),
        greybags::demo::demo_usrclass(),
    )
    .unwrap();
}
