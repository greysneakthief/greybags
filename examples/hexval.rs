use greybags::regf::{Hive, OpenOptions};
fn main() {
    let a: Vec<String> = std::env::args().collect();
    let hive = Hive::open(std::path::Path::new(&a[1]), &OpenOptions::default()).unwrap();
    let k = hive.open_key(&a[2]).unwrap().unwrap();
    let v = k.value(&a[3]).unwrap().unwrap();
    println!("{}", greybags::util::bytes::to_hex(&v.data().unwrap()));
}
