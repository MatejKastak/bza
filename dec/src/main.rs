const XOR_KEYS: [u8; 0x10] = [
    0x42, 0x42, 0x32, 0x46, 0x41, 0x33, 0x36, 0x41, 0x41, 0x41, 0x39, 0x35, 0x34, 0x31, 0x46, 0x30,
];

fn decode(data: &str) -> String {
    let res_size = data.len();
    let mut res = String::with_capacity(res_size);
    for (i, d) in data.bytes().enumerate() {
        let decoded = d ^ XOR_KEYS[i % 0x10];
        res.push(decoded as char);
    }
    res
}

fn main() {
    let encoded = vec![
        "m7A4nQ_/nA".to_string(),
        "m [(n3".to_string(),
        "m6_6n3".to_string(),
        "m4S4nAC/n&ZV\x1aA/TB".to_string(),
        "m.[$n__#4%\\C\x1aB)0".to_string(),
        "m.[$n3".to_string(),
        // "*6F6{\x1c\x19  \x17QGP,\x02#l]4&\x1cU./\'PR\x1aC\'BB:TqoPY,{y\t\r\x04M1Gl&\\55VZ-2oZZY\\v~".to_string(),
        "m4S4nAC/nA".to_string(),
        "55\x1c!;PP3t AS\x02\x1f%_/x\nvy\x03J66o^OWW4\x05#:TqoPY,{y\t\r\x04M1Gl&\\55VZ-2oZZY\\v~"
            .to_string(),
    ];

    for enc in encoded.into_iter() {
        println!("{:30} -> {}", enc, decode(&enc));
    }
}
