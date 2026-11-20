use aw_mhac::hash::expand_message_xmd;

#[test]
fn rfc9380_k1_empty_message() {
    let expected = "68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235";
    let actual = expand_message_xmd(b"", b"QUUX-V01-CS02-with-expander-SHA256-128", 32);
    let actual: String = actual.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(actual, expected);
}
