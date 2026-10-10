use ouro_jail::commands::Rules;
#[test]
fn probe() {
    let rules = Rules {
        deny: vec![],
        forbid: vec!["/usr/bin/echo **".to_string()],
    };
    let argv: Vec<Vec<u8>> = vec![b"t".to_vec(), b"SHOULD_NOT_PRINT".to_vec()];
    println!(
        "with image: {:?}",
        rules
            .check(Some(&argv), Some(b"/usr/bin/echo"))
            .map(|h| (h.pattern, h.forbidden))
    );
    println!(
        "claimed only: {:?}",
        rules
            .check(Some(&argv), Some(b"t"))
            .map(|h| (h.pattern, h.forbidden))
    );
    let _ = Rules::default();
}
