use dataonion::*;
use std::fs::File;
use std::io::Write;
fn main() -> Res<()> {
    if false {
        let input = read_input("input.txt").unwrap();
        let output = peel_all_layers2(&input);
        File::create("thecore.txt")?.write_all(&output)?;
    } else {
        peel_all_layers()?;
    }

    Ok(())
}
