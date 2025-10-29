// // src/main.rs
mod scanner;
// ... other mods

use scanner::Scanner;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let target = "192.168.1.1".parse()?;
    let ports = vec![80, 443, 22];

    let scanner = Scanner::new(target, ports);
    let results = scanner.run().await?;

    for result in results {
        println!(
            "{}/tcp {:10} {}",
            result.port, result.state, result.service.name
        );
    }

    Ok(())
}
