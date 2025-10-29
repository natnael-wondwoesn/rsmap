mod cli;
mod llm;
mod output;
mod scanner;
mod utils;
// mod config;

// use llm::Explainer;
// use output::OutputFormat;
// use scanner::Scanner;

#[tokio::main]
async fn main() -> anyhow::Result<T> {
    let args = Args::parse();
}
