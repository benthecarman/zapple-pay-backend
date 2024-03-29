use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(version, author, about)]
/// A tool for zapping based on reactions to notes.
pub struct Config {
    #[clap(default_value = ".", long)]
    /// Location keys files
    pub data_dir: String,
    #[clap(long)]
    /// Postgres connection string
    pub pg_url: String,
    #[clap(short, long)]
    /// Relay to connect to, can be specified multiple times
    pub relay: Vec<String>,
    #[clap(default_value = "0.0.0.0", long)]
    /// Bind address for zapple-pay's webserver
    pub bind: String,
    #[clap(default_value_t = 3000, long)]
    /// Port for zapple-pay's webserver
    pub port: u16,
}
