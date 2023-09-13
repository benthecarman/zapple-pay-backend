use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(version, author, about)]
/// A tool for zapping based on reactions to notes.
pub struct Config {
    #[clap(default_value_t = String::from("."), long)]
    /// Location keys files
    pub data_dir: String,
    #[clap(long)]
    /// Postgres connection string
    pub pg_url: String,
    #[clap(default_value_t = String::from("0.0.0.0"), long)]
    /// Bind address for zap-tunnel's webserver
    pub bind: String,
    #[clap(default_value_t = 3000, long)]
    /// Port for zap-tunnel's webserver
    pub port: u16,
}
