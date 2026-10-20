use std::io::Read;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use opentunnel_server::clock::Clock;
use opentunnel_server::config::Config;
use opentunnel_server::migration::{self, ExportFile};
use opentunnel_server::server::Server;
use opentunnel_server::store::Store;

#[derive(Parser)]
#[command(
    name = "opentunnel-server",
    version,
    about = "The hosted OpenTunnel service"
)]
struct Cli {
    #[command(flatten)]
    config: Config,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the service (the default).
    Serve,
    /// Import tunnel records from an export file (`-` for stdin) into the database.
    Import {
        file: PathBuf,
        /// Overwrite records this server has changed since they were imported.
        #[arg(long)]
        force: bool,
    },
    /// Write every tunnel record to an export file (`-` for stdout).
    Export { file: PathBuf },
    /// Print a new ACME account key (a P-256 private JWK) for ACME_ACCOUNT_KEY_JWK.
    AccountKey,
}

fn database_url(config: &Config) -> Result<String> {
    config
        .database_url
        .clone()
        .filter(|url| !url.is_empty())
        .context("DATABASE_URL is not set")
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    opentunnel_server::logging::init(
        cli.config.log_format,
        cli.config.machine_id.as_deref(),
        &cli.config.region,
    );
    opentunnel_server::install_crypto_provider();
    let clock = Clock::system();
    match cli.command.unwrap_or(Command::Serve) {
        Command::Serve => {
            opentunnel_server::net::raise_fd_limit();
            let server = Server::build(cli.config.clone(), clock).await?;
            if let (Some(ca), Some(path)) = (&server.local_ca, &cli.config.local_ca_file) {
                std::fs::write(path, ca).with_context(|| format!("writing {}", path.display()))?;
                tracing::warn!(path = %path.display(), "wrote the local test CA certificate");
            }
            server.run().await
        }
        Command::Import { file, force } => {
            let text = if file.as_os_str() == "-" {
                let mut text = String::new();
                std::io::stdin().read_to_string(&mut text)?;
                text
            } else {
                std::fs::read_to_string(&file)
                    .with_context(|| format!("reading {}", file.display()))?
            };
            let export: ExportFile =
                serde_json::from_str(&text).context("reading the export file")?;
            let store = Store::open(&database_url(&cli.config)?).await?;
            let domain = cli.config.domain.to_ascii_lowercase();
            let mut summary = migration::import(&store, &clock, &domain, export, force).await?;
            summary.ids.clear();
            println!("{}", serde_json::to_string_pretty(&summary)?);
            eprintln!(
                "a running server picks up imported records within a minute; POST /api/admin/import applies them at once"
            );
            Ok(())
        }
        Command::Export { file } => {
            let store = Store::open(&database_url(&cli.config)?).await?;
            let mut out: Box<dyn std::io::Write> = if file.as_os_str() == "-" {
                Box::new(std::io::stdout())
            } else {
                Box::new(std::io::BufWriter::new(
                    std::fs::File::create(&file)
                        .with_context(|| format!("creating {}", file.display()))?,
                ))
            };
            let mut chunks = migration::export(store, clock, migration::EXPORT_PAGE);
            while let Some(chunk) = chunks.recv().await {
                out.write_all(&chunk?)?;
            }
            out.flush()?;
            Ok(())
        }
        Command::AccountKey => {
            println!("{}", opentunnel_server::acme::generate_account_jwk()?);
            Ok(())
        }
    }
}
