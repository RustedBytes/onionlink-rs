use std::env;
use std::io::{Read, Write};

use log::info;
use onionlink_core::{
    base64_encode_unpadded, build_simple_http_get, connect_onion_service_with_retries,
    derive_hs_period_keys, fetch_hidden_service_descriptor, from_string, hydrate_microdescriptors,
    load_consensus, parse_hostport, parse_onion_address, Bytes, Options, Result,
};

fn usage() {
    eprintln!(
        "usage: onionlink <service.onion> <port> [options]\n\
options:\n  \
--bootstrap host:port      HTTP directory cache (default 128.31.0.39:9131)\n  \
--consensus-file path      use a local consensus-microdesc file\n  \
--timeout-ms n             network timeout (default 30000)\n  \
--http-get [path]          send a simple HTTP/1.0 GET after connecting\n  \
--send text                send raw text after connecting\n  \
--stdin                    send standard input after connecting\n  \
--verbose                  print progress"
    );
}

fn parse_args(args: &[String]) -> Result<Options> {
    if args.get(1).is_some_and(|a| a == "--help" || a == "-h") {
        usage();
        std::process::exit(0);
    }
    if args.len() < 3 {
        usage();
        std::process::exit(2);
    }
    let mut opt = Options {
        onion: args[1].clone(),
        port: args[2].parse()?,
        ..Options::default()
    };
    let mut i = 3usize;
    while i < args.len() {
        let a = &args[i];
        let need_value = |name: &str, i: &mut usize| -> Result<String> {
            if *i + 1 >= args.len() {
                return onionlink_core::err(format!("{name} requires a value"));
            }
            *i += 1;
            Ok(args[*i].clone())
        };
        match a.as_str() {
            "--bootstrap" => opt.bootstrap = parse_hostport(&need_value(a, &mut i)?, 0)?,
            "--consensus-file" => opt.consensus_file = need_value(a, &mut i)?,
            "--timeout-ms" => opt.timeout_ms = need_value(a, &mut i)?.parse()?,
            "--http-get" => {
                if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                    i += 1;
                    opt.http_get = args[i].clone();
                } else {
                    opt.http_get = "/".to_string();
                }
            }
            "--send" => opt.send_text = need_value(a, &mut i)?,
            "--stdin" => opt.stdin_mode = true,
            "--verbose" => opt.verbose = true,
            "--help" | "-h" => {
                usage();
                std::process::exit(0);
            }
            _ => return onionlink_core::err(format!("unknown option: {a}")),
        }
        i += 1;
    }
    if opt.http_get.is_empty() && opt.send_text.is_empty() && !opt.stdin_mode {
        opt.http_get = "/".to_string();
    }
    Ok(opt)
}

fn read_stdin_all() -> Result<Bytes> {
    let mut out = Vec::new();
    std::io::stdin().read_to_end(&mut out)?;
    Ok(out)
}

fn init_logging(verbose: bool) {
    let default_filter = if verbose { "info" } else { "warn" };
    let env = env_logger::Env::default().filter_or("RUST_LOG", default_filter);
    env_logger::Builder::from_env(env)
        .format_timestamp_secs()
        .format_target(false)
        .init();
}

fn run() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let opt = parse_args(&args)?;
    init_logging(opt.verbose);
    info!("starting onionlink request for {}:{}", opt.onion, opt.port);
    let onion = parse_onion_address(&opt.onion)?;
    let mut consensus = load_consensus(&opt)?;
    let keys = derive_hs_period_keys(&consensus, &onion)?;
    info!(
        "derived blinded key {} for period {}",
        base64_encode_unpadded(&keys.blinded),
        keys.period_num
    );
    hydrate_microdescriptors(&mut consensus, &opt.bootstrap, opt.timeout_ms, opt.verbose)?;
    let desc = fetch_hidden_service_descriptor(&consensus, &keys, opt.timeout_ms, opt.verbose)?;
    let mut stream = connect_onion_service_with_retries(
        &opt,
        &consensus,
        &desc.descriptor,
        &keys,
        &[desc.guard],
    )?;
    const STREAM_ID: u16 = 1;
    info!("opening onion service stream to port {}", opt.port);
    stream.begin(STREAM_ID, opt.port)?;
    let mut outbound = Bytes::new();
    if !opt.http_get.is_empty() {
        outbound.extend_from_slice(&build_simple_http_get(&opt.onion, &opt.http_get));
    }
    if !opt.send_text.is_empty() {
        outbound.extend_from_slice(&from_string(&opt.send_text));
    }
    if opt.stdin_mode {
        outbound.extend_from_slice(&read_stdin_all()?);
    }
    if !outbound.is_empty() {
        info!("sending {} outbound bytes", outbound.len());
        stream.send_data(STREAM_ID, &outbound)?;
    }
    let inbound = stream.read_until_end(STREAM_ID, 4 * 1024 * 1024)?;
    info!("received {} inbound bytes", inbound.len());
    std::io::stdout().write_all(&inbound)?;
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn parse_args_defaults_to_http_get_root() {
        let opt = parse_args(&args(&["onionlink", "service.onion", "80"])).unwrap();
        assert_eq!(opt.onion, "service.onion");
        assert_eq!(opt.port, 80);
        assert_eq!(opt.http_get, "/");
        assert!(!opt.stdin_mode);
    }

    #[test]
    fn parse_args_preserves_send_and_stdin_modes() {
        let opt = parse_args(&args(&[
            "onionlink",
            "service.onion",
            "1234",
            "--bootstrap",
            "127.0.0.1:7000",
            "--timeout-ms",
            "2500",
            "--send",
            "hello",
            "--stdin",
            "--verbose",
        ]))
        .unwrap();
        assert_eq!(opt.bootstrap.host, "127.0.0.1");
        assert_eq!(opt.bootstrap.port, 7000);
        assert_eq!(opt.timeout_ms, 2500);
        assert_eq!(opt.send_text, "hello");
        assert!(opt.stdin_mode);
        assert!(opt.verbose);
    }
}
