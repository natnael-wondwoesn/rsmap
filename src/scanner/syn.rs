// src/scanner/syn.rs
use super::types::{PortState, ScanResult};
use super::util::build_syn_packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::tcp::TcpFlags;
use pnet::transport::tcp_packet_iter;
use pnet::transport::{transport_channel, TransportChannelType::Layer4, TransportProtocol::Ipv4};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::sync::Semaphore;

const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const GLOBAL_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CONCURRENT: usize = 100;

/// Message for the single sender task
#[derive(Debug)]
struct SendJob {
    packet: Vec<u8>,
    dst_port: u16,
    start: Instant,
}

pub async fn scan(target: IpAddr, ports: &[u16]) -> anyhow::Result<Vec<ScanResult>> {
    // --------------------------------------------------------------- //
    // 1. Validate target
    // --------------------------------------------------------------- //
    let target_ip = match target {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => return Err(anyhow::anyhow!("IPv6 not supported")),
    };

    // --------------------------------------------------------------- //
    // 2. Open raw channel (requires sudo)
    // --------------------------------------------------------------- //
    let (mut tx, mut rx) = transport_channel(4096, Layer4(Ipv4(IpNextHeaderProtocols::Tcp)))?;

    // --------------------------------------------------------------- //
    // 3. Job channel → one sender task
    // --------------------------------------------------------------- //
    let (job_tx, mut job_rx) = mpsc::channel::<SendJob>(MAX_CONCURRENT * 2);

    // --------------------------------------------------------------- //
    // 4. Single sender task (owns TransportSender)
    // --------------------------------------------------------------- //
    let sender_handle = tokio::spawn(async move {
        while let Some(job) = job_rx.recv().await {
            // Build an IPv4 packet wrapper from the raw buffer and send it.
            let mut buf = job.packet;
            if let Some(ip_pkt) = MutableIpv4Packet::new(&mut buf[..]) {
                let _ = tx.send_to(ip_pkt, target);
            }
        }
    });

    // --------------------------------------------------------------- //
    // 5. Concurrency limiter + tracking
    // --------------------------------------------------------------- //
    let sem = Arc::new(Semaphore::new(MAX_CONCURRENT));
    let mut sent = HashMap::<u16, Instant>::new();

    // --------------------------------------------------------------- //
    // 6. Launch a probe per port
    // --------------------------------------------------------------- //
    let mut probe_handles = Vec::with_capacity(ports.len());

    for &dst_port in ports {
        let permit = sem.clone().acquire_owned().await?;
        let job_tx = job_tx.clone();

        let src_port = 40000_u16.wrapping_add(dst_port % 10000);
        let packet = build_syn_packet(Ipv4Addr::UNSPECIFIED, target_ip, src_port, dst_port);
        let start = Instant::now();
        sent.insert(dst_port, start);

        let handle = tokio::spawn(async move {
            let _permit = permit;
            let job = SendJob {
                packet,
                dst_port,
                start,
            };
            let _ = job_tx.try_send(job);
            Ok::<_, anyhow::Error>(dst_port)
        });

        probe_handles.push(handle);
    }

    // --------------------------------------------------------------- //
    // 7. Wait for probes to be queued
    // --------------------------------------------------------------- //
    for h in probe_handles {
        let _ = h.await;
    }

    drop(job_tx);
    let _ = sender_handle.await;

    // --------------------------------------------------------------- //
    // 8. Receive loop with timeout (blocking reader thread + async timeouts)
    // --------------------------------------------------------------- //
    let mut result_map: HashMap<u16, ScanResult> = ports
        .iter()
        .map(|&p| (p, ScanResult::new_filtered(p)))
        .collect();

    // Channel to pass minimal events from the blocking reader to async task
    let (evt_tx, mut evt_rx) = mpsc::unbounded_channel::<(u16, u8)>();

    // Move the receiver into a blocking thread; read packets and forward (port, flags)
    std::thread::spawn(move || {
        let mut iter = tcp_packet_iter(&mut rx);
        while let Ok((tcp, _addr)) = iter.next() {
            // IMPORTANT: source port is the target’s port you probed
            let remote_port = tcp.get_source();
            let flags = tcp.get_flags();
            let _ = evt_tx.send((remote_port, flags));
        }
    });

    let deadline = Instant::now() + GLOBAL_TIMEOUT;
    while Instant::now() < deadline {
        let wait = deadline
            .saturating_duration_since(Instant::now())
            .min(PROBE_TIMEOUT);

        match tokio::time::timeout(wait, evt_rx.recv()).await {
            Ok(Some((remote_port, flags))) => {
                if let Some(&start) = sent.get(&remote_port) {
                    println!("port {remote_port} data {flags}");
                    let rtt = start.elapsed();
                    let state = if (flags & TcpFlags::SYN != 0) && (flags & TcpFlags::ACK != 0) {
                        PortState::Open
                    } else if (flags & TcpFlags::RST) != 0 {
                        PortState::Closed
                    } else {
                        PortState::Filtered
                    };

                    let result = match state {
                        PortState::Open => ScanResult::new_open(remote_port, rtt),
                        PortState::Closed => ScanResult::new_closed(remote_port),
                        PortState::Filtered => ScanResult::new_filtered(remote_port),
                        PortState::OpenFiltered => ScanResult::new_open_filterd(remote_port),
                    };
                    result_map.insert(remote_port, result);
                }
            }
            Ok(None) => break,         // reader thread ended (channel closed)
            Err(_elapsed) => continue, // per-iteration timeout; keep waiting until GLOBAL_TIMEOUT
        }
    }

    // --------------------------------------------------------------- //
    // 9. Return results in order (unchanged)
    // --------------------------------------------------------------- //

    let results: Vec<ScanResult> = ports.iter().map(|&p| result_map[&p].clone()).collect();
    Ok(results)
}
