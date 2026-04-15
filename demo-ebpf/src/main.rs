#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;
use core::mem;
use demo_common::BackendPorts;

mod bindings;
use bindings::{ethhdr, iphdr, udphdr};

const IPPROTO_UDP: u8 = 0x0011;
const ETH_P_IP: u16 = 0x0800;
const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();
const IP_HDR_LEN: usize = mem::size_of::<iphdr>();

#[map(name = "BACKEND_PORTS")]
static mut BACKEND_PORTS: HashMap<u16, BackendPorts> =
    HashMap::<u16, BackendPorts>::with_max_entries(10, 0);

#[xdp]
pub fn demo(ctx: XdpContext) -> u32 {
    match try_demo(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_demo(ctx: XdpContext) -> Result<u32, u32> {
    info!(&ctx, "received a packet");

    let eth = ptr_at::<ethhdr>(&ctx, 0).ok_or(xdp_action::XDP_PASS)?;

    if unsafe { u16::from_be((*eth).h_proto) } != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip = ptr_at::<iphdr>(&ctx, ETH_HDR_LEN).ok_or(xdp_action::XDP_PASS)?;

    if unsafe { (*ip).protocol } != IPPROTO_UDP {
        return Ok(xdp_action::XDP_PASS);
    }

    info!(&ctx, "received a UDP packet");

    let udp = ptr_at_mut::<udphdr>(&ctx, ETH_HDR_LEN + IP_HDR_LEN).ok_or(xdp_action::XDP_PASS)?;

    let destination_port = unsafe { u16::from_be((*udp).dest) };

    let backends = match unsafe { BACKEND_PORTS.get(&destination_port) } {
        Some(backends) => {
            info!(&ctx, "FOUND backends for port");
            backends
        }
        None => {
            info!(&ctx, "NO backends found for this port");
            return Ok(xdp_action::XDP_PASS);
        }
    };

    // IMPORTANT: `backends` is a map value pointer. The verifier is extremely picky about
    // "pointer + variable offset" accesses into map values, even when Rust seems to bound-check.
    // To keep the verifier happy, only perform constant-offset reads from the map value and then
    // use `match` (no variable indexing) for selection.
    let p0 = backends.ports[0];
    let p1 = backends.ports[1];
    let p2 = backends.ports[2];
    let p3 = backends.ports[3];

    let current_index = backends.index;
    let new_destination_port = match current_index {
        0 => p0,
        1 => p1,
        2 => p2,
        3 => p3,
        _ => return Ok(xdp_action::XDP_ABORTED),
    };
    unsafe { (*udp).dest = u16::from_be(new_destination_port) };

    info!(
        &ctx,
        "redirected port {} to {}", destination_port, new_destination_port
    );

    let mut next_index = match current_index {
        0 => 1,
        1 => 2,
        2 => 3,
        3 => 0,
        _ => 0,
    };
    let next_port = match next_index {
        0 => p0,
        1 => p1,
        2 => p2,
        _ => p3,
    };
    if next_port == 0 {
        next_index = 0;
    }

    let new_backends = BackendPorts {
        ports: [p0, p1, p2, p3],
        index: next_index,
    };

    match unsafe { BACKEND_PORTS.insert(&destination_port, &new_backends, 0) } {
        Ok(_) => {
            info!(&ctx, "index updated for port {}", destination_port);
            Ok(xdp_action::XDP_PASS)
        }
        Err(err) => {
            info!(&ctx, "error inserting index update: {}", err);
            Ok(xdp_action::XDP_ABORTED)
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Option<*const T> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return None;
    }

    Some((start + offset) as *const T)
}

#[inline(always)]
fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Option<*mut T> {
    let ptr = ptr_at::<T>(ctx, offset)?;
    Some(ptr as *mut T)
}
