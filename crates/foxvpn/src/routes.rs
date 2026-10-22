//! Route planning.
//!
//! Tunnel routes go into a dedicated policy-routing table. The SSH server, and
//! any jump host or SOCKS proxy, get a more specific route through the original
//! gateway so the tunnel cannot swallow its own transport.

use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

use crate::config::{Profile, RoutingMode};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultRoute {
    pub gateway: Ipv4Addr,
    pub device: String,
}

#[derive(Debug, Clone)]
pub struct RoutePlan {
    pub full_tunnel: bool,
    pub install: Vec<Ipv4Net>,
    pub bypass: Vec<Ipv4Addr>,
    pub exclude_lan: bool,
    pub gateway: Ipv4Addr,
    pub gateway_dev: String,
    pub ipv6_blackhole: bool,
    pub kill_switch: bool,
    pub ssh_port: u16,
}

pub fn parse_default_route(text: &str) -> Option<DefaultRoute> {
    for line in text.lines() {
        let line = line.trim();
        if !line.starts_with("default") {
            continue;
        }
        let mut gateway = None;
        let mut device = None;
        let parts: Vec<&str> = line.split_whitespace().collect();
        let mut i = 0;
        while i + 1 < parts.len() {
            match parts[i] {
                "via" => gateway = parts[i + 1].parse().ok(),
                "dev" => device = Some(parts[i + 1].to_string()),
                _ => {}
            }
            i += 1;
        }
        if let (Some(gateway), Some(device)) = (gateway, device) {
            return Some(DefaultRoute { gateway, device });
        }
    }
    None
}

pub fn parse_remote_routes(text: &str) -> Vec<Ipv4Net> {
    let mut out = Vec::new();
    for line in text.lines() {
        let Some(token) = line.split_whitespace().next() else {
            continue;
        };
        if token == "default" || !token.contains('/') {
            continue;
        }
        let Ok(net) = token.parse::<Ipv4Net>() else {
            continue;
        };
        if usable_auto_net(net) {
            out.push(net);
        }
        if out.len() == 256 {
            break;
        }
    }
    out
}

fn usable_auto_net(net: Ipv4Net) -> bool {
    let ip = net.addr();
    if net.prefix_len() == 0 || ip.is_unspecified() || ip.is_loopback() || ip.is_link_local() || ip.is_multicast() || ip.is_broadcast() {
        return false;
    }
    // Skip the tunnel's own range if a remote helper reports it.
    if net.contains(&Ipv4Addr::new(10, 77, 0, 0)) && net.prefix_len() <= 24 {
        return false;
    }
    true
}

pub fn lan_exclusions() -> Vec<Ipv4Net> {
    ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"]
        .into_iter()
        .map(|s| s.parse().unwrap())
        .collect()
}

pub fn plan_routes(
    profile: &Profile,
    default: &DefaultRoute,
    server_addrs: &[Ipv4Addr],
    extra_bypass: &[Ipv4Addr],
    remote_routes: &[Ipv4Net],
) -> Result<RoutePlan, String> {
    if server_addrs.is_empty() {
        return Err("the SSH server did not resolve to an IPv4 address".into());
    }
    let mut install = Vec::new();
    match profile.routing_mode {
        RoutingMode::FullTunnel => {
            if profile.ipv4 {
                install.push("0.0.0.0/0".parse().unwrap());
            }
        }
        RoutingMode::SplitTunnel => {
            for route in &profile.split_routes {
                let net: ipnet::IpNet = route.parse().map_err(|_| format!("bad route {route}"))?;
                if let ipnet::IpNet::V4(v4) = net {
                    install.push(v4);
                }
            }
            if profile.auto_networks {
                install.extend(remote_routes.iter().copied());
            }
            if install.is_empty() {
                return Err("split tunnel produced no IPv4 routes".into());
            }
        }
    }
    let mut bypass = Vec::new();
    for addr in server_addrs.iter().chain(extra_bypass.iter()) {
        if !bypass.contains(addr) {
            bypass.push(*addr);
        }
    }
    Ok(RoutePlan {
        full_tunnel: matches!(profile.routing_mode, RoutingMode::FullTunnel),
        install,
        bypass,
        exclude_lan: profile.exclude_lan,
        gateway: default.gateway,
        gateway_dev: default.device.clone(),
        ipv6_blackhole: !profile.ipv6,
        kill_switch: profile.kill_switch,
        ssh_port: profile.port,
    })
}

/// Linux commands that install `plan` and the commands that undo them.
/// Commands are argument vectors. Nothing is passed through a shell.
pub fn linux_commands(plan: &RoutePlan, tun: &str, table: u32, mark: u32) -> (Vec<Vec<String>>, Vec<Vec<String>>) {
    let ip = tool("ip");
    let mut apply = Vec::new();

    let rule_mark = vec![
        ip.clone(),
        "rule".into(),
        "add".into(),
        "fwmark".into(),
        format!("0x{mark:x}"),
        "lookup".into(),
        "main".into(),
        "priority".into(),
        "50".into(),
    ];
    let rule_table = vec![
        ip.clone(),
        "rule".into(),
        "add".into(),
        "lookup".into(),
        table.to_string(),
        "priority".into(),
        "100".into(),
    ];
    apply.push(rule_mark.clone());
    apply.push(rule_table.clone());

    let gw = plan.gateway.to_string();
    let dev = plan.gateway_dev.clone();
    // The original gateway must be reachable from the tunnel table before any
    // `via` route can use it.
    let gw_link = vec![
        ip.clone(),
        "route".into(),
        "add".into(),
        format!("{gw}/32"),
        "dev".into(),
        dev.clone(),
        "table".into(),
        table.to_string(),
    ];
    apply.push(gw_link);

    for addr in &plan.bypass {
        let route = vec![
            ip.clone(),
            "route".into(),
            "add".into(),
            format!("{addr}/32"),
            "via".into(),
            gw.clone(),
            "dev".into(),
            dev.clone(),
            "table".into(),
            table.to_string(),
        ];
        apply.push(route);
    }
    if plan.exclude_lan {
        for net in lan_exclusions() {
            apply.push(vec![
                ip.clone(),
                "route".into(),
                "add".into(),
                net.to_string(),
                "via".into(),
                gw.clone(),
                "dev".into(),
                dev.clone(),
                "table".into(),
                table.to_string(),
            ]);
        }
    }
    for net in &plan.install {
        let mut route = vec![
            ip.clone(),
            "route".into(),
            "add".into(),
            net.to_string(),
            "dev".into(),
            tun.to_string(),
            "table".into(),
            table.to_string(),
        ];
        if net.prefix_len() == 0 {
            route.push("src".into());
            route.push(crate::TUN_ADDR.into());
        }
        apply.push(route);
    }
    let mut blackhole_del = None;
    if plan.ipv6_blackhole {
        let blackhole = vec![
            ip.clone(),
            "-6".into(),
            "route".into(),
            "add".into(),
            "blackhole".into(),
            "::/0".into(),
            "metric".into(),
            "15".into(),
        ];
        apply.push(blackhole.clone());
        blackhole_del = Some(replace_arg(&blackhole, "add", "del"));
    }
    if plan.kill_switch {
        let nft = tool("nft");
        let script = kill_switch_script(tun, mark, &plan.bypass, plan.ssh_port);
        apply.push(vec![nft, "-f".into(), "-".into(), script]);
    }

    // Restore drops tunnel routes before the kill switch, so traffic cannot
    // leak out the physical interface during teardown.
    let mut restore = vec![vec![
        ip.clone(),
        "route".into(),
        "flush".into(),
        "table".into(),
        table.to_string(),
    ]];
    restore.push(replace_arg(&rule_table, "add", "del"));
    restore.push(replace_arg(&rule_mark, "add", "del"));
    if let Some(cmd) = blackhole_del {
        restore.push(cmd);
    }
    if plan.kill_switch {
        restore.push(vec![
            tool("nft"),
            "delete".into(),
            "table".into(),
            "inet".into(),
            "foxvpn".into(),
        ]);
    }
    (apply, restore)
}

fn replace_arg(cmd: &[String], from: &str, to: &str) -> Vec<String> {
    cmd.iter().map(|s| if s == from { to.to_string() } else { s.clone() }).collect()
}

pub fn kill_switch_script(tun: &str, mark: u32, bypass: &[Ipv4Addr], port: u16) -> String {
    let mut rules = String::new();
    for addr in bypass {
        rules.push_str(&format!("        ip daddr {addr} tcp dport {port} accept\n"));
    }
    format!(
        r#"table inet foxvpn
delete table inet foxvpn
table inet foxvpn {{
    chain output {{
        type filter hook output priority -100; policy accept;
        oifname "{tun}" accept
        oifname "lo" accept
        meta mark {mark} accept
{rules}        counter drop
    }}
}}
"#
    )
}

pub(crate) fn tool(name: &str) -> String {
    for dir in ["/usr/sbin", "/sbin", "/usr/bin", "/bin"] {
        let path = format!("{dir}/{name}");
        if std::path::Path::new(&path).exists() {
            return path;
        }
    }
    name.to_string()
}

pub fn windows_route_commands(plan: &RoutePlan, tun_peer: &str) -> (Vec<Vec<String>>, Vec<Vec<String>>) {
    let mut apply = Vec::new();
    let mut restore = Vec::new();
    for addr in &plan.bypass {
        let add = vec![
            "route".into(),
            "ADD".into(),
            addr.to_string(),
            "MASK".into(),
            "255.255.255.255".into(),
            plan.gateway.to_string(),
            "METRIC".into(),
            "1".into(),
        ];
        apply.push(add.clone());
        restore.push(vec!["route".into(), "DELETE".into(), addr.to_string()]);
    }
    if plan.full_tunnel {
        let add = vec![
            "route".into(),
            "ADD".into(),
            "0.0.0.0".into(),
            "MASK".into(),
            "0.0.0.0".into(),
            tun_peer.into(),
            "METRIC".into(),
            "1".into(),
        ];
        apply.push(add);
        restore.push(vec![
            "route".into(),
            "DELETE".into(),
            "0.0.0.0".into(),
            "MASK".into(),
            "0.0.0.0".into(),
            tun_peer.into(),
        ]);
    } else {
        for net in &plan.install {
            let add = vec![
                "route".into(),
                "ADD".into(),
                net.addr().to_string(),
                "MASK".into(),
                net.netmask().to_string(),
                tun_peer.into(),
                "METRIC".into(),
                "1".into(),
            ];
            apply.push(add);
            restore.push(vec!["route".into(), "DELETE".into(), net.addr().to_string()]);
        }
    }
    (apply, restore)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Profile;

    #[test]
    fn parses_ip_route_default() {
        let text = "default via 192.168.1.1 dev wlp2s0 proto dhcp src 192.168.1.20 metric 600\n";
        let route = parse_default_route(text).unwrap();
        assert_eq!(route.gateway, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(route.device, "wlp2s0");
    }

    #[test]
    fn auto_nets_skip_default_and_loopback() {
        let text = "\
default via 10.0.0.1 dev eth0
10.8.0.0/24 dev eth1 proto kernel scope link
127.0.0.0/8 dev lo
1.2.3.4 via 10.0.0.1 dev eth0
not a route
";
        let nets = parse_remote_routes(text);
        assert_eq!(nets.len(), 1);
        assert_eq!(nets[0].to_string(), "10.8.0.0/24");
    }

    #[test]
    fn server_bypass_is_more_specific_than_default_and_uses_original_gateway() {
        let mut profile = Profile::blank();
        profile.host = "203.0.113.10".into();
        profile.authentication = crate::config::AuthMethod::Password;
        profile.exclude_lan = true;
        profile.kill_switch = true;
        let default = DefaultRoute {
            gateway: Ipv4Addr::new(192, 168, 1, 1),
            device: "eth0".into(),
        };
        let server = Ipv4Addr::new(203, 0, 113, 10);
        let plan = plan_routes(&profile, &default, &[server], &[], &[]).unwrap();
        assert!(plan.bypass.contains(&server));
        assert!(plan.ipv6_blackhole);
        let (apply, restore) = linux_commands(&plan, "fox0", 7660, 0x6670);
        let joined: Vec<String> = apply.iter().map(|c| c.join(" ")).collect();
        let text = joined.join("\n");
        assert!(text.contains("203.0.113.10/32 via 192.168.1.1 dev eth0 table 7660"), "{text}");
        assert!(text.contains("0.0.0.0/0 dev fox0 table 7660 src 10.77.0.2"), "{text}");
        assert!(text.contains("fwmark 0x6670 lookup main priority 50"), "{text}");
        assert!(text.contains("192.168.0.0/16 via 192.168.1.1"), "{text}");
        assert!(text.contains("blackhole ::/0"), "{text}");
        assert!(text.contains("ip daddr 203.0.113.10 tcp dport 2222 accept"));
        assert!(restore.iter().any(|c| c.iter().any(|a| a == "flush")));
        for cmd in apply.iter().chain(restore.iter()) {
            let program = cmd.first().map(String::as_str).unwrap_or("");
            assert!(program != "sh" && program != "bash" && !program.ends_with("/sh") && !program.ends_with("/bash"), "{program}");
            for arg in cmd {
                if program.ends_with("nft") && arg.contains("table inet") {
                    continue;
                }
                assert!(!arg.contains(';') && !arg.contains('|') && !arg.contains('`') && !arg.contains('$'), "{arg}");
            }
        }
    }

    #[test]
    fn rejects_shell_metacharacters_in_auto_routes() {
        let nets = parse_remote_routes("1.2.3.0/24;rm -rf /\n$(reboot)/32\n");
        assert!(nets.is_empty());
    }
}
