import nmap
import networkx as nx
from pyvis.network import Network
from datetime import datetime

class AutoNetworkDiagrammer:
    def __init__(self):
        self.scanner = nmap.PortScanner()
        self.G = nx.Graph()
        self.net = Network(height="1000px", width="100%", directed=False, notebook=False)
        self.net.set_options("""
        {
            "nodes": {"shape": "dot", "size": 28, "font": {"size": 15, "face": "Arial"}},
            "edges": {"smooth": true},
            "physics": {"stabilization": {"iterations": 2500}}
        }
        """)

    def scan_network(self, targets=None):
        if not targets:
            targets = ["192.168.5.0/27", "192.168.15.0/28", "192.168.20.0/28",
                       "192.168.25.0/28", "192.168.30.0/28", "10.20.0.0/25"]
        
        print("🔍 Scanning your VLANs...")
        for target in targets:
            try:
                self.scanner.scan(hosts=target, arguments='-sn -R')
                for host in self.scanner.all_hosts():
                    hostname = self.scanner[host].hostname() or f"host-{host.split('.')[-1]}"
                    mac = self.scanner[host]['addresses'].get('mac', 'Unknown')
                    device_type = self.guess_device_type(hostname)
                    
                    label = f"{hostname}\n{host}"
                    title = f"IP: {host}\nHostname: {hostname}\nMAC: {mac}\nVLAN: {self.get_vlan(host)}"
                    
                    self.G.add_node(host, label=label, title=title, group=device_type)
                    self.net.add_node(host, label=label, title=title, color=self.get_color(device_type))
                    print(f"   ✓ {hostname} ({host})")
            except Exception as e:
                print(f"   Error on {target}: {e}")

    def get_vlan(self, ip):
        if ip.startswith("192.168.5"): return "5"
        if ip.startswith("10.20.0"): return "10"
        if ip.startswith("192.168.15"): return "15"
        if ip.startswith("192.168.20"): return "20"
        if ip.startswith("192.168.25"): return "25"
        if ip.startswith("192.168.30"): return "30"
        return "?"

    def guess_device_type(self, hostname):
        h = hostname.lower()
        if any(x in h for x in ['mikrotik', 'router', 'gateway', 'pfsense']): return "router"
        if any(x in h for x in ['switch', 'core']): return "switch"
        if any(x in h for x in ['proxmox', 'pve', 'esxi', 'vm']): return "server"
        if any(x in h for x in ['nas', 'omv']): return "nas"
        if any(x in h for x in ['wazuh', 'siem']): return "server"
        if 'dns' in h or 'technitium' in h or 'map' in h: return "dns"
        if any(x in h for x in ['ap', 'wifi']): return "ap"
        return "workstation"

    def get_color(self, device_type):
        colors = {
            "router": "#e74c3c", "switch": "#3498db", "server": "#2ecc71",
            "nas": "#1abc9c", "dns": "#8e44ad", "ap": "#9b59b6",
            "workstation": "#95a5a6"
        }
        return colors.get(device_type, "#3498db")

    def generate(self, output_file="auto_network_map.html"):
        self.net.from_nx(self.G)
        # Removed problematic show_buttons line
        self.net.write_html(output_file)
        print(f"\n✅ Diagram saved: {output_file}")
        print("   Open the HTML file in your browser")

if __name__ == "__main__":
    diagram = AutoNetworkDiagrammer()
    diagram.scan_network()
    diagram.generate()
