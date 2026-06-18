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
            "nodes": {"shape": "dot", "size": 28, "font": {"size": 15}},
            "edges": {"smooth": {"type": "dynamic"}, "font": {"size": 10}},
            "physics": {"stabilization": {"iterations": 2000}}
        }
        """)
        self.router_ip = None  # Will detect the main router

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
                    
                    # Detect router
                    if self.router_ip is None and any(x in hostname.lower() for x in ['map', 'mikrotik', 'router', 'gateway']):
                        self.router_ip = host
                    
                    label = f"{hostname}\n{host}"
                    title = f"IP: {host}\nHostname: {hostname}\nMAC: {mac}\nVLAN: {self.get_vlan(host)}"
                    
                    self.G.add_node(host, label=label, title=title, group=device_type)
                    self.net.add_node(host, label=label, title=title, color=self.get_color(device_type))
                    print(f"   ✓ {hostname} ({host})")
            except Exception as e:
                print(f"   Error on {target}: {e}")

    def add_inferred_edges(self):
        """Infer connections — mainly star topology via router"""
        if not self.router_ip:
            print("⚠️ No router detected. Using fallback logic.")
            # Fallback: pick the .5.1 address as router
            for node in list(self.G.nodes):
                if node.endswith('.1') or 'map' in node.lower():
                    self.router_ip = node
                    break
        
        if self.router_ip and self.router_ip in self.G:
            print(f"🔗 Connecting devices to router: {self.router_ip}")
            for node in list(self.G.nodes):
                if node != self.router_ip:
                    # Add edge with label showing possible connection type
                    self.G.add_edge(self.router_ip, node, label="inferred")
                    self.net.add_edge(self.router_ip, node, title="Inferred connection", label="→")
        else:
            print("⚠️ Could not find a central router for edge inference.")

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
        if any(x in h for x in ['mikrotik', 'router', 'gateway', 'pfsense', 'map']): return "router"
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
        self.add_inferred_edges()
        self.net.from_nx(self.G)
        self.net.write_html(output_file)
        print(f"\n✅ Diagram with inferred topology saved: {output_file}")

if __name__ == "__main__":
    diagram = AutoNetworkDiagrammer()
    diagram.scan_network()
    diagram.generate()
