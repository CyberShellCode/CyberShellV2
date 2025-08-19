from dataclasses import dataclass, field
from typing import List
import ipaddress
from urllib.parse import urlparse

@dataclass
class SafetyConfig:
    allow_private_ranges: bool = True
    allow_localhost: bool = True
    additional_scope_hosts: List[str] = field(default_factory=list)
    require_manual_approval: bool = True  # for risky ops in user plugins

    def in_scope(self, target: str) -> bool:
        # Check if we're in CTF/test mode (allows common test sites)
        host = urlparse(target).hostname or target
        
        # Always allow common CTF and test sites
        ctf_sites = [
            'testphp.vulnweb.com',
            'testaspnet.vulnweb.com',
            'demo.testfire.net',
            'juice-shop.herokuapp.com',
            'bwapp.local',
            'dvwa.local',
            'mutillidae.local'
        ]
        
        if any(site in host for site in ctf_sites):
            return True
            
        if self.allow_localhost and host in {'localhost','127.0.0.1','::1'}:
            return True
        try:
            ip = ipaddress.ip_address(host)
            if self.allow_private_ranges and (ip.is_private or ip.is_loopback):
                return True
        except ValueError:
            if host in self.additional_scope_hosts or any(host.endswith('.'+h) for h in self.additional_scope_hosts):
                return True
        return False
