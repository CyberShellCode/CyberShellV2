import os
import sys
import argparse
import json
from pathlib import Path
from datetime import datetime

# Fix imports - use unified_config for SafetyConfig and BountyConfig
if __name__ == "__main__" and __package__ is None:
    # Ensure package imports work when executed directly
    try:
        from cybershell.orchestrator import CyberShell
        from cybershell.unified_config import SafetyConfig, BountyConfig
        from cybershell.agent import AutonomousBountyHunter
    except ModuleNotFoundError:
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from cybershell.orchestrator import CyberShell
        from cybershell.unified_config import SafetyConfig, BountyConfig
        from cybershell.agent import AutonomousBountyHunter
    from cybershell.llm_connectors import (
        OllamaConnector,
        OpenAIChatConnector,
        LocalFunctionConnector,
    )
else:
    from .orchestrator import CyberShell
    from .unified_config import SafetyConfig, BountyConfig
    from .agent import AutonomousBountyHunter
    from .llm_connectors import (
        OllamaConnector,
        OpenAIChatConnector,
        LocalFunctionConnector,
    )

def print_banner():
    """Print CyberShell banner"""
    banner = """
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║   ██████╗██╗   ██╗██████╗ ███████╗██████╗                ║
║  ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗               ║
║  ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝               ║
║  ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗               ║
║  ╚██████╗   ██║   ██████╔╝███████╗██║  ██║               ║
║   ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝               ║
║                                                          ║
║         ███████╗██╗  ██╗███████╗██╗     ██╗              ║
║         ██╔════╝██║  ██║██╔════╝██║     ██║              ║
║         ███████╗███████║█████╗  ██║     ██║              ║
║         ╚════██║██╔══██║██╔══╝  ██║     ██║              ║
║         ███████║██║  ██║███████╗███████╗███████╗         ║
║         ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝         ║
║                                                          ║
║    Autonomous Bug Bounty & CTF Hunting Framework v2.0    ║
║           For Authorized Security Testing Only           ║
╚══════════════════════════════════════════════════════════╝
    """
    print(banner)

def setup_llm(args, bot: CyberShell):
    """Configure LLM based on arguments"""
    
    if args.llm == "none":
        return None
    
    print(f"[*] Configuring LLM: {args.llm}")
    
    try:
        if args.llm == "ollama":
            model = os.getenv("OLLAMA_MODEL", "dolphin-mixtral:8x7b")
            base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
            llm = OllamaConnector(model=model, base_url=base_url)
            print(f"[+] Ollama configured with {model}")
            
        elif args.llm == "openai":
            if not os.getenv("OPENAI_API_KEY"):
                print("[!] Warning: OPENAI_API_KEY not set")
                return None
            llm = OpenAIChatConnector()
            print("[+] OpenAI configured")
            
        elif args.llm == "localfn":
            def aggressive_llm(prompt: str) -> str:
                return json.dumps([
                    {"plugin": "SQLiExploitPlugin", "why": "SQL injection attack", 
                     "params": {"technique": "union_based", "extract_data": True}},
                ])
            llm = LocalFunctionConnector(generate_fn=aggressive_llm)
            print("[+] Local function LLM configured")
            
        else:
            print(f"[!] Unknown LLM type: {args.llm}")
            return None
        
        bot.llm = llm
        return llm
        
    except Exception as e:
        print(f"[!] Failed to configure LLM: {e}")
        return None

def run_ctf_mode(args: argparse.Namespace) -> dict:
    """Run CTF solving mode with targeted vulnerability testing"""
    
    print(f"\n[CTF MODE] Target: {args.target}")
    
    # Configure for CTF (always aggressive)
    config = SafetyConfig(
        allow_localhost=True,
        allow_private_ranges=True,
        additional_scope_hosts=[],
        require_explicit_authorization=False  # Fixed parameter name
    )
    
    # Initialize CyberShell with args
    bot = CyberShell(args=args)
    bot.safety_config = config  # Override safety config for CTF
    
    # Setup LLM
    setup_llm(args, bot)
    
    # Check if specific vulnerability was specified
    if args.vuln_type:
        print(f"[*] Targeting specific vulnerability: {args.vuln_type.upper()}")
        result = run_targeted_ctf_test(bot, args.target, args.vuln_type)
    else:
        print("[*] Running full CTF exploitation scan")
        # Configure for CTF hunting
        ctf_config = BountyConfig(
            target_domain=args.target,
            scope=[args.target],
            aggressive_mode=True,
            chain_vulnerabilities=True,
            extract_data_samples=True,
            auto_generate_reports=True,
            max_parallel_exploits=10,
            min_cvss_for_exploit=0.0,
            confidence_threshold=0.2
        )
        
        # Use agent.hunt if available
        if hasattr(bot, 'agent') and hasattr(bot.agent, 'hunt'):
            result = bot.agent.hunt(args.target)
        else:
            # Fallback to execute
            result = bot.execute(args.target, llm_step_budget=5)
    
    # Extract and display flag
    extract_ctf_flag(result)
    
    # Save CTF report
    if args.output:
        save_ctf_report(result, args.output)
    else:
        save_ctf_report(result, f"ctf_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    
    return result

def run_targeted_ctf_test(bot: CyberShell, target: str, vuln_type: str):
    """Run targeted vulnerability test for CTF"""
    
    vuln_type = vuln_type.upper()
    results = []
    
    # Map vulnerability types to plugins - only use existing ones
    vuln_plugin_map = {
        'SQLI': ['SQLiTestPlugin', 'SQLiExploitPlugin'],
        'SQL': ['SQLiTestPlugin', 'SQLiExploitPlugin'],
        'XSS': ['XSSTestPlugin', 'XSSExploitPlugin'],
        'RCE': ['RCETestPlugin', 'RCEExploitPlugin'],
        'IDOR': ['IDORTestPlugin', 'IDORExploitPlugin'],
        'SSRF': ['SSRFTestPlugin', 'SSRFExploitPlugin'],
    }
    
    if vuln_type not in vuln_plugin_map:
        print(f"[!] Unknown vulnerability type: {vuln_type}")
        print(f"[*] Available types: {', '.join(vuln_plugin_map.keys())}")
        # Fallback to execute
        return bot.execute(target, llm_step_budget=5)
    
    plugins = vuln_plugin_map[vuln_type]
    
    print(f"\n[*] Running {vuln_type} exploitation chain:")
    print("-" * 50)
    
    for plugin_name in plugins:
        print(f"[*] Executing: {plugin_name}")
        
        # Check if plugin exists
        if plugin_name not in bot.plugins:
            print(f"  [!] Plugin {plugin_name} not found, skipping...")
            continue
        
        params = {'target': target}
        
        # Add specific params for exploitation plugins
        if 'Exploit' in plugin_name:
            if 'SQLi' in plugin_name:
                params.update({
                    'technique': 'union_based',
                    'extract_data': True,
                    'enumerate_db': True
                })
        
        try:
            result = bot.execute_plugin(plugin_name, params)
            results.append(result)
            
            if result.success:
                print(f"  [+] SUCCESS: {plugin_name}")
            else:
                print(f"  [-] Failed: {plugin_name}")
        except Exception as e:
            print(f"  [!] Error executing {plugin_name}: {e}")
    
    print("-" * 50)
    
    return {
        'target': target,
        'vulnerability_type': vuln_type,
        'results': [r.__dict__ if hasattr(r, '__dict__') else r for r in results],
        'success': any(r.success if hasattr(r, 'success') else False for r in results)
    }

def extract_ctf_flag(result: dict):
    """Extract and display CTF flags from results"""
    import re
    
    print("\n" + "="*60)
    print("FLAG EXTRACTION")
    print("="*60)
    
    flag_patterns = [
        r'flag\{[^}]+\}',
        r'FLAG\{[^}]+\}',
        r'ctf\{[^}]+\}',
        r'CTF\{[^}]+\}',
        r'picoCTF\{[^}]+\}',
    ]
    
    flags_found = set()
    result_str = json.dumps(result, default=str)
    
    for pattern in flag_patterns:
        matches = re.findall(pattern, result_str, re.IGNORECASE)
        flags_found.update(matches)
    
    if flags_found:
        print("\n🏁 FLAGS FOUND:")
        for flag in flags_found:
            print(f"  🚩 {flag}")
    else:
        print("\n❌ No flags found in exploitation results")

def save_ctf_report(result: dict, filename: str):
    """Save CTF exploitation report"""
    output_path = Path(filename)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, default=str)
    
    print(f"\n[+] CTF report saved to {output_path}")

def run_standard_mode(args: argparse.Namespace) -> None:
    """Run standard bug bounty hunting mode"""
    
    # Configure safety settings
    config = SafetyConfig(
        allow_private_ranges=not args.production,
        allow_localhost=not args.production,
        additional_scope_hosts=args.scope.split(',') if args.scope else [],
        require_explicit_authorization=args.safe_mode
    )
    
    # Initialize CyberShell with args
    bot = CyberShell(args=args)
    bot.safety_config = config
    
    # Setup LLM
    setup_llm(args, bot)
    
    # Execute exploitation workflow
    print(f"[*] Starting exploitation on {args.target}")
    print(f"[*] Planner: {args.planner} | Scorer: {args.scorer}")
    
    result = bot.execute(
        target=args.target,
        llm_step_budget=args.llm_steps
    )
    
    # Display results
    print("\n" + "="*60)
    print("EXPLOITATION RESULTS")
    print("="*60)
    
    evidence = result.get('evidence_summary', {})
    print(f"\n[*] Evidence Score (EMA): {evidence.get('ema', 0):.2f}")
    print(f"[*] Maximum Evidence: {evidence.get('max', 0):.2f}")
    print(f"[*] Evidence Trend: {evidence.get('trend', 'stable')}")
    
    metrics = result.get('metrics', {})
    print(f"\n[*] Total Attempts: {metrics.get('total_attempts', 0)}")
    print(f"[*] Successful Exploits: {metrics.get('successful_exploits', 0)}")
    print(f"[*] Success Rate: {metrics.get('success_rate', 0):.2%}")
    
    # Save report
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        if args.format == "markdown":
            output_path.write_text(result.get('report', ''), encoding='utf-8')
            print(f"\n[+] Report saved to {output_path}")
        else:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(result, f, indent=2, default=str)
            print(f"\n[+] JSON results saved to {output_path}")
    else:
        print("\n" + result.get('report', ''))

def run_autonomous_mode(args: argparse.Namespace) -> None:
    """Run fully autonomous bug bounty hunting mode"""
    
    print("[*] Initializing Autonomous Bug Bounty Hunter")
    
    # Configure bounty settings
    bounty_config = BountyConfig(
        target_domain=args.target,
        scope=args.scope.split(',') if args.scope else [args.target],
        out_of_scope=args.out_of_scope.split(',') if args.out_of_scope else [],
        aggressive_mode=not args.safe_mode,
        chain_vulnerabilities=args.chain_exploits,
        extract_data_samples=args.extract_data,
        auto_generate_reports=True,
        max_parallel_exploits=args.parallel,
        min_cvss_for_exploit=args.min_cvss,
        confidence_threshold=args.confidence
    )
    
    # Configure safety
    config = SafetyConfig(
        allow_private_ranges=not args.production,
        allow_localhost=not args.production,
        additional_scope_hosts=bounty_config.scope
    )
    
    # Initialize orchestrator with args
    bot = CyberShell(args=args)
    bot.safety_config = config
    
    # Setup LLM
    setup_llm(args, bot)
    
    # Run autonomous hunt
    print(f"[*] Starting autonomous hunt on {args.target}")
    print(f"[*] Scope: {bounty_config.scope}")
    
    # Try different methods
    if hasattr(bot, 'hunt_autonomous'):
        result = bot.hunt_autonomous(args.target, bounty_config)
    elif hasattr(bot, 'agent') and hasattr(bot.agent, 'hunt'):
        result = bot.agent.hunt(args.target)
    else:
        print("[!] Using standard execution mode")
        result = bot.execute(args.target, llm_step_budget=10)
    
    # Display findings
    print("\n" + "="*60)
    print("BUG BOUNTY FINDINGS")
    print("="*60)
    
    findings = result.get('findings', [])
    if findings:
        print(f"\n[*] Total Findings: {len(findings)}")
        for i, finding in enumerate(findings, 1):
            print(f"\n[Finding #{i}]")
            print(f"  Type: {finding.get('vuln_type', 'Unknown')}")
    else:
        print("\n[*] No specific findings recorded")
    
    # Save results
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, default=str)
        print(f"\n[+] Results saved to {output_path}")

def main() -> None:
    """Main entry point"""

    print_banner()

    parser = argparse.ArgumentParser(
        prog="cybershell",
        description="CyberShell - Autonomous Bug Bounty & CTF Hunting Framework"
    )

    # Execution modes
    subparsers = parser.add_subparsers(dest='mode', help='Execution mode')

    # CTF mode
    ctf_parser = subparsers.add_parser('ctf', help='CTF solving mode')
    ctf_parser.add_argument('target', help='CTF challenge URL')
    ctf_parser.add_argument('--vuln', '--vuln-type', dest='vuln_type',
                            choices=['SQLI', 'SQL', 'XSS', 'RCE', 'IDOR', 'SSRF'],
                            help='Specific vulnerability to test for')

    # Standard exploitation mode
    exploit_parser = subparsers.add_parser('exploit', help='Standard exploitation mode')
    exploit_parser.add_argument('target', help='Target URL or domain')

    # Autonomous hunting mode
    hunt_parser = subparsers.add_parser('hunt', help='Autonomous bug bounty hunting')
    hunt_parser.add_argument('target', help='Target domain for bug bounty')

    # Common arguments for all modes
    for p in [ctf_parser, exploit_parser, hunt_parser]:
        # Scope control arguments
        p.add_argument('--scope', help='Comma-separated in-scope domains')
        p.add_argument('--out-of-scope', help='Comma-separated out-of-scope patterns')

        # Exploitation parameters
        p.add_argument('--min-cvss', type=float, default=4.0, help='Minimum CVSS to exploit')
        p.add_argument('--confidence', type=float, default=0.75, help='Confidence threshold')
        p.add_argument('--parallel', type=int, default=5, help='Parallel exploits')
        p.add_argument('--chain-exploits', action='store_true', help='Chain vulnerabilities')
        p.add_argument('--extract-data', action='store_true', help='Extract data for PoC')

        # Planning and scoring
        p.add_argument('--planner', default='aggressive' if p == ctf_parser else 'depth_first',
                       choices=['depth_first', 'breadth_first', 'aggressive', 'adaptive'],
                       help='Planning strategy')
        p.add_argument('--scorer', default='weighted_signal',
                       choices=['default', 'weighted_signal', 'high_confidence', 'bounty_value'],
                       help='Evidence scoring method')

        # LLM configuration
        p.add_argument('--llm', default='none',
                       choices=['none', 'ollama', 'openai', 'localfn'],
                       help='LLM for exploitation assistance')
        p.add_argument('--llm-steps', type=int, default=5,
                       help='Number of LLM-suggested steps')

        # Paths and output
        p.add_argument('--doc-root', default='docs',
                       help='Document root for knowledge base')
        p.add_argument('--plugins-dir', default='plugins_user',
                       help='User plugins directory')
        p.add_argument('--output', '-o', help='Output file path')
        p.add_argument('--format', choices=['json', 'markdown'], default='json',
                       help='Output format')

        # Safety and mode flags
        p.add_argument('--safe-mode', action='store_true',
                       help='Safe mode (less aggressive)')
        p.add_argument('--production', action='store_true',
                       help='Production mode (no localhost/private IPs)')
        p.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')

    # Parse arguments
    args = parser.parse_args()

    if not args.mode:
        parser.print_help()
        sys.exit(1)

    # Execute based on mode
    try:
        if args.mode == 'ctf':
            run_ctf_mode(args)
        elif args.mode == 'exploit':
            run_standard_mode(args)
        elif args.mode == 'hunt':
            run_autonomous_mode(args)
        else:
            parser.print_help()
            sys.exit(1)

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        if hasattr(args, 'verbose') and args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
