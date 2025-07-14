from typing import List, Dict
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

# Enhanced analysis type definitions with rich formatting metadata
ANALYSIS_TYPES = {
    "business_logic": {
        "name": "Business Logic Security",
        "icon": "🧠",
        "color": "bright_magenta",
        "description": "Authentication, authorization, and business rule vulnerabilities",
        "examples": ["Authentication bypass", "Privilege escalation", "Race conditions"],
        "priority": 1
    },
    "framework_security": {
        "name": "Framework-Specific Security", 
        "icon": "🔧",
        "color": "cyan",
        "description": "Framework-specific security anti-patterns and misconfigurations",
        "examples": ["Django ORM issues", "React XSS patterns", "Express.js middleware"],
        "priority": 2
    },
    "data_protection": {
        "name": "Data Protection & Privacy",
        "icon": "🛡️", 
        "color": "green",
        "description": "PII handling, encryption, and privacy compliance issues",
        "examples": ["PII logging", "Unencrypted storage", "GDPR violations"],
        "priority": 3
    },
    "api_security": {
        "name": "API Security",
        "icon": "🌐",
        "color": "blue",
        "description": "REST/GraphQL security, rate limiting, input validation",
        "examples": ["Missing rate limits", "Unbounded queries", "CORS issues"],
        "priority": 4
    },
    "cryptographic": {
        "name": "Cryptographic Security",
        "icon": "🔐",
        "color": "yellow",
        "description": "Encryption, hashing, key management, and crypto implementation",
        "examples": ["Weak algorithms", "Poor key management", "Crypto misuse"],
        "priority": 5
    },
    "code_quality_security": {
        "name": "Security Code Quality",
        "icon": "📝",
        "color": "bright_white",
        "description": "Security-impacting code smells and patterns",
        "examples": ["Information disclosure", "Error handling", "Logging issues"],
        "priority": 6
    },
    "general": {
        "name": "General Vulnerabilities",
        "icon": "⚠️ ",
        "color": "red",
        "description": "Traditional security vulnerabilities (XSS, SQLi, etc.)",
        "examples": ["SQL injection", "XSS", "Path traversal"],
        "priority": 7
    }
}

class SecurityScanResult:
    def __init__(self, description: str, severity: str, cwe_id: str):
        self.issue = description
        self.severity = severity
        self.cwe = cwe_id

    def __repr__(self):
        return f"{self.issue} (Severity: {self.severity}, CWE: {self.cwe})"


def summarize_security_scan(results: List[SecurityScanResult]) -> Dict[str, List[SecurityScanResult]]:
    summary = {
        "Critical": [],
        "High": [],
        "Medium": [],
        "Low": [],
        "Info": []
    }

    for result in results:
        # Normalize severity to title case (e.g., "high" -> "High")
        severity_key = result.severity.title()
        if severity_key in summary:
            summary[severity_key].append(result)

    return summary


def format_summary(summary: Dict[str, List[SecurityScanResult]]) -> str:
    severity_icons = {
        "Critical": "🛑",
        "High": "🔴",
        "Medium": "🟠",
        "Low": "🟡",
        "Info": "🔵"
    }
    output = []
    output.append("🔒 Security Scan Summary\n" + "="*28)
    for severity, issues in summary.items():
        icon = severity_icons.get(severity, "")
        header = f"[bold]{icon} {severity} Issues ({len(issues)})[/bold]"
        if severity in ["Critical", "High"]:
            header += " [PRIORITY!]"
        output.append(header)
        if issues:
            for issue in issues:
                output.append(
                    f"  - {issue.issue}\n    Severity: {issue.severity.title()} | CWE: {issue.cwe}"
                )
        else:
            output.append("  - None found")
        output.append("")  # Blank line for spacing
    output.append("Legend: 🛑 Critical | 🔴 High | 🟠 Medium | 🟡 Low | 🔵 Info")
    
    # Add Enhanced Analysis Types section
    output.append("\n" + create_enhanced_analysis_overview(summary))
    
    return "\n".join(output)


def generate_security_scan_summary(results: List[SecurityScanResult]) -> str:
    console = Console()
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Processing security scan results...", total=None)
        
        progress.update(task, description="Analyzing security findings...")
        summary = summarize_security_scan(results)
        
        progress.update(task, description="Formatting security summary...")
        formatted_summary = format_summary(summary)
        
        progress.update(task, description="Security scan summary complete!")
        return formatted_summary


def create_enhanced_analysis_overview(summary: Dict[str, List[SecurityScanResult]]) -> str:
    """Create Enhanced Analysis Types overview with analysis of current findings"""
    output = []
    
    # Main header
    output.append("")
    output.append("🔍 Enhanced Security Analysis Types")
    output.append("=" * 50)
    output.append("")
    
    # Analysis Categories Table Header
    output.append("📊 Analysis Categories & Coverage")
    output.append("-" * 40)
    
    # Sort analysis types by priority
    sorted_types = sorted(ANALYSIS_TYPES.items(), key=lambda x: x[1]["priority"])
    
    for type_key, type_info in sorted_types:
        icon = type_info["icon"]
        name = type_info["name"]
        priority = type_info["priority"]
        description = type_info["description"]
        examples = " • ".join(type_info["examples"][:2])
        if len(type_info["examples"]) > 2:
            examples += "..."
        
        output.append(f"{priority}. {icon} {name}")
        output.append(f"   Description: {description}")
        output.append(f"   Examples: {examples}")
        output.append("")
    
    # Detailed breakdown section
    output.append("📋 Detailed Analysis Breakdown")
    output.append("-" * 40)
    
    for type_key, type_info in sorted_types:
        icon = type_info["icon"]
        name = type_info["name"]
        description = type_info["description"]
        
        output.append(f"• {icon} {name}")
        output.append(f"  └─ {description}")
        output.append(f"  └─ Common Vulnerabilities:")
        
        for example in type_info["examples"]:
            output.append(f"     • {example}")
        output.append("")
    
    # Summary statistics
    output.append("📊 Analysis Coverage Summary")
    output.append("-" * 40)
    output.append(f"Total Analysis Types: {len(ANALYSIS_TYPES)}")
    output.append("Coverage Areas: Authentication, Data Protection, Cryptography, APIs, and more")
    output.append("Priority Levels: 1 (Highest) to 7 (Standard)")
    output.append("")
    
    # NEW: Analysis of current findings
    output.append("🎯 Current Security Issues Analysis")
    output.append("=" * 45)
    output.append("")
    
    # Add Severity Distribution Graph
    output.append("📊 Severity Distribution")
    output.append("-" * 30)
    
    # Calculate totals and percentages
    total_issues = sum(len(issues) for issues in summary.values())
    
    if total_issues > 0:
        severity_data = [
            ("Critical", "🛑", len(summary.get("Critical", [])), "red"),
            ("High", "🔴", len(summary.get("High", [])), "bright_red"),
            ("Medium", "🟠", len(summary.get("Medium", [])), "yellow"),
            ("Low", "🟡", len(summary.get("Low", [])), "bright_yellow"),
            ("Info", "🔵", len(summary.get("Info", [])), "blue")
        ]
        
        for severity, icon, count, color in severity_data:
            percentage = (count / total_issues) * 100
            bar_length = 20
            filled_length = int(bar_length * percentage / 100)
            bar = "█" * filled_length + "░" * (bar_length - filled_length)
            
            output.append(f"{icon} {severity:<8} {bar} {percentage:5.1f}% ({count}/{total_issues})")
        
        output.append("")
    else:
        output.append("No issues to display")
        output.append("")
    
    # Analyze findings and map to categories
    findings_analysis = analyze_security_findings(summary)
    
    if findings_analysis["has_issues"]:
        output.append("[bold red]⚠️  PRIORITY SECURITY ISSUES DETECTED[/bold red]")
        output.append("")
        
        # Show critical/high priority findings
        if findings_analysis["critical_high_count"] > 0:
            output.append(f"[bold red]🚨 {findings_analysis['critical_high_count']} Critical/High Severity Issues Require Immediate Attention[/bold red]")
            output.append("")
        
        # Map findings to analysis categories
        output.append("[bold cyan]📋 Issues by Analysis Category:[/bold cyan]")
        output.append("")
        
        for category, issues in findings_analysis["categorized_issues"].items():
            if issues:
                category_info = ANALYSIS_TYPES[category]
                icon = category_info["icon"]
                name = category_info["name"]
                priority = category_info["priority"]
                
                priority_indicator = "🔥 HIGH PRIORITY" if priority <= 3 else "📊 MONITOR"
                output.append(f"[bold]{icon} {name}[/bold] ({len(issues)} issues) - {priority_indicator}")
                
                for issue in issues[:3]:  # Show first 3 issues
                    severity_icon = "🛑" if issue.severity in ["Critical"] else "🔴" if issue.severity == "High" else "🟠" if issue.severity == "Medium" else "🟡"
                    output.append(f"  └─ {severity_icon} {issue.issue[:80]}{'...' if len(issue.issue) > 80 else ''}")
                
                if len(issues) > 3:
                    output.append(f"  └─ ... and {len(issues) - 3} more issues")
                output.append("")
        
        # Priority recommendations
        output.append("[bold yellow]🎯 Recommended Action Priority:[/bold yellow]")
        output.append("")
        
        if findings_analysis["critical_high_count"] > 0:
            output.append("1. [bold red]IMMEDIATE[/bold red] - Address Critical/High severity issues")
        
        high_priority_categories = [cat for cat, issues in findings_analysis["categorized_issues"].items() 
                                  if issues and ANALYSIS_TYPES[cat]["priority"] <= 3]
        if high_priority_categories:
            output.append("2. [bold orange]URGENT[/bold orange] - Focus on high-priority categories:")
            for cat in high_priority_categories:
                output.append(f"   • {ANALYSIS_TYPES[cat]['icon']} {ANALYSIS_TYPES[cat]['name']}")
        
        output.append("3. [bold green]SCHEDULED[/bold green] - Plan remediation for remaining issues")
        
    else:
        output.append("[bold green]✅ No security issues detected in current scan[/bold green]")
        output.append("")
        output.append("Continue monitoring with regular security scans to maintain this status.")
    
    output.append("")
    
    return "\n".join(output)


def analyze_security_findings(summary: Dict[str, List[SecurityScanResult]]) -> Dict:
    """Analyze security findings and categorize them by analysis type"""
    
    # CWE to category mapping
    cwe_mapping = {
        # Business Logic Security
        "CWE-287": "business_logic",  # Authentication bypass
        "CWE-863": "business_logic",  # Privilege escalation
        "CWE-362": "business_logic",  # Race conditions
        
        # General Vulnerabilities  
        "CWE-89": "general",   # SQL injection
        "CWE-79": "general",   # XSS
        "CWE-22": "general",   # Path traversal
        "CWE-434": "general",  # File upload
        "CWE-352": "general",  # CSRF
        "CWE-639": "general",  # Insecure direct object reference
        
        # Cryptographic Security
        "CWE-327": "cryptographic",  # Weak algorithms
        "CWE-798": "cryptographic",  # Hardcoded credentials
        "CWE-330": "cryptographic",  # Weak random number generation
        "CWE-916": "cryptographic",  # Predictable random generation
        
        # Data Protection & Privacy
        "CWE-209": "data_protection",  # Information disclosure
        "CWE-532": "data_protection",  # Information in log files
        "CWE-200": "data_protection",  # Information exposure
        
        # API Security
        "CWE-770": "api_security",  # Missing rate limiting
        "CWE-400": "api_security",  # Resource consumption
        
        # Security Code Quality
        "CWE-476": "code_quality_security",  # NULL pointer dereference
        "CWE-119": "code_quality_security",  # Buffer overflow
    }
    
    # Initialize analysis results
    categorized_issues = {category: [] for category in ANALYSIS_TYPES.keys()}
    total_issues = 0
    critical_high_count = 0
    
    # Categorize all findings
    for severity, issues in summary.items():
        for issue in issues:
            total_issues += 1
            if severity in ["Critical", "High"]:
                critical_high_count += 1
            
            # Map CWE to category
            cwe_id = issue.cwe.replace("CWE-", "") if issue.cwe.startswith("CWE-") else issue.cwe
            cwe_key = f"CWE-{cwe_id}"
            
            category = cwe_mapping.get(cwe_key, "general")  # Default to general if not mapped
            categorized_issues[category].append(issue)
    
    return {
        "has_issues": total_issues > 0,
        "total_issues": total_issues,
        "critical_high_count": critical_high_count,
        "categorized_issues": categorized_issues
    }