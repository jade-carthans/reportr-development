from openai import AzureOpenAI
import os
import csv
from collections import Counter, defaultdict

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.markup import escape
from rich.progress import Progress, SpinnerColumn, TextColumn

def analyze_security_scan(scan_results):
    """Analyze security scan results and categorize issues by severity level."""
    summary = {
        "high": [],
        "medium": [],
        "low": [],
        "info": []
    }

    for result in scan_results:
        severity = result.get("severity", "info")
        if severity not in summary:
            severity = "info"
        summary[severity].append(result)
        
    return summary

def enhance_with_cwe(scan_results, client=None):
    console = Console()
    enhanced_results = []
    
    if client and scan_results:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Enhancing scan results with CWE information...", total=None)
            
            for result in scan_results:
                cwe_id = result.get("cwe_id")
                cwe_info = CWE_INFO.get(cwe_id)
                if cwe_info:
                    result["cwe_title"] = cwe_info["title"]
                    result["cwe_description"] = cwe_info["description"]
                    # Only generate remediation tip if client is provided
                    if client is not None:
                        progress.update(task, description=f"Generating remediation tip for {cwe_id}...")
                        result["remediation_tip"] = get_remediation_tip_llm(
                            client, cwe_id, cwe_info["title"], cwe_info["description"]
                        )
                    else:
                        result["remediation_tip"] = "No LLM client provided."
                enhanced_results.append(result)
            
            progress.update(task, description="CWE enhancement complete!")
    else:
        # No progress needed for simple enhancement without LLM calls
        for result in scan_results:
            cwe_id = result.get("cwe_id")
            cwe_info = CWE_INFO.get(cwe_id)
            if cwe_info:
                result["cwe_title"] = cwe_info["title"]
                result["cwe_description"] = cwe_info["description"]
                result["remediation_tip"] = "No LLM client provided."
            enhanced_results.append(result)
    
    return enhanced_results

def generate_security_scan_summary(scan_results: list, client=None) -> dict:
    """Generate a summary of security scan results with CWE insights."""
    categorized_results = analyze_security_scan(scan_results)
    # Pass the client argument to enhance_with_cwe
    high_severity_results = enhance_with_cwe(categorized_results["high"], client)

    summary = {
        "total_issues": sum(len(v) for v in categorized_results.values()),
        "high_severity": len(high_severity_results),
        "medium_severity": len(categorized_results["medium"]),
        "low_severity": len(categorized_results["low"]),
        "info_severity": len(categorized_results["info"]),
        "high_severity_details": high_severity_results
    }

    return summary

def load_cwe_titles(csv_path=None):
    if csv_path is None:
        # Automatically get the path relative to this script's location
        csv_path = os.path.join(os.path.dirname(__file__), "cwe_information.csv")
    cwe_titles = {}
    with open(csv_path, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            cwe_id = row['CWE-ID']
            name = row['Name']
            description = row.get('Description', '')
            cwe_titles[f"CWE-{cwe_id}"] = name
    return cwe_titles

def load_cwe_info(csv_path=None):
    if csv_path is None:
        # Automatically get the path relative to this script's location
        csv_path = os.path.join(os.path.dirname(__file__), "cwe_information.csv")
    cwe_info = {}
    with open(csv_path, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            cwe_id = row['CWE-ID']
            name = row['Name']
            description = row.get('Description', '')
            cwe_info[f"CWE-{cwe_id}"] = {
                "title": name,
                "description": description
            }
    return cwe_info

def get_remediation_tip_llm(client, cwe_id, title, description):
    prompt = (
        f"You are a security expert. "
        f"Given the following CWE information, provide a concise, actionable remediation tip for developers. "
        f"Respond with only the tip, no extra text.\n\n"
        f"CWE ID: {cwe_id}\n"
        f"Title: {title}\n"
        f"Description: {description}\n"
        f"Remediation Tip:"
    )
    response = client.chat.completions.create(
        model="reportr",  # or your deployed model name
        messages=[{"role": "user", "content": prompt}],
        max_tokens=60,
        temperature=0.2,
    )
    return response.choices[0].message.content.strip()

remediation_cache = {}

def get_remediation_tip_cached(client, cwe_id, title, description):
    if cwe_id in remediation_cache:
        return remediation_cache[cwe_id]
    tip = get_remediation_tip_llm(client, cwe_id, title, description)
    remediation_cache[cwe_id] = tip
    return tip

CWE_TITLES = load_cwe_titles()
CWE_INFO = load_cwe_info()

def generate_security_vulnerability_analysis(scan_results: list, client=None) -> str:
    console = Console()
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Analyzing security vulnerability scan results...", total=None)
        
        # Group by CWE
        cwe_counter = Counter()
        cwe_details = defaultdict(list)
        severity_score_map = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
        total_score = 0

        progress.update(task, description="Processing scan results...")
        
        for issue in scan_results:
            cwe_id = issue.get("cwe_id", "Unknown")
            cwe_counter[cwe_id] += 1
            cwe_details[cwe_id].append(issue)
            severity = issue.get("severity", "info").lower()
            total_score += severity_score_map.get(severity, 1)

        # Top 5 CWEs
        top_cwes = cwe_counter.most_common(5)

        progress.update(task, description="Calculating risk scores...")
        
        # Risk Score Calculation
        max_score = len(scan_results) * max(severity_score_map.values()) if scan_results else 1
        risk_percent = int((total_score / max_score) * 100)
        if risk_percent >= 80:
            risk_level = "🔥 High"
        elif risk_percent >= 50:
            risk_level = "🟠 Medium"
        else:
            risk_level = "🟢 Low"

        # Executive Summary
        exec_summary = (
            f"[bold]Executive Summary:[/bold]\n"
            f"• Total findings: {len(scan_results)}\n"
            f"• Unique CWEs: {len(cwe_counter)}\n"
            f"• Top CWE: [bright_cyan]{top_cwes[0][0]}[/bright_cyan] ({top_cwes[0][1]} findings)\n"
            f"• Risk Score: {risk_level} ({risk_percent}%)"
        ) if top_cwes else "No CWEs found."

        progress.update(task, description="Generating detailed vulnerability insights...")
        
        # Build output
        output = []
        output.append("[bold bright_blue]🔍 Security Vulnerability Analysis[/bold bright_blue]")
        output.append("=" * 28)
        output.append(exec_summary)
        output.append("\n[bold]Top 5 Most Common CWEs:[/bold]")
        
        for i, (cwe_id, count) in enumerate(top_cwes):
            cwe_info = CWE_INFO.get(cwe_id, {})
            title = cwe_info.get("title", cwe_id)
            description = cwe_info.get("description", "")
            
            # Optionally generate remediation tip with LLM if client is provided
            remediation = ""
            if client:
                progress.update(task, description=f"Generating remediation tip for {cwe_id}...")
                remediation = get_remediation_tip_cached(client, cwe_id, title, description)
            
            # Add spacing between CWE sections
            if i > 0:
                output.append("")
            
            output.append(
                f"[bold bright_cyan]{cwe_id}[/bold bright_cyan] ([italic]{escape(title)}[/italic]) - {count} finding(s)\n"
                f"   [bold]Description:[/bold] {escape(description)}\n"
                f"   [bold]Remediation:[/bold] {escape(remediation if remediation else 'See CWE documentation.')}\n"
                f"   [blue]🔗 https://cwe.mitre.org/data/definitions/{cwe_id.split('-')[-1]}.html[/blue]"
            )
        
        # Add Severity Distribution Graph
        progress.update(task, description="Generating severity distribution...")
        output.append("\n[bold]📊 Severity Distribution:[/bold]")
        output.append("-" * 30)
        
        # Calculate severity distribution
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for issue in scan_results:
            severity = issue.get("severity", "info").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        total_issues = len(scan_results)
        if total_issues > 0:
            severity_data = [
                ("Critical", "🛑", severity_counts["critical"], "red"),
                ("High", "🔴", severity_counts["high"], "bright_red"),
                ("Medium", "🟠", severity_counts["medium"], "yellow"),
                ("Low", "🟡", severity_counts["low"], "bright_yellow"),
                ("Info", "🔵", severity_counts["info"], "blue")
            ]
            
            for severity, icon, count, color in severity_data:
                percentage = (count / total_issues) * 100
                bar_length = 20
                filled_length = int(bar_length * percentage / 100)
                bar = "█" * filled_length + "░" * (bar_length - filled_length)
                
                output.append(f"{icon} {severity:<8} {bar} {percentage:5.1f}% ({count}/{total_issues})")
        else:
            output.append("No issues to display")
        
        output.append(f"\n[bold]Risk Score:[/bold] {risk_level} ({risk_percent}%)")
        output.append("\n[bold]Legend:[/bold] 🔴 High | 🟠 Medium | 🟡 Low | 🔵 Info")

        progress.update(task, description="Security vulnerability analysis complete!")
        return "\n".join(output)

