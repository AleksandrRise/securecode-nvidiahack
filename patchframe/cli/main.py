"""
Command-line interface for PatchFrame.
"""

import asyncio
import json
import logging
from pathlib import Path
from typing import Optional
import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.text import Text

from ..core.scanner import PatchFrameScanner
from ..services.trust_scorer import TrustScorer
from ..services.anomaly_detector import AnomalyDetector
from ..services.sbom_generator import SBOMGenerator
from ..database.models import init_database

app = typer.Typer(
    name="patchframe",
    help="Real-Time Patch-Level Vulnerability Scanner for Open Source Dependencies",
    add_completion=False
)

console = Console()

@app.command()
def scan(
    project_path: str = typer.Argument(..., help="Path to the project to scan"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file for results"),
    format: str = typer.Option("json", "--format", "-f", help="Output format: json, table, summary"),
    max_commits: int = typer.Option(100, "--max-commits", help="Maximum commits to analyze per dependency"),
    include_dev: bool = typer.Option(True, "--include-dev/--no-dev", help="Include dev dependencies"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    trust_analysis: bool = typer.Option(False, "--trust", help="Include trust score analysis"),
    anomaly_detection: bool = typer.Option(False, "--anomaly", help="Include anomaly detection"),
    sbom: bool = typer.Option(False, "--sbom", help="Generate SBOM"),
    sbom_format: str = typer.Option("spdx", "--sbom-format", help="SBOM format: spdx, cyclonedx, swid")
):
    """Scan a project for vulnerabilities."""
    if verbose:
        logging.basicConfig(level=logging.INFO)
    
    # Validate project path
    project_path = Path(project_path)
    if not project_path.exists():
        console.print(f"[red]Error: Project path '{project_path}' does not exist[/red]")
        raise typer.Exit(1)
    
    console.print(f"[bold blue]PatchFrame Scanner[/bold blue]")
    console.print(f"Scanning project: {project_path}")
    console.print()
    
    # Run scan with progress
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Scanning project...", total=None)
        
        async def run_scan():
            try:
                scanner = PatchFrameScanner()
                result = await scanner.scan_project(str(project_path))
                
                # Add trust analysis if requested
                if trust_analysis:
                    progress.update(task, description="Analyzing trust scores...")
                    trust_scorer = TrustScorer()
                    for vuln in result.get('vulnerabilities', []):
                        trust_score = await trust_scorer.calculate_trust_score(
                            vuln['dependency_name'],
                            vuln['patch_sha']
                        )
                        vuln['trust_score'] = trust_score.overall_trust_score
                
                # Add anomaly detection if requested
                if anomaly_detection:
                    progress.update(task, description="Detecting anomalies...")
                    anomaly_detector = AnomalyDetector()
                    for vuln in result.get('vulnerabilities', []):
                        if vuln.get('diff_content'):
                            anomaly_result = await anomaly_detector.detect_anomaly(
                                vuln['dependency_name'],
                                vuln['patch_sha'],
                                vuln['diff_content']
                            )
                            vuln['anomaly_score'] = anomaly_result.anomaly_score
                            vuln['is_anomaly'] = anomaly_result.is_anomaly
                
                # Generate SBOM if requested
                if sbom:
                    progress.update(task, description="Generating SBOM...")
                    sbom_generator = SBOMGenerator()
                    sbom_result = await sbom_generator.generate_sbom(str(project_path), sbom_format)
                    result['sbom'] = {
                        'format': sbom_result.format,
                        'content': sbom_result.content,
                        'total_components': sbom_result.total_components,
                        'vulnerabilities_found': sbom_result.vulnerabilities_found
                    }
                
                return result
                
            except Exception as e:
                console.print(f"[red]Scan failed: {e}[/red]")
                raise typer.Exit(1)
        
        result = asyncio.run(run_scan())
    
    # Display results
    if format == "json":
        if output:
            with open(output, 'w') as f:
                json.dump(result, f, indent=2, default=str)
            console.print(f"[green]Results saved to {output}[/green]")
        else:
            console.print_json(data=result)
    
    elif format == "table":
        display_results_table(result)
    
    elif format == "summary":
        display_results_summary(result)
    
    # Save SBOM if generated
    if sbom and result.get('sbom'):
        sbom_file = f"{project_path.name}_sbom.{sbom_format}.json"
        with open(sbom_file, 'w') as f:
            f.write(result['sbom']['content'])
        console.print(f"[green]SBOM saved to {sbom_file}[/green]")

@app.command()
def trust(
    dependency: str = typer.Argument(..., help="Dependency name"),
    patch_sha: str = typer.Argument(..., help="Patch SHA"),
    author_email: Optional[str] = typer.Option(None, "--author", help="Author email")
):
    """Calculate trust score for a specific patch."""
    console.print(f"[bold blue]Trust Score Analysis[/bold blue]")
    console.print(f"Dependency: {dependency}")
    console.print(f"Patch SHA: {patch_sha}")
    console.print()
    
    async def run_trust_analysis():
        trust_scorer = TrustScorer()
        trust_score = await trust_scorer.calculate_trust_score(
            dependency, patch_sha, author_email
        )
        return trust_score
    
    trust_score = asyncio.run(run_trust_analysis())
    
    # Display trust score
    table = Table(title="Trust Score Analysis")
    table.add_column("Metric", style="cyan")
    table.add_column("Score", style="magenta")
    table.add_column("Description", style="green")
    
    table.add_row("Author Trust", f"{trust_score.author_trust_score:.2f}", "Maintainer reputation score")
    table.add_row("Commit Trust", f"{trust_score.commit_trust_score:.2f}", "Commit quality score")
    table.add_row("Overall Trust", f"{trust_score.overall_trust_score:.2f}", "Combined trust score")
    
    console.print(table)
    console.print()
    
    # Display factors
    if trust_score.factors:
        console.print("[bold]Trust Factors:[/bold]")
        for factor in trust_score.factors:
            console.print(f"  • {factor}")
        console.print()
    
    # Display explanation
    console.print(f"[bold]Explanation:[/bold] {trust_score.explanation}")

@app.command()
def anomaly(
    dependency: str = typer.Argument(..., help="Dependency name"),
    patch_sha: str = typer.Argument(..., help="Patch SHA"),
    diff_file: str = typer.Option(None, "--diff-file", help="File containing diff content"),
    diff_content: Optional[str] = typer.Option(None, "--diff-content", help="Diff content directly")
):
    """Detect anomalies in a patch."""
    console.print(f"[bold blue]Anomaly Detection[/bold blue]")
    console.print(f"Dependency: {dependency}")
    console.print(f"Patch SHA: {patch_sha}")
    console.print()
    
    # Get diff content
    if diff_file:
        with open(diff_file, 'r') as f:
            diff_content = f.read()
    elif not diff_content:
        console.print("[red]Error: Either --diff-file or --diff-content must be provided[/red]")
        raise typer.Exit(1)
    
    async def run_anomaly_detection():
        anomaly_detector = AnomalyDetector()
        anomaly_result = await anomaly_detector.detect_anomaly(
            dependency, patch_sha, diff_content
        )
        return anomaly_result
    
    anomaly_result = asyncio.run(run_anomaly_detection())
    
    # Display results
    if anomaly_result.is_anomaly:
        console.print(f"[red]🚨 Anomaly Detected![/red]")
    else:
        console.print(f"[green]✅ No significant anomalies detected[/green]")
    
    console.print()
    
    table = Table(title="Anomaly Analysis")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="magenta")
    
    table.add_row("Anomaly Score", f"{anomaly_result.anomaly_score:.2f}")
    table.add_row("Anomaly Type", anomaly_result.anomaly_type or "none")
    table.add_row("Is Anomaly", "Yes" if anomaly_result.is_anomaly else "No")
    
    console.print(table)
    console.print()
    
    # Display description
    console.print(f"[bold]Description:[/bold] {anomaly_result.description}")
    console.print()
    
    # Display recommendations
    if anomaly_result.recommendations:
        console.print("[bold]Recommendations:[/bold]")
        for rec in anomaly_result.recommendations:
            console.print(f"  • {rec}")

@app.command()
def sbom(
    project_path: str = typer.Argument(..., help="Path to the project"),
    format: str = typer.Option("spdx", "--format", "-f", help="SBOM format: spdx, cyclonedx, swid"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file"),
    validate: bool = typer.Option(False, "--validate", help="Validate generated SBOM")
):
    """Generate Software Bill of Materials."""
    project_path = Path(project_path)
    if not project_path.exists():
        console.print(f"[red]Error: Project path '{project_path}' does not exist[/red]")
        raise typer.Exit(1)
    
    console.print(f"[bold blue]SBOM Generation[/bold blue]")
    console.print(f"Project: {project_path}")
    console.print(f"Format: {format}")
    console.print()
    
    async def generate_sbom():
        sbom_generator = SBOMGenerator()
        sbom_result = await sbom_generator.generate_sbom(str(project_path), format)
        return sbom_result
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Generating SBOM...", total=None)
        sbom_result = asyncio.run(generate_sbom())
    
    # Display results
    table = Table(title="SBOM Generation Results")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="magenta")
    
    table.add_row("Format", sbom_result.format)
    table.add_row("Total Components", str(sbom_result.total_components))
    table.add_row("Vulnerabilities Found", str(sbom_result.vulnerabilities_found))
    table.add_row("Generated At", sbom_result.generated_at.strftime("%Y-%m-%d %H:%M:%S"))
    
    console.print(table)
    console.print()
    
    # Save to file
    if output:
        output_file = output
    else:
        output_file = f"{project_path.name}_sbom.{format}.json"
    
    with open(output_file, 'w') as f:
        f.write(sbom_result.content)
    
    console.print(f"[green]SBOM saved to {output_file}[/green]")
    
    # Validate if requested
    if validate:
        console.print()
        console.print("[bold]Validating SBOM...[/bold]")
        
        async def validate_sbom():
            sbom_generator = SBOMGenerator()
            validation_result = await sbom_generator.validate_sbom(sbom_result.content, format)
            return validation_result
        
        validation_result = asyncio.run(validate_sbom())
        
        if validation_result['valid']:
            console.print("[green]✅ SBOM is valid[/green]")
        else:
            console.print("[red]❌ SBOM validation failed[/red]")
            for error in validation_result['errors']:
                console.print(f"  • Error: {error}")
        
        if validation_result['warnings']:
            console.print("[yellow]⚠️  Warnings:[/yellow]")
            for warning in validation_result['warnings']:
                console.print(f"  • {warning}")

@app.command()
def init():
    """Initialize the database."""
    console.print("[bold blue]Initializing PatchFrame Database[/bold blue]")
    init_database()
    console.print("[green]✅ Database initialized successfully[/green]")

@app.command()
def version():
    """Show version information."""
    from .. import __version__
    console.print(f"[bold blue]PatchFrame[/bold blue] v{__version__}")
    console.print("Real-Time Patch-Level Vulnerability Scanner for Open Source Dependencies")

def display_results_table(result: dict):
    """Display scan results in a table format."""
    summary = result.get('summary', {})
    
    # Summary table
    summary_table = Table(title="Scan Summary")
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Value", style="magenta")
    
    summary_table.add_row("Project Path", result.get('project_path', 'Unknown'))
    summary_table.add_row("Scan Timestamp", result.get('scan_timestamp', 'Unknown'))
    summary_table.add_row("Total Dependencies", str(summary.get('total_dependencies', 0)))
    summary_table.add_row("Total Vulnerabilities", str(summary.get('total_vulnerabilities', 0)))
    summary_table.add_row("Critical", str(summary.get('critical_vulns', 0)))
    summary_table.add_row("High", str(summary.get('high_vulns', 0)))
    summary_table.add_row("Medium", str(summary.get('medium_vulns', 0)))
    summary_table.add_row("Low", str(summary.get('low_vulns', 0)))
    
    console.print(summary_table)
    console.print()
    
    # Vulnerabilities table
    vulnerabilities = result.get('vulnerabilities', [])
    if vulnerabilities:
        vuln_table = Table(title="Detected Vulnerabilities")
        vuln_table.add_column("Dependency", style="cyan")
        vuln_table.add_column("Version", style="blue")
        vuln_table.add_column("Severity", style="red")
        vuln_table.add_column("Description", style="green")
        vuln_table.add_column("Confidence", style="yellow")
        
        for vuln in vulnerabilities[:10]:  # Limit to top 10
            severity_color = {
                'critical': 'red',
                'high': 'orange',
                'medium': 'yellow',
                'low': 'green'
            }.get(vuln.get('severity', 'low'), 'white')
            
            vuln_table.add_row(
                vuln.get('dependency_name', 'Unknown'),
                vuln.get('dependency_version', 'Unknown'),
                f"[{severity_color}]{vuln.get('severity', 'unknown')}[/{severity_color}]",
                vuln.get('description', 'No description')[:50] + "..." if len(vuln.get('description', '')) > 50 else vuln.get('description', 'No description'),
                f"{vuln.get('confidence', 0):.2f}"
            )
        
        console.print(vuln_table)
        
        if len(vulnerabilities) > 10:
            console.print(f"[dim]... and {len(vulnerabilities) - 10} more vulnerabilities[/dim]")

def display_results_summary(result: dict):
    """Display scan results summary."""
    summary = result.get('summary', {})
    vulnerabilities = result.get('vulnerabilities', [])
    
    # Create summary panel
    total_vulns = summary.get('total_vulnerabilities', 0)
    critical_vulns = summary.get('critical_vulns', 0)
    high_vulns = summary.get('high_vulns', 0)
    
    if total_vulns == 0:
        status_text = Text("✅ No vulnerabilities detected", style="green")
    elif critical_vulns > 0:
        status_text = Text(f"🚨 {critical_vulns} critical vulnerabilities found!", style="red")
    elif high_vulns > 0:
        status_text = Text(f"⚠️  {high_vulns} high vulnerabilities found", style="orange")
    else:
        status_text = Text(f"⚠️  {total_vulns} vulnerabilities found", style="yellow")
    
    summary_panel = Panel(
        f"{status_text}\n\n"
        f"Project: {result.get('project_path', 'Unknown')}\n"
        f"Dependencies: {summary.get('total_dependencies', 0)}\n"
        f"Vulnerabilities: {total_vulns}\n"
        f"  • Critical: {critical_vulns}\n"
        f"  • High: {high_vulns}\n"
        f"  • Medium: {summary.get('medium_vulns', 0)}\n"
        f"  • Low: {summary.get('low_vulns', 0)}",
        title="Scan Results",
        border_style="blue"
    )
    
    console.print(summary_panel)
    
    # Show top vulnerabilities
    if vulnerabilities:
        console.print("\n[bold]Top Vulnerabilities:[/bold]")
        for i, vuln in enumerate(vulnerabilities[:5], 1):
            severity_icon = {
                'critical': '🔴',
                'high': '🟠',
                'medium': '🟡',
                'low': '🟢'
            }.get(vuln.get('severity', 'low'), '⚪')
            
            console.print(f"{i}. {severity_icon} {vuln.get('dependency_name', 'Unknown')}@{vuln.get('dependency_version', 'Unknown')}")
            console.print(f"   {vuln.get('description', 'No description')}")
            console.print()

if __name__ == "__main__":
    app() 