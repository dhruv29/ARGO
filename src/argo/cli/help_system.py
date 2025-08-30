"""Comprehensive help system for Argo CLI."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.columns import Columns
from rich.syntax import Syntax
from typing import Dict, Any, List


class ArgoHelpSystem:
    """Comprehensive help system for Argo CLI."""
    
    def __init__(self, console: Console):
        self.console = console
    
    def show_main_help(self):
        """Show main help overview."""
        self.console.print(Panel.fit(
            "[bold blue]Argo CLI — The Argonauts SOC Platform[/]\n\n"
            "A comprehensive command-line interface for cyber threat intelligence operations.\n\n"
            "Use [bold]argo --help[/] to see all available commands.\n"
            "Use [bold]argo <command> --help[/] for detailed command help.",
            title="🚀 Welcome to Argo",
            border_style="blue"
        ))
        
        # Quick start guide
        self.console.print("\n[bold]🚀 Quick Start Guide[/]")
        self.console.print("1. [blue]argo config validate[/] - Validate your configuration")
        self.console.print("2. [blue]argo ingest <path>[/] - Ingest PDF documents")
        self.console.print("3. [blue]argo embed[/] - Generate embeddings")
        self.console.print("4. [blue]argo index[/] - Build search index")
        self.console.print("5. [blue]argo run orpheus --actor <name>[/] - Analyze threat actor")
    
    def show_command_help(self, command: str):
        """Show detailed help for a specific command."""
        help_data = self._get_command_help(command)
        if not help_data:
            self.console.print(f"[red]Unknown command: {command}[/]")
            return
        
        self.console.print(f"\n[bold]Command:[/] {command}")
        self.console.print(f"[bold]Description:[/] {help_data['description']}")
        
        if help_data.get('examples'):
            self.console.print(f"\n[bold]Examples:[/]")
            for example in help_data['examples']:
                self.console.print(f"  [blue]$ {example}[/]")
        
        if help_data.get('notes'):
            self.console.print(f"\n[bold]Notes:[/]")
            for note in help_data['notes']:
                self.console.print(f"  • {note}")
    
    def show_workflow_help(self):
        """Show workflow system help."""
        self.console.print(Panel.fit(
            "[bold]Workflow System[/]\n\n"
            "Argo provides predefined workflows for common CTI operations:\n\n"
            "• [blue]full_cti_pipeline[/] - Complete pipeline from ingestion to analysis\n"
            "• [blue]quick_analysis[/] - Quick analysis using existing data\n\n"
            "Use [bold]argo workflow list[/] to see all workflows.\n"
            "Use [bold]argo workflow info <name>[/] for workflow details.\n"
            "Use [bold]argo workflow run <name>[/] to execute workflows.",
            title="🔄 Workflows",
            border_style="green"
        ))
    
    def show_configuration_help(self):
        """Show configuration help."""
        self.console.print(Panel.fit(
            "[bold]Configuration Management[/]\n\n"
            "Argo uses a hierarchical configuration system:\n\n"
            "1. [blue]Environment Variables[/] - Highest priority\n"
            "2. [blue]Config Files[/] - Persistent settings\n"
            "3. [blue]Defaults[/] - Built-in values\n\n"
            "Key configuration files:\n"
            "• [blue]config/argo_cli.json[/] - CLI settings\n"
            "• [blue]config/approval_policy.yaml[/] - Approval policies\n\n"
            "Use [bold]argo config show[/] to view current settings.\n"
            "Use [bold]argo config validate[/] to check configuration.",
            title="🔧 Configuration",
            border_style="yellow"
        ))
    
    def show_examples(self):
        """Show comprehensive examples."""
        examples = [
            ("Basic Operations", [
                "argo ingest ./documents",
                "argo embed",
                "argo index",
                "argo status"
            ]),
            ("Threat Analysis", [
                "argo run orpheus --actor FIN7",
                "argo search 'T1059.001'",
                "argo validate-outputs"
            ]),
            ("Batch Operations", [
                "argo batch ingest ./large_document_set",
                "argo batch embed",
                "argo batch index"
            ]),
            ("Workflows", [
                "argo workflow list",
                "argo workflow run full_cti_pipeline --context config.json",
                "argo workflow info quick_analysis"
            ]),
            ("Configuration", [
                "argo config show",
                "argo config set batch_size 10",
                "argo config validate"
            ])
        ]
        
        self.console.print("\n[bold]📚 Comprehensive Examples[/]")
        
        for category, cmds in examples:
            self.console.print(f"\n[bold blue]{category}:[/]")
            for cmd in cmds:
                self.console.print(f"  [green]$ {cmd}[/]")
    
    def show_troubleshooting(self):
        """Show troubleshooting guide."""
        self.console.print(Panel.fit(
            "[bold]Troubleshooting Guide[/]\n\n"
            "Common issues and solutions:\n\n"
            "[bold]Database Connection Issues:[/]\n"
            "• Check DATABASE_URL environment variable\n"
            "• Verify PostgreSQL is running\n"
            "• Check network connectivity\n\n"
            "[bold]OpenAI API Issues:[/]\n"
            "• Verify OPENAI_API_KEY is set\n"
            "• Check API key validity and quota\n"
            "• Verify network access to OpenAI\n\n"
            "[bold]File Permission Issues:[/]\n"
            "• Check write permissions for output directories\n"
            "• Verify input file accessibility\n\n"
            "Use [bold]argo config validate[/] to diagnose issues.",
            title="🔍 Troubleshooting",
            border_style="red"
        ))
    
    def show_api_reference(self):
        """Show API reference information."""
        self.console.print(Panel.fit(
            "[bold]API Reference[/]\n\n"
            "Core modules and their purposes:\n\n"
            "[bold]Core Modules:[/]\n"
            "• [blue]ingest[/] - Document ingestion and processing\n"
            "• [blue]embed[/] - Text embedding generation\n"
            "• [blue]retrieve[/] - Hybrid search and retrieval\n"
            "• [blue]summarize[/] - Report generation\n\n"
            "[bold]Advanced Features:[/]\n"
            "• [blue]approval_policy[/] - Policy-driven approval gates\n"
            "• [blue]enhanced_evidence[/] - Rich evidence metadata\n"
            "• [blue]output_validator[/] - Output quality validation\n"
            "• [blue]local_embeddings[/] - Air-gapped embedding options\n\n"
            "Use [bold]argo status[/] to see system capabilities.",
            title="📖 API Reference",
            border_style="cyan"
        ))
    
    def _get_command_help(self, command: str) -> Dict[str, Any]:
        """Get help data for a specific command."""
        help_data = {
            "ingest": {
                "description": "Ingest PDF files from a directory into the database",
                "examples": [
                    "argo ingest ./documents",
                    "argo ingest ./reports --min-tokens 200 --max-tokens 600",
                    "argo ingest ./intel --no-ocr"
                ],
                "notes": [
                    "Supports recursive directory scanning",
                    "OCR fallback for text extraction",
                    "Configurable chunk sizes",
                    "Stores files in object store"
                ]
            },
            "run": {
                "description": "Execute Orpheus CTI analysis workflow",
                "examples": [
                    "argo run orpheus --actor FIN7",
                    "argo run orpheus --actor APT29 --interactive"
                ],
                "notes": [
                    "Interactive approval gate",
                    "Policy-driven validation",
                    "Generates professional reports",
                    "Creates evidence packs"
                ]
            },
            "workflow": {
                "description": "Manage and execute predefined workflows",
                "examples": [
                    "argo workflow list",
                    "argo workflow run full_cti_pipeline --context config.json",
                    "argo workflow info quick_analysis"
                ],
                "notes": [
                    "Predefined workflows for common operations",
                    "Context-driven execution",
                    "Step-by-step progress tracking",
                    "Automatic retry and error handling"
                ]
            },
            "config": {
                "description": "Manage Argo configuration settings",
                "examples": [
                    "argo config show",
                    "argo config set batch_size 10",
                    "argo config reset log_level",
                    "argo config validate"
                ],
                "notes": [
                    "Persistent configuration storage",
                    "Environment variable integration",
                    "Validation and health checks",
                    "Import/export capabilities"
                ]
            }
        }
        
        return help_data.get(command, {})
    
    def show_interactive_help(self):
        """Show interactive mode help."""
        self.console.print(Panel.fit(
            "[bold]Interactive Mode[/]\n\n"
            "Start interactive session with [bold]argo interactive[/]\n\n"
            "Available commands:\n"
            "• [blue]help[/] - Show this help\n"
            "• [blue]status[/] - Show system status\n"
            "• [blue]config[/] - Show configuration\n"
            "• [blue]ingest <path>[/] - Ingest documents\n"
            "• [blue]search <query>[/] - Search documents\n"
            "• [blue]analyze <actor>[/] - Analyze threat actor\n"
            "• [blue]exit[/] - Quit interactive mode\n\n"
            "Interactive mode provides a shell-like experience\n"
            "for complex CTI operations.",
            title="💻 Interactive Mode",
            border_style="magenta"
        ))


def get_help_system(console: Console) -> ArgoHelpSystem:
    """Get the help system instance."""
    return ArgoHelpSystem(console)
