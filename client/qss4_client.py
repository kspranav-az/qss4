#!/usr/bin/env python3
"""
QSS4 Client - Cross-platform CLI for QSS4 Backend

A secure command-line client for uploading, downloading, and managing files
in the QSS4 quantum-safe storage system.
"""

import os
import sys
import json
import click
import requests
import keyring
from pathlib import Path
from typing import Optional, Dict, Any
import getpass
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn
from rich.prompt import Prompt, Confirm
from rich import print as rprint
import tempfile
import mimetypes

# Initialize Rich console
console = Console()

class QSS4Client:
    """QSS4 API Client"""
    
    def __init__(self, base_url: str = "http://localhost:5000"):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.config_dir = Path.home() / '.qss4'
        self.config_file = self.config_dir / 'config.json'
        self.config_dir.mkdir(exist_ok=True)
        
        # Load configuration
        self.config = self.load_config()
        
        # Set up authentication
        self.setup_auth()
    
    def load_config(self) -> Dict[str, Any]:
        """Load client configuration"""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                console.print(f"[yellow]Warning: Could not load config: {e}[/yellow]")
        
        return {
            "base_url": self.base_url,
            "user_email": None,
            "verify_ssl": True
        }
    
    def save_config(self):
        """Save client configuration"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            console.print(f"[red]Error saving config: {e}[/red]")
    
    def setup_auth(self):
        """Set up authentication headers"""
        if self.config.get("user_email"):
            try:
                # Try to get stored access token
                access_token = keyring.get_password("qss4", f"{self.config['user_email']}_access")
                if access_token:
                    self.session.headers.update({
                        'Authorization': f'Bearer {access_token}'
                    })
            except Exception:
                pass  # Keyring might not be available
    
    def login(self, email: str, password: str) -> bool:
        """Login to QSS4 backend"""
        try:
            response = self.session.post(
                f"{self.base_url}/api/v1/auth/login",
                json={
                    "email": email,
                    "password": password
                },
                verify=self.config.get("verify_ssl", True)
            )
            
            if response.status_code == 200:
                data = response.json()
                
                # Store tokens securely
                try:
                    keyring.set_password("qss4", f"{email}_access", data["access_token"])
                    keyring.set_password("qss4", f"{email}_refresh", data["refresh_token"])
                except Exception:
                    console.print("[yellow]Warning: Could not store tokens securely[/yellow]")
                
                # Update session headers
                self.session.headers.update({
                    'Authorization': f'Bearer {data["access_token"]}'
                })
                
                # Update config
                self.config["user_email"] = email
                self.config["base_url"] = self.base_url
                self.save_config()
                
                return True
            else:
                error_data = response.json()
                console.print(f"[red]Login failed: {error_data.get('error', 'Unknown error')}[/red]")
                return False
                
        except requests.exceptions.RequestException as e:
            console.print(f"[red]Connection error: {e}[/red]")
            return False
    
    def logout(self):
        """Logout and clear stored credentials"""
        if self.config.get("user_email"):
            try:
                keyring.delete_password("qss4", f"{self.config['user_email']}_access")
                keyring.delete_password("qss4", f"{self.config['user_email']}_refresh")
            except Exception:
                pass
        
        self.config["user_email"] = None
        self.save_config()
        
        # Clear session headers
        if 'Authorization' in self.session.headers:
            del self.session.headers['Authorization']
    
    def upload_file(self, file_path: Path, category: str = None, 
                   tags: list = None, description: str = None) -> bool:
        """Upload a file to QSS4"""
        if not file_path.exists():
            console.print(f"[red]Error: File not found: {file_path}[/red]")
            return False
        
        file_size = file_path.stat().st_size
        if file_size == 0:
            console.print("[red]Error: Cannot upload empty file[/red]")
            return False
        
        # Prepare metadata
        metadata = {}
        if category:
            metadata["category"] = category
        if tags:
            metadata["tags"] = tags
        if description:
            metadata["description"] = description
        
        # Detect MIME type
        mime_type, _ = mimetypes.guess_type(str(file_path))
        
        try:
            with Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                "[progress.percentage]{task.percentage:>3.0f}%",
                TimeRemainingColumn(),
                console=console
            ) as progress:
                
                task = progress.add_task(
                    f"Uploading {file_path.name}",
                    total=file_size
                )
                
                with open(file_path, 'rb') as f:
                    files = {'file': (file_path.name, f, mime_type)}
                    data = {'metadata': json.dumps(metadata)}
                    
                    response = self.session.post(
                        f"{self.base_url}/api/v1/files/upload",
                        files=files,
                        data=data,
                        verify=self.config.get("verify_ssl", True),
                        stream=True
                    )
                
                if response.status_code == 201:
                    result = response.json()
                    file_info = result["file"]
                    
                    console.print("[green]✓ Upload successful![/green]")
                    
                    # Display file information
                    table = Table(title="Upload Results")
                    table.add_column("Property", style="cyan")
                    table.add_column("Value", style="white")
                    
                    table.add_row("File ID", file_info["file_id"])
                    table.add_row("Filename", file_info["filename"])
                    table.add_row("Size", self.format_size(file_info["size"]))
                    table.add_row("Encryption", file_info["encryption_algo"])
                    table.add_row("Compression", file_info["compression_algo"])
                    table.add_row("File Hash", file_info["file_hash"][:32] + "...")
                    
                    if file_info.get("blockchain_txn_id"):
                        table.add_row("Blockchain TX", file_info["blockchain_txn_id"][:16] + "...")
                    
                    console.print(table)
                    return True
                else:
                    error_data = response.json()
                    console.print(f"[red]Upload failed: {error_data.get('error', 'Unknown error')}[/red]")
                    return False
                    
        except requests.exceptions.RequestException as e:
            console.print(f"[red]Upload error: {e}[/red]")
            return False
    
    def list_files(self, page: int = 1, per_page: int = 20) -> bool:
        """List user's files"""
        try:
            params = {
                "page": page,
                "per_page": per_page,
                "sort": "created_at",
                "order": "desc"
            }
            
            response = self.session.get(
                f"{self.base_url}/api/v1/files/list",
                params=params,
                verify=self.config.get("verify_ssl", True)
            )
            
            if response.status_code == 200:
                data = response.json()
                files = data["files"]
                pagination = data["pagination"]
                
                if not files:
                    console.print("[yellow]No files found[/yellow]")
                    return True
                
                # Create table
                table = Table(title=f"Your Files (Page {pagination['page']} of {pagination['pages']})")
                table.add_column("ID", style="cyan", max_width=12)
                table.add_column("Filename", style="white")
                table.add_column("Size", style="green")
                table.add_column("Type", style="yellow")
                table.add_column("Uploaded", style="blue")
                table.add_column("Encrypted", style="magenta")
                
                for file in files:
                    table.add_row(
                        file["file_id"][:8] + "...",
                        file["filename"],
                        self.format_size(file["size"]),
                        file["mime_type"],
                        file["created_at"][:10],
                        "✓" if file.get("blockchain_txn_id") else "⏳"
                    )
                
                console.print(table)
                
                # Show pagination info
                console.print(f"\nShowing {pagination['page']} of {pagination['pages']} pages "
                            f"({pagination['total']} total files)")
                
                return True
            else:
                error_data = response.json()
                console.print(f"[red]Error listing files: {error_data.get('error', 'Unknown error')}[/red]")
                return False
                
        except requests.exceptions.RequestException as e:
            console.print(f"[red]Error: {e}[/red]")
            return False
    
    def create_download_token(self, file_id: str, ttl_seconds: int = 300) -> Optional[str]:
        """Create a download token for a file"""
        try:
            response = self.session.post(
                f"{self.base_url}/api/v1/files/{file_id}/token",
                json={"ttl_seconds": ttl_seconds},
                verify=self.config.get("verify_ssl", True)
            )
            
            if response.status_code == 200:
                data = response.json()
                token = data["token"]
                
                download_url = f"{self.base_url}/api/v1/files/{file_id}/download?token={token}"
                
                console.print("[green]✓ Download token created![/green]")
                console.print(f"[white]URL: {download_url}[/white]")
                console.print(f"[yellow]Expires in: {ttl_seconds} seconds[/yellow]")
                console.print(f"[red]Note: Token is single-use only![/red]")
                
                return download_url
            else:
                error_data = response.json()
                console.print(f"[red]Error creating token: {error_data.get('error', 'Unknown error')}[/red]")
                return None
                
        except requests.exceptions.RequestException as e:
            console.print(f"[red]Error: {e}[/red]")
            return None
    
    def download_file(self, file_id: str, output_path: Path = None, 
                     ttl_seconds: int = 300) -> bool:
        """Download a file using a token"""
        # First create a download token
        download_url = self.create_download_token(file_id, ttl_seconds)
        if not download_url:
            return False
        
        try:
            # Download the file
            response = requests.get(download_url, stream=True, 
                                  verify=self.config.get("verify_ssl", True))
            
            if response.status_code == 200:
                # Get filename from Content-Disposition header
                filename = "downloaded_file"
                if 'Content-Disposition' in response.headers:
                    cd = response.headers['Content-Disposition']
                    if 'filename=' in cd:
                        filename = cd.split('filename=')[1].strip('"')
                
                # Determine output path
                if output_path is None:
                    output_path = Path.cwd() / filename
                elif output_path.is_dir():
                    output_path = output_path / filename
                
                # Get file size for progress bar
                file_size = int(response.headers.get('Content-Length', 0))
                
                with Progress(
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    "[progress.percentage]{task.percentage:>3.0f}%",
                    TimeRemainingColumn(),
                    console=console
                ) as progress:
                    
                    task = progress.add_task(
                        f"Downloading {filename}",
                        total=file_size
                    )
                    
                    with open(output_path, 'wb') as f:
                        for chunk in response.iter_content(chunk_size=8192):
                            if chunk:
                                f.write(chunk)
                                progress.update(task, advance=len(chunk))
                
                console.print(f"[green]✓ Downloaded to: {output_path}[/green]")
                return True
            else:
                error_data = response.json()
                console.print(f"[red]Download failed: {error_data.get('error', 'Unknown error')}[/red]")
                return False
                
        except requests.exceptions.RequestException as e:
            console.print(f"[red]Download error: {e}[/red]")
            return False
    
    def delete_file(self, file_id: str) -> bool:
        """Delete a file"""
        try:
            response = self.session.delete(
                f"{self.base_url}/api/v1/files/{file_id}",
                verify=self.config.get("verify_ssl", True)
            )
            
            if response.status_code == 200:
                console.print("[green]✓ File deleted successfully[/green]")
                return True
            else:
                error_data = response.json()
                console.print(f"[red]Delete failed: {error_data.get('error', 'Unknown error')}[/red]")
                return False
                
        except requests.exceptions.RequestException as e:
            console.print(f"[red]Error: {e}[/red]")
            return False
    
    def get_file_info(self, file_id: str) -> bool:
        """Get detailed file information"""
        try:
            response = self.session.get(
                f"{self.base_url}/api/v1/files/{file_id}",
                verify=self.config.get("verify_ssl", True)
            )
            
            if response.status_code == 200:
                data = response.json()
                file_info = data["file"]
                
                # Create detailed table
                table = Table(title=f"File Details: {file_info['filename']}")
                table.add_column("Property", style="cyan")
                table.add_column("Value", style="white")
                
                table.add_row("File ID", file_info["file_id"])
                table.add_row("Filename", file_info["filename"])
                table.add_row("Size", self.format_size(file_info["size"]))
                table.add_row("MIME Type", file_info["mime_type"])
                table.add_row("Encryption", file_info["encryption_algo"])
                table.add_row("Compression", file_info["compression_algo"])
                table.add_row("File Hash", file_info["file_hash"])
                table.add_row("Created", file_info["created_at"])
                
                if file_info.get("blockchain_txn_id"):
                    table.add_row("Blockchain TX", file_info["blockchain_txn_id"])
                
                if file_info.get("metadata"):
                    for key, value in file_info["metadata"].items():
                        table.add_row(f"Meta: {key}", str(value))
                
                console.print(table)
                return True
            else:
                error_data = response.json()
                console.print(f"[red]Error: {error_data.get('error', 'Unknown error')}[/red]")
                return False
                
        except requests.exceptions.RequestException as e:
            console.print(f"[red]Error: {e}[/red]")
            return False
    
    @staticmethod
    def format_size(size_bytes: int) -> str:
        """Format file size in human readable format"""
        if size_bytes == 0:
            return "0 B"
        
        size_names = ["B", "KB", "MB", "GB", "TB"]
        i = 0
        while size_bytes >= 1024 and i < len(size_names) - 1:
            size_bytes /= 1024.0
            i += 1
        
        return f"{size_bytes:.1f} {size_names[i]}"


# CLI Commands
@click.group()
@click.option('--url', default='http://localhost:5000', help='QSS4 backend URL')
@click.option('--no-ssl-verify', is_flag=True, help='Disable SSL verification')
@click.pass_context
def cli(ctx, url, no_ssl_verify):
    """QSS4 Client - Quantum-Safe Secure Storage CLI"""
    ctx.ensure_object(dict)
    ctx.obj['client'] = QSS4Client(url)
    if no_ssl_verify:
        ctx.obj['client'].config['verify_ssl'] = False

@cli.command()
@click.option('--email', prompt=True, help='Your email address')
@click.option('--password', prompt=True, hide_input=True, help='Your password')
@click.pass_context
def login(ctx, email, password):
    """Login to QSS4 backend"""
    client = ctx.obj['client']
    
    with console.status("[bold blue]Logging in...", spinner="dots"):
        success = client.login(email, password)
    
    if success:
        console.print(f"[green]✓ Successfully logged in as {email}[/green]")
    else:
        sys.exit(1)

@cli.command()
@click.pass_context
def logout(ctx):
    """Logout from QSS4 backend"""
    client = ctx.obj['client']
    client.logout()
    console.print("[green]✓ Logged out successfully[/green]")

@cli.command()
@click.argument('file_path', type=click.Path(exists=True, path_type=Path))
@click.option('--category', help='File category (medical, legal, financial, etc.)')
@click.option('--tags', help='Comma-separated tags')
@click.option('--description', help='File description')
@click.pass_context
def upload(ctx, file_path, category, tags, description):
    """Upload a file to QSS4"""
    client = ctx.obj['client']
    
    tag_list = [tag.strip() for tag in tags.split(',')] if tags else None
    
    success = client.upload_file(file_path, category, tag_list, description)
    if not success:
        sys.exit(1)

@cli.command()
@click.option('--page', default=1, help='Page number')
@click.option('--per-page', default=20, help='Files per page')
@click.pass_context
def list(ctx, page, per_page):
    """List your files"""
    client = ctx.obj['client']
    
    success = client.list_files(page, per_page)
    if not success:
        sys.exit(1)

@cli.command()
@click.argument('file_id')
@click.option('--output', '-o', type=click.Path(path_type=Path), help='Output file or directory')
@click.option('--ttl', default=300, help='Token TTL in seconds (default: 300)')
@click.pass_context
def download(ctx, file_id, output, ttl):
    """Download a file by ID"""
    client = ctx.obj['client']
    
    success = client.download_file(file_id, output, ttl)
    if not success:
        sys.exit(1)

@cli.command()
@click.argument('file_id')
@click.option('--ttl', default=300, help='Token TTL in seconds (default: 300)')
@click.pass_context
def token(ctx, file_id, ttl):
    """Create a download token for a file"""
    client = ctx.obj['client']
    
    url = client.create_download_token(file_id, ttl)
    if not url:
        sys.exit(1)

@cli.command()
@click.argument('file_id')
@click.pass_context
def info(ctx, file_id):
    """Get detailed file information"""
    client = ctx.obj['client']
    
    success = client.get_file_info(file_id)
    if not success:
        sys.exit(1)

@cli.command()
@click.argument('file_id')
@click.confirmation_option(prompt='Are you sure you want to delete this file?')
@click.pass_context
def delete(ctx, file_id):
    """Delete a file"""
    client = ctx.obj['client']
    
    success = client.delete_file(file_id)
    if not success:
        sys.exit(1)

@cli.command()
@click.pass_context
def status(ctx):
    """Show client status and configuration"""
    client = ctx.obj['client']
    
    table = Table(title="QSS4 Client Status")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="white")
    
    table.add_row("Backend URL", client.config.get("base_url", "Not set"))
    table.add_row("User Email", client.config.get("user_email", "Not logged in"))
    table.add_row("SSL Verify", str(client.config.get("verify_ssl", True)))
    table.add_row("Config Dir", str(client.config_dir))
    
    console.print(table)

if __name__ == '__main__':
    cli()
