import subprocess
import logging
import json
import tempfile
import os
import re
import urllib.parse
from typing import List, Optional, Dict, Any
from mcp.server.fastmcp import Context

logger = logging.getLogger("pentest-mcp")

class SecurityToolError(Exception):
    """Custom exception for security tool errors"""
    pass

class InputValidationError(Exception):
    """Custom exception for input validation errors"""
    pass

def run_nikto(target: str, ctx: Context, options: Optional[List[str]] = None) -> str:
    """Run nikto web vulnerability scanner on a target.
    
    Args:
        target: Target URL or IP address (e.g., http://example.com or 192.168.1.1)
        options: List of nikto scan options (default: ['-h'])
    """
    if options is None:
        options = []
    
    logger.info(f"Running nikto scan on {target} with options: {options}")
    ctx.info(f"Starting nikto scan on {target} with options: {options}")
    ctx.report_progress(1, 3)
    
    try:
        # Validate and sanitize inputs
        validated_target = validate_and_sanitize_target(target)
        validated_options = validate_nikto_options(options)
        
        ctx.info(f"Validated target: {validated_target}")
        ctx.report_progress(2, 3)
        
        # Construct command with explicit arguments
        cmd_args = ["nikto"] + validated_options + ["-h", validated_target]
        
        logger.info(f"Executing command: {' '.join(cmd_args)}")
        ctx.info(f"Executing nikto scan")
        
        result = subprocess.run(
            cmd_args,
            capture_output=True,
            text=True,
            check=False,
            timeout=600,  # 10 minute timeout
            env=get_safe_environment()
        )
        
        ctx.report_progress(3, 3)
        
        return process_command_output(result, "nikto")
        
    except (InputValidationError, SecurityToolError) as e:
        logger.error(f"Validation/tool error: {str(e)}")
        return f"Error: {str(e)}"
    except subprocess.TimeoutExpired:
        ctx.info("Nikto scan timed out")
        return "Nikto scan timed out after 10 minutes"
    except FileNotFoundError:
        return "Nikto not found. Please ensure Nikto is installed and in your PATH."
    except Exception as e:
        logger.error(f"Unexpected error executing nikto: {str(e)}")
        return f"Unexpected error executing nikto: {str(e)}"

def run_msfconsole(commands: List[str], ctx: Context, output_format: str = "text") -> str:
    """Run Metasploit commands via msfconsole.
    
    Args:
        commands: List of Metasploit commands to execute
        output_format: Output format - 'text' or 'json' (default: text)
    """
    logger.info(f"Running msfconsole with {len(commands)} commands")
    ctx.info(f"Starting msfconsole with {len(commands)} commands")
    ctx.report_progress(1, 4)
    
    rc_file_path = None
    
    try:
        # Validate commands
        validated_commands = validate_metasploit_commands(commands)
        
        # Create temporary resource file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.rc', delete=False) as rc_file:
            for cmd in validated_commands:
                rc_file.write(f"{cmd}\n")
            rc_file.write("exit\n")  # Ensure msfconsole exits
            rc_file_path = rc_file.name
        
        ctx.report_progress(2, 4)
        
        # Construct msfconsole command with explicit arguments
        cmd_args = ["msfconsole", "-q", "-r", rc_file_path]
        
        if output_format.lower() == "json":
            cmd_args.extend(["-o", "/dev/stdout"])
        
        logger.info(f"Executing msfconsole with resource file: {rc_file_path}")
        ctx.info(f"Executing msfconsole")
        ctx.report_progress(3, 4)
        
        result = subprocess.run(
            cmd_args,
            capture_output=True,
            text=True,
            check=False,
            timeout=900,  # 15 minute timeout
            env=get_safe_environment()
        )
        
        ctx.report_progress(4, 4)
        
        return process_command_output(result, "msfconsole")
        
    except (InputValidationError, SecurityToolError) as e:
        logger.error(f"Validation/tool error: {str(e)}")
        return f"Error: {str(e)}"
    except subprocess.TimeoutExpired:
        ctx.info("Msfconsole timed out")
        return "Msfconsole timed out after 15 minutes"
    except FileNotFoundError:
        return "Msfconsole not found. Please ensure Metasploit Framework is installed and in your PATH."
    except Exception as e:
        logger.error(f"Unexpected error executing msfconsole: {str(e)}")
        return f"Unexpected error executing msfconsole: {str(e)}"
    finally:
        # Ensure cleanup of temp file
        if rc_file_path:
            try:
                os.unlink(rc_file_path)
            except OSError as e:
                logger.warning(f"Could not delete temporary file {rc_file_path}: {e}")

def search_exploits(search_term: str, ctx: Context, platform: str = "") -> str:
    """Search for exploits in Metasploit database.
    
    Args:
        search_term: Term to search for (e.g., 'apache', 'wordpress', CVE number)
        platform: Platform filter (e.g., 'linux', 'windows', 'unix')
    """
    logger.info(f"Searching exploits for: {search_term}")
    ctx.info(f"Searching Metasploit exploits for: {search_term}")
    ctx.report_progress(1, 2)
    
    try:
        # Validate inputs
        validated_search_term = validate_search_term(search_term)
        validated_platform = validate_platform(platform) if platform else ""
        
        # Construct search command
        if validated_platform:
            search_cmd = f"search {validated_search_term} platform:{validated_platform}"
        else:
            search_cmd = f"search {validated_search_term}"
        
        ctx.report_progress(2, 2)
        return run_msfconsole([search_cmd], ctx)
        
    except InputValidationError as e:
        return f"Invalid search parameters: {str(e)}"

def quick_exploit_search(cve: str, ctx: Context) -> str:
    """Quick search for exploits by CVE number.
    
    Args:
        cve: CVE identifier (e.g., 'CVE-2021-44228')
    """
    try:
        validated_cve = validate_cve_format(cve)
        return search_exploits(validated_cve, ctx)
    except InputValidationError as e:
        return f"Invalid CVE format: {str(e)}"

def get_exploit_info(exploit_path: str, ctx: Context) -> str:
    """Get detailed information about a specific exploit.
    
    Args:
        exploit_path: Path to the exploit module (e.g., 'exploit/linux/http/apache_log4j_rce')
    """
    try:
        validated_path = validate_exploit_path(exploit_path)
        commands = [f"use {validated_path}", "info"]
        return run_msfconsole(commands, ctx)
    except InputValidationError as e:
        return f"Invalid exploit path: {str(e)}"

# Validation functions with strict allowlists
def validate_and_sanitize_target(target: str) -> str:
    """Validate and sanitize target URL or IP address."""
    if not target or not target.strip():
        raise InputValidationError("Target cannot be empty")
    
    target = target.strip()
    
    # Check if it's a URL
    if target.startswith(('http://', 'https://')):
        parsed = urllib.parse.urlparse(target)
        if not parsed.netloc:
            raise InputValidationError("Invalid URL format")
        # Reconstruct URL to ensure it's properly formatted
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    
    # Check if it's an IP address or hostname
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    hostname_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9\-\.]*[a-zA-Z0-9]$'
    
    if re.match(ip_pattern, target):
        # Validate IP address ranges
        parts = target.split('.')
        if all(0 <= int(part) <= 255 for part in parts):
            return target
        else:
            raise InputValidationError("Invalid IP address range")
    elif re.match(hostname_pattern, target) and len(target) <= 253:
        return target
    else:
        raise InputValidationError("Target must be a valid URL, IP address, or hostname")

def validate_nikto_options(options: List[str]) -> List[str]:
    """Validate nikto command options."""
    if not options:
        return []
    
    # Allowlist of safe nikto options
    safe_options = {
        '-C', '-config', '-Display', '-evasion', '-Format', '-host', '-id',
        '-list-plugins', '-mutate', '-nointeractive', '-output', '-Pause',
        '-Plugins', '-port', '-root', '-ssl', '-Tuning', '-timeout',
        '-useragent', '-vhost', '-404code', '-404string'
    }
    
    validated_options = []
    for option in options:
        option = option.strip()
        if not option:
            continue
            
        # Check if option starts with allowed flags
        option_flag = option.split('=')[0].split()[0]
        if option_flag in safe_options:
            # Additional validation for option values
            if '=' in option:
                flag, value = option.split('=', 1)
                if not validate_option_value(value):
                    raise InputValidationError(f"Invalid option value: {value}")
            validated_options.append(option)
        else:
            raise InputValidationError(f"Disallowed nikto option: {option_flag}")
    
    return validated_options

def validate_metasploit_commands(commands: List[str]) -> List[str]:
    """Validate Metasploit commands."""
    if not commands:
        raise InputValidationError("Commands list cannot be empty")
    
    # Allowlist of safe MSF commands
    safe_commands = {
        'search', 'use', 'info', 'show', 'set', 'unset', 'setg', 'unsetg',
        'run', 'exploit', 'check', 'options', 'advanced', 'help', 'back',
        'sessions', 'jobs', 'load', 'reload', 'version', 'exit', 'quit'
    }
    
    validated_commands = []
    for command in commands:
        command = command.strip()
        if not command:
            continue
            
        # Extract the main command (first word)
        main_command = command.split()[0].lower()
        
        if main_command not in safe_commands:
            raise InputValidationError(f"Disallowed command: {main_command}")
        
        # Additional validation for command arguments
        if not validate_command_arguments(command):
            raise InputValidationError(f"Invalid characters in command: {command}")
        
        validated_commands.append(command)
    
    return validated_commands

def validate_search_term(search_term: str) -> str:
    """Validate search terms."""
    if not search_term or not search_term.strip():
        raise InputValidationError("Search term cannot be empty")
    
    search_term = search_term.strip()
    
    # Allow alphanumeric, spaces, hyphens, underscores, dots, and slashes
    if not re.match(r'^[a-zA-Z0-9\s\-_\./]+$', search_term):
        raise InputValidationError("Search term contains invalid characters")
    
    if len(search_term) > 100:
        raise InputValidationError("Search term too long")
    
    return search_term

def validate_platform(platform: str) -> str:
    """Validate platform filter."""
    allowed_platforms = {
        'linux', 'windows', 'unix', 'osx', 'solaris', 'bsd', 'android', 'ios'
    }
    
    platform = platform.lower().strip()
    if platform not in allowed_platforms:
        raise InputValidationError(f"Invalid platform: {platform}")
    
    return platform

def validate_cve_format(cve: str) -> str:
    """Validate CVE format."""
    cve = cve.strip().upper()
    
    # CVE format: CVE-YYYY-NNNN or CVE-YYYY-NNNNN+
    cve_pattern = r'^CVE-\d{4}-\d{4,}$'
    
    if not re.match(cve_pattern, cve):
        raise InputValidationError("Invalid CVE format. Expected format: CVE-YYYY-NNNN")
    
    return cve

def validate_exploit_path(exploit_path: str) -> str:
    """Validate exploit module path."""
    if not exploit_path or not exploit_path.strip():
        raise InputValidationError("Exploit path cannot be empty")
    
    exploit_path = exploit_path.strip()
    
    # Exploit paths should follow pattern: category/platform/service/exploit_name
    path_pattern = r'^[a-zA-Z0-9_]+(/[a-zA-Z0-9_]+)*$'
    
    if not re.match(path_pattern, exploit_path):
        raise InputValidationError("Invalid exploit path format")
    
    if len(exploit_path) > 200:
        raise InputValidationError("Exploit path too long")
    
    return exploit_path

def validate_option_value(value: str) -> bool:
    """Validate option values for dangerous content."""
    # Disallow shell metacharacters and control characters
    dangerous_chars = set(';&|<>`$(){}\\"\'\n\r\t')
    return not any(char in value for char in dangerous_chars)

def validate_command_arguments(command: str) -> bool:
    """Validate command arguments for dangerous content."""
    # More permissive than option values but still safe
    dangerous_chars = set(';&|<>`$(){}\\"\n\r')
    return not any(char in command for char in dangerous_chars)

def get_safe_environment() -> Dict[str, str]:
    """Get a safe environment for subprocess execution."""
    # Start with minimal environment
    safe_env = {
        'PATH': os.environ.get('PATH', '/usr/local/bin:/usr/bin:/bin'),
        'HOME': os.environ.get('HOME', '/tmp'),
        'USER': os.environ.get('USER', 'nobody'),
        'TERM': 'xterm',
    }
    
    # Add any necessary tool-specific environment variables
    for var in ['METASPLOIT_BASEDIR', 'MSF_DATABASE_CONFIG']:
        if var in os.environ:
            safe_env[var] = os.environ[var]
    
    return safe_env

def process_command_output(result: subprocess.CompletedProcess, tool_name: str) -> str:
    """Process and sanitize command output."""
    if result.returncode != 0 and result.stderr:
        logger.error(f"{tool_name} error: {result.stderr}")
        raise SecurityToolError(f"Error running {tool_name}: {result.stderr}")
    
    # Combine stdout and stderr
    output = result.stdout or ""
    if result.stderr:
        output += f"\n--- Warnings/Info ---\n{result.stderr}"
    
    # Sanitize output (remove any potential control sequences)
    output = re.sub(r'\x1b\[[0-9;]*m', '', output)  # Remove ANSI escape sequences
    
    return output.strip() if output.strip() else f"{tool_name} completed but no output was generated."
