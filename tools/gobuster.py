import subprocess
import shlex
import logging
from mcp.server.fastmcp import Context

logger = logging.getLogger("pentest-mcp")

def run_gobuster(target: str, ctx: Context, wordlist: str = "/usr/share/wordlists/dirb/common.txt", options: str = "-q") -> str:
    """Run gobuster directory scan on a target.
    
    Args:
        target: Target URL (e.g., http://example.com)
        wordlist: Path to wordlist file (default: common.txt from dirb)
        options: Additional gobuster options (default: -q for quiet mode)
    """
    logger.info(f"Running gobuster on {target} with wordlist: {wordlist}")
    ctx.info(f"Starting gobuster scan on {target} with wordlist: {wordlist}")
    ctx.report_progress(1, 3)
    
    # Validate input to prevent command injection
    if not validate_input(target) or not validate_options(options) or not validate_wordlist(wordlist):
        return "Invalid input. Please check your parameters."
    
    # Construct and execute command
    try:
        cmd = f"gobuster dir -u {target} -w {wordlist} {options}"
        logger.info(f"Executing command: {cmd}")
        ctx.info(f"Executing command: {cmd}")
        ctx.report_progress(2, 3)
        result = subprocess.run(
            shlex.split(cmd),
            capture_output=True,
            text=True,
            check=False,
            timeout=300  # 5 minute timeout
        )
        
        if result.returncode != 0 and "Error:" in result.stderr:
            logger.error(f"gobuster error: {result.stderr}")
            return f"Error running gobuster: {result.stderr}"
        
        output = result.stdout if result.stdout else "No results found."
        ctx.report_progress(3, 3)
        return output
    except subprocess.TimeoutExpired:
        return "Gobuster scan timed out after 5 minutes"
    except Exception as e:
        logger.error(f"Error executing gobuster: {str(e)}")
        return f"Error executing gobuster: {str(e)}"

def validate_input(input_str: str) -> bool:
    """Basic validation to help prevent command injection"""
    # Disallow dangerous characters
    dangerous_chars = [';', '&', '|', '>', '<', '`', '$', '(', ')', '{', '}', '\\']
    return not any(char in input_str for char in dangerous_chars)

def validate_options(options: str) -> bool:
    """Validate command-line options"""
    # Disallow dangerous characters
    dangerous_chars = [';', '&', '|', '>', '<', '`', '$', '(', ')', '{', '}', '\\']
    return not any(char in options for char in dangerous_chars)

def validate_wordlist(wordlist: str) -> bool:
    """Validate wordlist path"""
    # Only allow wordlists in specific directories
    allowed_prefixes = ["/usr/share/wordlists/", "/opt/wordlists/"]
    dangerous_chars = [';', '&', '|', '>', '<', '`', '$', '(', ')', '{', '}', '\\']
    
    return (
        any(wordlist.startswith(prefix) for prefix in allowed_prefixes) and
        not any(char in wordlist for char in dangerous_chars)
    )