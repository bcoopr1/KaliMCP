import subprocess
import shlex
import logging

logger = logging.getLogger("pentest-mcp")

def run_nmap(target: str, options: str = "-sV") -> str:
    """Run nmap scan on a target.
    
    Args:
        target: Target IP address or hostname
        options: Nmap scan options (default: -sV for service/version detection)
    """
    logger.info(f"Running nmap scan on {target} with options: {options}")
    
    # Validate input to prevent command injection
    if not validate_input(target) or not validate_options(options):
        return "Invalid input. Please provide a valid target IP, hostname, or subnet."
    
    # Construct and execute the command
    try:
        cmd = f"nmap {options} {target}"
        logger.info(f"Executing command: {cmd}")
        
        result = subprocess.run(
            shlex.split(cmd),
            capture_output=True,
            text=True,
            check=False,
            timeout=300  # 5 minute timeout
        )
        
        if result.returncode != 0:
            logger.error(f"nmap error: {result.stderr}")
            return f"Error running nmap: {result.stderr}"
        
        return result.stdout
    except subprocess.TimeoutExpired:
        logger.warning("Nmap scan timed out")
        return "Nmap scan timed out after 5 minutes"
    except Exception as e:
        logger.error(f"Error executing nmap: {str(e)}")
        return f"Error executing nmap: {str(e)}"

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
