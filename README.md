# KaliMCP
A simple Kali Linux MCP protocol that can utilize Nikto, Nmap, Gobuster, Metasploit. This is a POC and a WIP so look for updates or expand on it yourself.


## MAKE SURE TO PASTE YOUR CONTAINERS HASH IN ClAUDE.config file 
  -works with other Ai models but Im a Claudehead and enjoy that over other models. 


## Set Up

1. Clone this repository:

2. Build and start the Docker container:
   ```bash
   docker-compose up -d
   ```
3. Configure Claude Desktop to use this MCP server

4. Restart Claude Desktop

5. Send IPs, URLs, ect to Claude with what you want

Ex:

"Please run a nmap scan on (ipaddr) and write me a report of open ports and possible vulnerabilities"

## DISCLAIMER 
  - This is to be used for research purposes only and in no way shape or form should this be used for malicous or unauthorized pentesting.
