# External Reconnaissance MCP Server

A Model Context Protocol (MCP) server for performing active external reconnaissance activities against a domain. This tool provides a simple suite of reconnaissance capabilities including DNS enumeration, subdomain discovery, email security analysis, and SSL certificate inspection.

## Want to build your own?
This project was created as a PoC for my tutorial on creating your own MCP server [here](link)

> [!CAUTION]
> This is intended solely as a demonstration and is not production-ready. Use at your own risk. Only use MCPs that you trust to run on your machine. While this is a relatively benign tool, it does run OS commands. Do not target systems that you do not have permission to target.

## Features

- DNS Reconnaissance
  - Comprehensive DNS record enumeration (A, AAAA, MX, NS, SOA, TXT, SRV)
  - DNS zone transfer attempts
  - Subdomain enumeration & bruteforcing
- Domain Information
  - WHOIS lookups
  - HTTP headers analysis
- Email Security Assessment

### System Requirements
The following tools need to be installed on your system:
- dig (DNS lookup utility)
- whois
- dnsrecon

### Required Files
A subdomain wordlist has been supplied for brute-forcing, add to the list or replace for your own. (Note there is currently a limitation with very long wordlists).
- dns-wordlist.txt

## Usage
For using a pre-built server, instructions from here: https://modelcontextprotocol.io/quickstart/user

1. Download Claude for Desktop
2. Install uv
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```
3. Download this repo and add to Claude for Desktop config
    - Claude for Desktop > Settings > Developer > Edit config
    This will create a configuration file at:
```bash
macOS: ~/Library/Application Support/Claude/claude_desktop_config.json
Windows: %APPDATA%\Claude\claude_desktop_config.json
```
Open up the configuration file in any text editor. Replace the file contents with this:
```bash
{
	"mcpServers": {
		"external-recon": {
			"command": "/ABSOLUTE/PATH/TO/PARENT/FOLDER/uv",
			"args": [
				"--directory",
				"/ABSOLUTE/PATH/TO/PARENT/FOLDER/external-recon",
				"run",
				"external-recon.py"
			]
		}
}}
```
4. Relaunch Claude for Desktop
You should now see two icons in the chat bar, a hammer which shows the tools available and a connection icon which shows the prompt defined and the input required (domain name)

5. Select the external-recon setup prompt and supply the target domain, you can then ask Claude to peform external recon and away she goes!

## Security Considerations

1. Only use against authorised targets
2. Follow responsible disclosure practices
3. Respect target system's resources

## Contributing

Contributions are welcome! Please feel free to submit pull requests.

## Disclaimer

This tool is for educational and authorized testing purposes only. Users are responsible for ensuring they have permission to test target systems.