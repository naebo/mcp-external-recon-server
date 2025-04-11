from mcp.server.fastmcp import FastMCP
import subprocess
import httpx
import os

# Initialise FastMCP server
mcp = FastMCP("external-recon")

# function to execute OS commands
def execute_os_command(command: str) -> str:
    """
    Executes an OS command and returns its output as a string.
    
    :param command: command string to execute
    :return: output from command execution
    """
    try:
        result = subprocess.run(
            command, 
            shell=True, 
            check=True, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        return e.stderr.strip()

## Prompt to initialise the AI model to the task
@mcp.prompt()
def setup_prompt(domainname: str) -> str:
    """
    setup external reconnaissance by domain name

    :param domainname: domain name to target
    :type domainname: str
    :return:
    :rtype: str
    """

    return f"""
Your role is a highly skilled penetration tester specialising in network reconnaissance. Your primary objective is to enumerate the {domainname} domain and report on discovered IP addresses, subdomains, and email security.

Observer carefully the output of the tools in inform next steps

Your objective is to perform reconnaissance against the organisation's domain name, identify IP addresses, discover subdomains, report on the ownership of the domains, and assess the email security measures. When you find new IP addresses or subdomains I want you to repeat enumeration steps.

First, reflect on the objective, then execute any tools you have access to on the target domain {domainname} and report your findings on all IP addresses and subdomains discovered.
"""

### run dig to query DNS A records
@mcp.tool()
async def run_dig_lookup(domainname: str) -> str:
    """
    perform simple lookup of any A records for the domain.
    :param domainname: domain to query
    :type domainname: str
    :return: DNS query results
    """
    try:
        command = f"dig {domainname}"
        result = execute_os_command(command)
        
        if not result:
            return f"No DNS records found for {domainname}"
            
        return result
    except Exception as e:
        return f"Error performing DNS lookup: {str(e)}"

### run whois on each IP address to show who it belongs to
@mcp.tool()
async def run_whois_lookup(ipaddress: str) -> str:
    """
    perform query of domain ownership details.
    :param ipaddress: ip to query
    :type ipaddress: str
    :return: whois query results
    """
    try:
        command = f"whois {ipaddress}"
        return execute_os_command(command)
    except Exception as e:
        return f"Error performing whois lookup: {str(e)}"

### perform DNS zone transfer attempt
@mcp.tool()
async def attempt_zone_transfer(domainname: str) -> str:
    """
    Attempt to perform a DNS zone transfer (AXFR) to enumerate all DNS records.
    :param domainname: domain to attempt zone transfer against
    :type domainname: str
    :return: zone transfer results
    """
    try:
        command = f"dig axfr {domainname}"
        return execute_os_command(command)
    except Exception as e:
        return f"Error performing zone transfer: {str(e)}"

### perform subdomain enumeration using dnsrecon
@mcp.tool()
async def enumerate_subdomains(domainname: str) -> str:
    """
    Enumerate subdomains using dnsrecon tool.
    :param domainname: domain to enumerate subdomains for
    :type domainname: str
    :return: subdomain enumeration results
    """
    try:
        command = f"dnsrecon -d {domainname} -t std"
        return execute_os_command(command)
    except Exception as e:
        return f"Error performing subdomain enumeration: {str(e)}"

### bruteforce subdomains using dnsrecon and custom wordlist
@mcp.tool()
async def bruteforce_subdomains(domainname: str) -> str:
    """
    Bruteforce subdomains using dnsrecon and custom wordlist.
    :param domainname: domain to bruteforce subdomains for
    :type domainname: str
    :return: bruteforce results
    """
    try:
        # Check if wordlist exists
        if not os.path.exists('dns-wordlist.txt'):
            return "Error: dns-wordlist.txt not found in current directory. Please ensure it's available."
        
        # Use dnsrecon instead of direct DNS resolution
        command = f"dnsrecon -d {domainname} -t brt -D dns-wordlist.txt"
        results = execute_os_command(command)
        
        return f"""
Subdomain Bruteforce Results:
----------------------------
{results}

Note: This bruteforce attempt used the custom wordlist 'dns-wordlist.txt'.
Any discovered subdomains should be verified and further enumerated.
"""
    except Exception as e:
        return f"Error performing subdomain bruteforce: {str(e)}"

### perform DNS record enumeration
@mcp.tool()
async def enumerate_dns_records(domainname: str) -> str:
    """
    Enumerate various DNS record types for the target domain.
    :param domainname: domain to enumerate DNS records for
    :type domainname: str
    :return: DNS record enumeration results
    """
    record_types = ['A', 'AAAA', 'MX', 'NS', 'SOA', 'TXT', 'SRV']
    results = []
    for record_type in record_types:
        command = f"dig {domainname} {record_type}"
        results.append(execute_os_command(command))
    return "\n\n".join(results)

### perform HTTP headers analysis
@mcp.tool()
async def analyze_http_headers(domainname: str) -> str:
    """
    Analyze HTTP headers of the target domain.
    :param domainname: domain to analyze HTTP headers for
    :type domainname: str
    :return: HTTP headers analysis results
    """
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(f"https://{domainname}")
            headers = response.headers
            return "\n".join([f"{k}: {v}" for k, v in headers.items()])
        except Exception as e:
            return f"Error analyzing HTTP headers: {str(e)}"

### check email security
@mcp.tool()
async def check_email_security(domainname: str) -> str:
    """
    Check email security configuration
    :param domainname: domain to check email security for
    :type domainname: str
    :return: email security analysis results
    """
    email_checks = []
    
    # Check SPF record
    try:
        spf_command = f'dig +short {domainname} TXT | grep "v=spf1"'
        spf_result = execute_os_command(spf_command)
        if spf_result:
            email_checks.append(f"SPF Record found: {spf_result}")
        else:
            email_checks.append("Warning: No SPF record found")
    except Exception as e:
        email_checks.append(f"Error checking SPF: {str(e)}")

    # Check DMARC record
    try:
        dmarc_command = f'dig +short _dmarc.{domainname} TXT | grep "v=DMARC1"'
        dmarc_result = execute_os_command(dmarc_command)
        if dmarc_result:
            email_checks.append(f"DMARC Record found: {dmarc_result}")
        else:
            email_checks.append("Warning: No DMARC record found")
    except Exception as e:
        email_checks.append(f"Error checking DMARC: {str(e)}")

    # Check DKIM record
    try:
        dkim_command = f'dig +short default._domainkey.{domainname} TXT'
        dkim_result = execute_os_command(dkim_command)
        if dkim_result:
            email_checks.append(f"DKIM Record found: {dkim_result}")
        else:
            email_checks.append("Warning: No DKIM record found")
    except Exception as e:
        email_checks.append(f"Error checking DKIM: {str(e)}")

    return "\n\n".join(email_checks)

if __name__ == "__main__":
    # Initialise and run the server
    mcp.run(transport='stdio')
