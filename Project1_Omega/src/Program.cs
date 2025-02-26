using System;
using Project1_Omega.Scanners;
using SharpPcap;
using System.Net;

namespace Project1_Omega;

class Program
{
	static async Task Main(string[] args)
	{
		/*
		 * TCP SYN Scan (Stealth Scan)	nmap -sS -p 21 localhost      -i eth0 --pt 21 localhost
		 * TCP Connect Scan (HandShake) nmap -sT -p 21 localhost      -i eth0 --pt 21 localhost
		 * UDP Scan						nmap -sU -p 53 localhost      -i eth0 --pu 53 localhost
		 * TCP/UDP Combined Scan		nmap -sS -sU -p 21,22,143,53,67 localhost	-i eth0 --pt 21,22,143 --pu 53,67 localhost
		 * cmd > netstat -ano | findstr LISTENING
		 */


		var parser = new CommandLineParser(args);

		Console.WriteLine("Interface: " + (parser.Interface ?? "None"));
		Console.WriteLine("Timeout: " + parser.Timeout);
		Console.WriteLine("TCP Ports: " + (parser.TcpPorts.Count > 0 ? string.Join(",", parser.TcpPorts) : "None"));
		Console.WriteLine("UDP Ports: " + (parser.UdpPorts.Count > 0 ? string.Join(",", parser.UdpPorts) : "None"));
		Console.WriteLine("Domain/IP: " + (parser.DomainOrIp ?? "None"));

		// Ensure the user provided a domain or IP to scan
		if (parser.DomainOrIp == null)
		{
			Console.WriteLine("Error: No target domain or IP address provided.");
			return;
		}

		// Resolve target (domain name → IP address)
		IPAddress? targetIp;
		try
		{
			targetIp = IPAddress.TryParse(parser.DomainOrIp, out IPAddress parsedIp)
				? parsedIp : Utils.ResolveDomain(parser.DomainOrIp);
		}
		catch (Exception e)
		{
			Console.WriteLine($"Error: Could not resolve target {parser.DomainOrIp}. {e.Message}");
			return;
		}

		// Perform TCP Scan
		if (parser.TcpPorts.Count > 0)
		{
			TcpScanner tcpScanner =
				new TcpScanner(targetIp.ToString(), parser.TcpPorts, parser.Timeout, parser.Interface);
			await tcpScanner.ScanTcpAsync();
		}
	}
}