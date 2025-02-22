using System;
using Project1_Omega.Scanners;
using SharpPcap;

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

		// Perform TCP Scans
		if (parser.DomainOrIp != null && parser.TcpPorts.Count > 0)
		{
			TcpScanner tcpScanner = new TcpScanner(parser.DomainOrIp, parser.TcpPorts, parser.Timeout);
			await tcpScanner.ScanTcpAsync(); // Runs the TCP scan
		}
	}
}