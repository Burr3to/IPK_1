using Project1_Omega.Arguments;
using Project1_Omega.Scanners;

namespace Project1_Omega;

class Program
{
	static async Task Main(string[] args)
	{
		var parser = new CommandLineParser(args);

		// Ensure the user provided a domain or IP to scan
		if (parser.DomainOrIp == null)
			return;
		IPAddress[] targetIps;

		// Resolve target (domain name → IP addresses)
		if (IPAddress.TryParse(parser.DomainOrIp, out IPAddress singleIp))
			targetIps = new IPAddress[] { singleIp };
		else
		{
			try
			{
				targetIps = Utils.ResolveDomain(parser.DomainOrIp);
			}
			catch (Exception e)
			{
				Console.WriteLine($"Error: Could not resolve target {parser.DomainOrIp}. {e.Message}");
				return;
			}
		}

		// Create a list to hold the scanning tasks
		var scanTasks = new List<Task>();

		// Perform scan for each resolved IP address asynchronously
		foreach (var targetIp in targetIps)
		{
			// Perform TCP Scan asynchronously
			if (parser.TcpPorts.Count > 0)
			{
				TcpScanner tcpScanner = new TcpScanner(targetIp.ToString(), parser.TcpPorts, parser.Timeout, parser.Interface);
				scanTasks.Add(tcpScanner.ScanTcpAsync());
			}

			// Perform UDP Scan asynchronously
			if (parser.UdpPorts.Count > 0)
			{
				UdpScanner udpScanner = new UdpScanner(targetIp.ToString(), parser.UdpPorts, parser.Timeout, parser.Interface);
				scanTasks.Add(udpScanner.ScanUdpAsync());
			}
		}

		// Wait for all scanning tasks to complete
		await Task.WhenAll(scanTasks);
	}
}