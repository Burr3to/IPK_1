namespace Project1_Omega;

public static class Utils
{
	public static IPAddress GetLocalIpFromDevice(ICaptureDevice device, AddressFamily addressFamily)
	{
		try
		{
			foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
			{
				//Console.WriteLine($"Checking interface: {ni.Name}, Operational Status: {ni.OperationalStatus}, Description: {ni.Description}");
				// Check if the MAC address matches
				if (ni.GetPhysicalAddress().Equals(device.MacAddress))
				{
					foreach (UnicastIPAddressInformation ipInfo in ni.GetIPProperties().UnicastAddresses)
					{
						//Console.WriteLine($"  IP Address: {ipInfo.Address}, Address Family: {ipInfo.Address.AddressFamily}");
						if (ipInfo.Address.AddressFamily == addressFamily)
						{
							//Console.WriteLine($"  Matching IP found: {ipInfo.Address}");
							return ipInfo.Address;
						}
					}
				}
			}

			Console.WriteLine("No matching IP address found.");
			throw new Exception();
		}
		catch (Exception ex)
		{
			Console.WriteLine($"Error: {ex.Message}");
			throw;
		}
	}


	public static PhysicalAddress GetMacAddressFromDevice(ICaptureDevice device)
	{
		if (device == null)
		{
			throw new ArgumentNullException(nameof(device));
		}

		PhysicalAddress deviceMac = device.MacAddress;

		// Find the network interface with the matching MAC address
		foreach (var netInterface in NetworkInterface.GetAllNetworkInterfaces())
		{
			if (netInterface.GetPhysicalAddress().Equals(deviceMac))
			{
				return netInterface.GetPhysicalAddress();
			}
		}

		throw new Exception("Could not determine MAC address.");
	}

	public static IPAddress ResolveDomain(string hostname)
	{
		var addresses = Dns.GetHostAddresses(hostname);
		return addresses.Length > 0 ? addresses[0] : throw new Exception("Domain resolution failed.");
	}

	private static bool IsLocalNetwork(IPAddress ipAddress)
	{
		foreach (var netInterface in NetworkInterface.GetAllNetworkInterfaces())
		{
			foreach (var unicast in netInterface.GetIPProperties().UnicastAddresses)
			{
				if (unicast.Address.AddressFamily == ipAddress.AddressFamily)
				{
					byte[] ipBytes = ipAddress.GetAddressBytes();
					byte[] localIpBytes = unicast.Address.GetAddressBytes();
					byte[] subnetMaskBytes = unicast.IPv4Mask?.GetAddressBytes();

					if (subnetMaskBytes != null)
					{
						bool isLocal = true;
						for (int i = 0; i < ipBytes.Length; i++)
						{
							if ((ipBytes[i] & subnetMaskBytes[i]) != (localIpBytes[i] & subnetMaskBytes[i]))
							{
								isLocal = false;
								break;
							}
						}

						if (isLocal)
							return true;
					}
				}
			}
		}

		return false;
	}

	public static PhysicalAddress GetDestinationMac(IPAddress targetIp)
	{
		if (IsLocalNetwork(targetIp))
		{
			var mac = GetMacFromArpTable(targetIp);
			if (mac != null)
			{
				Console.WriteLine($"[DEBUG] Found MAC for local target {targetIp}: {mac}");
				return mac;
			}
		}

		// If it's not local, we need the default gateway's MAC
		var gatewayMac = GetGatewayMacAddress();
		if (gatewayMac != null)
		{
			Console.WriteLine($"[DEBUG] Using Gateway MAC for {targetIp}: {gatewayMac}");
			return gatewayMac;
		}

		// If we still fail, return a clear error instead of FF:FF:FF:FF:FF:FF
		throw new Exception($"Could not determine destination MAC for {targetIp}");
	}

	private static PhysicalAddress? GetGatewayMacAddress()
	{
		foreach (var netInterface in NetworkInterface.GetAllNetworkInterfaces())
		{
			foreach (var gateway in netInterface.GetIPProperties().GatewayAddresses)
			{
				var mac = GetMacFromArpTable(gateway.Address);
				if (mac != null)
					return mac;
			}
		}

		return null;
	}

	private static PhysicalAddress? GetMacFromArpTable(IPAddress ipAddress)
	{
		ProcessStartInfo psi = new ProcessStartInfo
		{
			FileName = "arp",
			Arguments = "-a",
			RedirectStandardOutput = true,
			UseShellExecute = false,
			CreateNoWindow = true
		};

		using (Process process = Process.Start(psi))
		using (StreamReader reader = process.StandardOutput)
		{
			string output = reader.ReadToEnd();
			string[] lines = output.Split('\n');

			foreach (string line in lines)
			{
				if (line.Contains(ipAddress.ToString()))
				{
					string[] parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
					if (parts.Length >= 2)
					{
						return PhysicalAddress.Parse(parts[1].Replace("-", ":"));
					}
				}
			}
		}

		return null; // MAC not found
	}
}