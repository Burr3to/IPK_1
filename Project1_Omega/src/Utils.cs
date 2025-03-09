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

	public static ICaptureDevice? GetNetworkInterface(string _interfaceName)
	{
		var devices = CaptureDeviceList.Instance;
		if (devices.Count < 1)
		{
			Console.Error.WriteLine("[ScanTcpPort] No network interfaces found. Exiting.");
			return null;
		}


		ICaptureDevice? device = null;
		if (!string.IsNullOrEmpty(_interfaceName))
		{
			device = devices.FirstOrDefault(d =>
				d.Name.Contains(_interfaceName, StringComparison.OrdinalIgnoreCase)
				|| d.Description.Contains(_interfaceName, StringComparison.OrdinalIgnoreCase));


			if (device == null)
			{
				Console.Error.WriteLine($"[ScanTcpPort] Error: Specified interface '{_interfaceName}' not found.");
				return null;
			}
		}
		else
		{
			Console.WriteLine("Available Interfaces:");
			foreach (var dev in devices)
			{
				Console.WriteLine($"  - {dev.Name} ({dev.Description})");
			}

			return null;
		}

		return device;
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
}