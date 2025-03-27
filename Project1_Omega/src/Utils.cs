namespace Project1_Omega;

public static class Utils
{
	// Flags enum for representing TCP flags and options.
	[Flags]
	public enum Flags : byte
	{
		Nul = 0x00,
		Syn = 0x02,
		Rst = 0x04,
		Ack = 0x10,
		SynAck = Syn | Ack, // 0x12

		MssKind = 0x02, // MSS option kind
		MssLength = 0x04, // MSS option length (should always be 4)
	}

	// Enum for representing the result of a port scan.
	public enum ScanResult
	{
		open,
		closed,
		filtered,
		Unknown
	}

	// Retrieves the local IP address for a given network interface and address family.
	public static IPAddress GetLocalIpFromDevice(string interfaceName, AddressFamily addressFamily)
	{
		if (string.IsNullOrEmpty(interfaceName))
			throw new Exception($"[GetLocalIpFromDevice] {interfaceName} is null or Empty");

		try
		{
			foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
			{
				if (ni.Name.Equals(interfaceName, StringComparison.OrdinalIgnoreCase))
				{
					foreach (UnicastIPAddressInformation ipInfo in ni.GetIPProperties().UnicastAddresses)
					{
						if (ipInfo.Address.AddressFamily == addressFamily)
						{
							return ipInfo.Address;
						}
					}
				}
			}

			throw new Exception($"No matching IP address found for interface: {interfaceName}");
		}
		catch (Exception ex)
		{
			Console.WriteLine($"Error: {ex.Message}");
			throw;
		}
	}

	// Resolves a domain name to an array of IP addresses.
	public static IPAddress[] ResolveDomain(string hostname)
	{
		try
		{
			return Dns.GetHostAddresses(hostname);
		}
		catch (Exception)
		{
			throw new Exception($"Domain resolution failed for {hostname}.");
		}
	}

	// Computes the 16-bit checksum of a byte array.
	public static ushort ComputeChecksum(byte[] buffer)
	{
		uint checksum = 0;
		for (int i = 0; i < buffer.Length; i += 2)
		{
			if (i + 1 < buffer.Length)
			{
				checksum += (ushort)((buffer[i] << 8) | buffer[i + 1]);
			}
			else
			{
				checksum += (ushort)(buffer[i] << 8);
			}
		}

		checksum = (checksum >> 16) + (checksum & 0xFFFF);
		checksum += (checksum >> 16);
		ushort finalChecksum = (ushort)(~checksum);
		return finalChecksum;
	}
}