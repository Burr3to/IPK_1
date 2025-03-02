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

	public static PhysicalAddress GetDestinationMac(IPAddress targetIp, ICaptureDevice device)
	{
		if (IsLocalNetwork(targetIp))
		{
			PhysicalAddress mac = GetMacFromArpRequest(targetIp, device);
			if (mac != null)
			{
				Console.WriteLine($"[DEBUG] Found MAC for local target {targetIp}: {mac}");
				return mac;
			}
		}

		// If it's not local, we need the default gateway's MAC
		PhysicalAddress gatewayMac = GetGatewayMacAddress(device);
		if (gatewayMac != null)
		{
			Console.WriteLine($"[DEBUG] Using Gateway MAC for {targetIp}: {gatewayMac}");
			return gatewayMac;
		}

		// If we still fail, return a clear error instead of FF:FF:FF:FF:FF:FF
		throw new Exception($"Could not determine destination MAC for {targetIp}");
	}

	public static PhysicalAddress? GetGatewayMacAddress(ICaptureDevice device)
	{
		foreach (var netInterface in NetworkInterface.GetAllNetworkInterfaces())
		{
			foreach (var gateway in netInterface.GetIPProperties().GatewayAddresses)
			{
				PhysicalAddress mac = GetMacFromArpRequest(gateway.Address, device);
				Console.WriteLine("GATEWAY REQ > " + mac);
				if (mac != null)
					return mac;
			}
		}

		return null;
	}

	public static PhysicalAddress? GetMacFromArpRequest(IPAddress targetIp, ICaptureDevice device)
	{
		// Ensure the target IP is on the local network
		if (!IsLocalNetwork(targetIp))
		{
			Console.WriteLine($"[ARP] {targetIp} is not on the local network. ARP only works for local hosts.");
			return null;
		}

		// Get the local IP and MAC addresses using your helper functions
		IPAddress localIp = GetLocalIpFromDevice(device, AddressFamily.InterNetwork);
		Console.WriteLine("local ip>" + localIp);
		PhysicalAddress localMac = GetMacAddressFromDevice(device);

		if (localIp == null || localMac == null)
		{
			Console.WriteLine("[ARP] Could not determine local IP or MAC address.");
			return null;
		}

		byte[] packet = new byte[42];

		//Dest MAC broadcast address FF:FF:FF:FF:FF:FF
		for (int i = 0; i < 6; i++)
			packet[i] = 0xFF;


		//Source MAC 6bytes
		byte[] localMacBytes = localMac.GetAddressBytes();
		Array.Copy(localMacBytes, 0, packet, 6, 6);

		//Ethernet type 0x0806
		packet[12] = 0x08;
		packet[13] = 0x06;

		//arp paylod
		//hardware type
		packet[14] = 0x00;
		packet[15] = 0x01;

		//protocol type ipv4
		packet[16] = 0x08;
		packet[17] = 0x00;

		//hardware addres lengtg 6, protocal size 4
		packet[18] = 0x06;
		packet[19] = 0x04;

		//OpCod for ARP, request = 1
		packet[20] = 0x00;
		packet[21] = 0x01;

		//sender MAC address (local) 6Bytes
		Array.Copy(localMacBytes, 0, packet, 22, 6);
		//sender IP address (local) 4Bytes
		byte[] localIpBytes = localIp.GetAddressBytes();
		Array.Copy(localIpBytes, 0, packet, 28, 4);

		//32 start
		//target MAC, unknown > 00:00 ...  6Bytes
		for (int i = 0; i < 6; i++)
			packet[i + 32] = 0x00;

		//target ip address, 4Bytes
		byte[] targetIpBytes = targetIp.GetAddressBytes();
		Array.Copy(targetIpBytes, 0, packet, 38, 4);

		PhysicalAddress? targetMac = null;
		object lockObject = new object();

		// Event handler for packet arrival
		void device_OnPacketArrival(object sender, SharpPcap.PacketCapture e)
		{
			var rawPacket = e.GetPacket();
			byte[] data = rawPacket.Data;

			// packet length >= Ethernet+ARP packet
			if (data.Length >= 42 &&
			    data[12] == 0x08 && data[13] == 0x06 && //EthetType field if its arp packet
			    data[20] == 0x00 && data[21] == 0x02 && //ARP Reply code 0x0002
			    data[28] == targetIpBytes[0] && data[29] == targetIpBytes[1] && //verify targetIp bytes
			    data[30] == targetIpBytes[2] && data[31] == targetIpBytes[3])
			{
				Console.WriteLine("contions for arp met");
				// Extract the sender MAC address from the ARP reply (bytes 22-27)
				byte[] macBytes = new byte[6];
				Array.Copy(data, 22, macBytes, 0, 6);
				lock (lockObject) //prevents parrarel writing to variable (inconsistencies)
				{
					targetMac = new PhysicalAddress(macBytes);
				}
			}
		}

		//for each new packet recieved call my own OnPacketArrival
		device.OnPacketArrival += new SharpPcap.PacketArrivalEventHandler(device_OnPacketArrival);

		device.Open(DeviceModes.Promiscuous, 1000);

		device.StartCapture();

		if (device is ILiveDevice liveDevice)
			liveDevice.SendPacket(packet);
		else
			Console.Error.WriteLine("[ARP] Device does not support packet injection.");

		int timeout = 3000;
		DateTime start = DateTime.Now;
		while ((DateTime.Now - start).TotalMilliseconds < timeout)
		{
			lock (lockObject)
			{
				if (targetMac != null)
					break;
			}

			System.Threading.Thread.Sleep(50);
		}

		device.StopCapture();
		device.OnPacketArrival -= new SharpPcap.PacketArrivalEventHandler(device_OnPacketArrival);

		if (targetMac == null)
			throw new InvalidOperationException($"[ARP] No ARP reply received for {targetIp}.");
		return targetMac;
	}
}