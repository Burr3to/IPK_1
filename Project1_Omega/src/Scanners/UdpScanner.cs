using static Project1_Omega.Utils;

namespace Project1_Omega.Scanners
{
	public class UdpScanner
	{
		// Target IP, UDP ports, timeout, and optional interface.
		private readonly string _targetIp;
		private readonly List<int> _udpPorts;
		private readonly int _timeout;
		private readonly string? _interfaceName;

		// Initializes UdpScanner with target, ports, timeout, and interface.
		public UdpScanner(string targetIp, List<int> udpPorts, int timeout, string? interfaceName = null)
		{
			_targetIp = targetIp;
			_udpPorts = udpPorts;
			_timeout = timeout;
			_interfaceName = interfaceName;
		}

		// Starts asynchronous UDP port scanning for all target ports.
		public async Task ScanUdpAsync()
		{
			List<Task> scanTasks = new();
			foreach (var port in _udpPorts)
				scanTasks.Add(Task.Run(() => ScanUdpPort(port)));

			await Task.WhenAll(scanTasks);
		}

		// Scans a single UDP port by calling the appropriate IPv4 or IPv6 specific scanning method.
		private void ScanUdpPort(int port)
		{
			try
			{
				IPAddress targetIpAddress = IPAddress.Parse(_targetIp);
				if (targetIpAddress.AddressFamily == AddressFamily.InterNetwork)
					ScanUdpPortIPv4(port, targetIpAddress);
				else if (targetIpAddress.AddressFamily == AddressFamily.InterNetworkV6)
					ScanUdpPortIPv6(port, targetIpAddress);
			}
			catch (Exception ex)
			{
				Console.Error.WriteLine($"[ERROR] Error scanning UDP port {port}: {ex.Message}");
				throw;
			}
		}

		// Processes ICMP responses to determine the status of a UDP port.
		private ScanResult ProcessUdpResponse(IPAddress localIp, IPAddress targetIp, int targetPort)
		{
			ScanResult result = ScanResult.open; // Assume open initially.
			AddressFamily icmpFam = targetIp.AddressFamily;
			// Determine the ICMP protocol type based on target IP family
			ProtocolType icmpProtocol = (icmpFam == AddressFamily.InterNetworkV6) ? ProtocolType.IcmpV6 : ProtocolType.Icmp;

			// Create a raw ICMP socket for receiving ICMP error messages.
			using Socket socket = new Socket(icmpFam, SocketType.Raw, icmpProtocol);
			try
			{
				socket.Bind(new IPEndPoint(localIp, 0));
				socket.ReceiveTimeout = _timeout;

				byte[] buffer = new byte[4096];
				DateTime start = DateTime.Now;

				// Listen for ICMP responses within the timeout period.
				while ((DateTime.Now - start).TotalMilliseconds < _timeout)
				{
					try
					{
						EndPoint remoteEp = new IPEndPoint(IPAddress.Any, 0);
						// Receiving packets
						int received = socket.ReceiveFrom(buffer, ref remoteEp);

						ScanResult? scanResult = null;
						// Processing packets
						if (targetIp.AddressFamily == AddressFamily.InterNetwork)
							scanResult = ProcessUdpIpv4Response(targetPort, buffer, received, targetIp, localIp);
						else if (targetIp.AddressFamily == AddressFamily.InterNetworkV6)
							scanResult = ProcessUdpIpv6Response(targetPort, buffer, received, targetIp, localIp);

						// If a valid scan result return
						if (scanResult.HasValue)
							return scanResult.Value;
					}
					catch (SocketException ex)
					{
						// If a timeout occurs break
						if (ex.SocketErrorCode == SocketError.TimedOut)
						{
							break;
						}

						// Other socket errors break
						break;
					}
				}
			}
			catch (SocketException ex)
			{
				Console.WriteLine($"[SocketException] Error creating or binding ICMP socket: {ex.Message}");
				throw;
			}

			// no ICMP port unreachable was received > port assumed open
			return result;
		}


		// IPv4 scanning
		private void ScanUdpPortIPv4(int port, IPAddress targetIpAddress)
		{
			// Create raw IPv4 socket.
			using (Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Raw))
			{
				IPEndPoint remoteEndPoint = new IPEndPoint(targetIpAddress, port);
				IPAddress localIp = Utils.GetLocalIpFromDevice(_interfaceName, AddressFamily.InterNetwork);
				ushort sourcePort = (ushort)new Random().Next(1024, 65535);

				// Build and send UDP packet.
				byte[] packet = BuildUdpIpv4Packet(localIp, targetIpAddress, port, sourcePort);
				socket.SendTo(packet, remoteEndPoint);
				socket.ReceiveTimeout = _timeout;

				// Process ICMP response.
				ScanResult result = ProcessUdpResponse(localIp, targetIpAddress, port);
				Console.WriteLine($"{targetIpAddress} {port} udp {result}");

				socket.Close();
			}
		}

		// Helper: Process IPv4 ICMP response for UDP scan.
		private ScanResult? ProcessUdpIpv4Response(int originalTargetPort, byte[] buffer, int received, IPAddress targetIp, IPAddress localIp)
		{
			if (received < 36) // Minimum ICMP + IP + UDP header size.
				return null;
			if (buffer[0] != 0x45 || buffer[9] != 0x01) // Check IPv4 and ICMP.
				return null;

			// Check for Destination Unreachable, Port Unreachable.
			if (buffer[20] != 3 || buffer[21] != 3)
				return null;

			int ipHeaderOffset = 28; // Offset to original IP header.
			int ipHeaderLengthBytes = (buffer[ipHeaderOffset] & 0x0F) * 4;
			int headerLengthBytes = ipHeaderOffset + ipHeaderLengthBytes;

			if (received < headerLengthBytes + 8) // Ensure enough data for UDP header.
				return null;

			// Extract reported destination port.
			ushort reportedPort = (ushort)((buffer[headerLengthBytes + 2] << 8) | buffer[headerLengthBytes + 3]);

			// Extract reported target and source IPs.
			byte[] reportedTargetIpBytes = new byte[4];
			Array.Copy(buffer, ipHeaderOffset + 16, reportedTargetIpBytes, 0, 4);
			IPAddress reportedTargetIp = new IPAddress(reportedTargetIpBytes);

			byte[] reportedSourceIpBytes = new byte[4];
			Array.Copy(buffer, ipHeaderOffset + 12, reportedSourceIpBytes, 0, 4);
			IPAddress reportedSourceIp = new IPAddress(reportedSourceIpBytes);

			// Check if the ICMP error is for our sent UDP packet.
			if (reportedPort == originalTargetPort && reportedTargetIp.Equals(targetIp) && reportedSourceIp.Equals(localIp))
				return ScanResult.closed;

			return null;
		}

		// Builds a raw IPv4 UDP packet.
		private byte[] BuildUdpIpv4Packet(IPAddress localIp, IPAddress targetIp, int destPort, ushort sourcePort)
		{
			byte[] udpData = { };

			// UDP Header (8 bytes)
			byte[] udpHeader = new byte[8];
			udpHeader[0] = (byte)(sourcePort >> 8); // Source Port
			udpHeader[1] = (byte)(sourcePort & 0xFF);
			udpHeader[2] = (byte)(destPort >> 8); // Destination Port
			udpHeader[3] = (byte)(destPort & 0xFF);
			ushort udpLength = (ushort)(udpHeader.Length + udpData.Length);
			udpHeader[4] = (byte)(udpLength >> 8); // Length
			udpHeader[5] = (byte)(udpLength & 0xFF);
			udpHeader[6] = 0; // Checksum (initially zero)
			udpHeader[7] = 0;

			// IPv4 Header (20 bytes)
			byte[] ipHeader = new byte[20];
			ipHeader[0] = 0x45; // Version 4, IHL 5
			ipHeader[1] = 0x00; // DSCP, ECN
			ushort totalLength = (ushort)(ipHeader.Length + udpHeader.Length + udpData.Length);
			ipHeader[2] = (byte)(totalLength >> 8); // Total Length
			ipHeader[3] = (byte)(totalLength & 0xFF);
			ushort identification = (ushort)new Random().Next(0, ushort.MaxValue);
			ipHeader[4] = (byte)(identification >> 8); // Identification
			ipHeader[5] = (byte)(identification & 0xFF);
			ipHeader[6] = 0x00; // Flags, Fragment Offset
			ipHeader[7] = 0x00;
			ipHeader[8] = 0x40; // TTL
			ipHeader[9] = 0x11; // Protocol (UDP)
			ipHeader[10] = 0x00; // Header Checksum (initially zero)
			ipHeader[11] = 0x00;

			localIp.GetAddressBytes().CopyTo(ipHeader, 12); // Source IP
			targetIp.GetAddressBytes().CopyTo(ipHeader, 16); // Destination IP

			// Calculate IPv4 Header Checksum
			ushort checksum = ComputeChecksum(ipHeader);
			ipHeader[10] = (byte)(checksum >> 8);
			ipHeader[11] = (byte)(checksum & 0xFF);

			// Combine headers and data
			byte[] packet = new byte[ipHeader.Length + udpHeader.Length + udpData.Length];
			ipHeader.CopyTo(packet, 0);
			udpHeader.CopyTo(packet, ipHeader.Length);
			udpData.CopyTo(packet, ipHeader.Length + udpHeader.Length);

			return packet;
		}


		// IPv6 scanning
		private void ScanUdpPortIPv6(int port, IPAddress targetIpAddress)
		{
			// Create raw UDP socket for IPv6.
			using (Socket socket = new Socket(AddressFamily.InterNetworkV6, SocketType.Raw, ProtocolType.Udp))
			{
				IPEndPoint remoteEndPoint = new IPEndPoint(targetIpAddress, 0);
				IPAddress localIp = Utils.GetLocalIpFromDevice(_interfaceName, AddressFamily.InterNetworkV6);
				ushort sourcePort = (ushort)new Random().Next(1024, 65535);

				// Build UDP segment and calculate IPv6 checksum.
				byte[] udpSegment = BuildUdpSegment(sourcePort, port);
				ushort checksum = ComputeUdpChecksumIPv6(localIp, targetIpAddress, udpSegment);
				udpSegment[6] = (byte)(checksum >> 8);
				udpSegment[7] = (byte)(checksum & 0xFF);
				byte[] packet = udpSegment;

				// Send the UDP packet.
				try
				{
					socket.SendTo(packet, remoteEndPoint);
				}
				catch (SocketException ex)
				{
					Console.Error.WriteLine($"[ERROR] ScanUdpPortIPv6 - SocketException during SendTo to {remoteEndPoint}:");
					Console.Error.WriteLine($"[ERROR] ScanUdpPortIPv6Message: {ex.Message}");
					throw;
				}

				socket.ReceiveTimeout = _timeout;

				// Process ICMPv6 response.
				ScanResult result = ProcessUdpResponse(localIp, targetIpAddress, port);
				Console.WriteLine($"{targetIpAddress} {port} udp {result}");

				socket.Close();
			}
		}

		// Helper: Process IPv6 ICMPv6 response for UDP scan.
		private ScanResult ProcessUdpIpv6Response(int originalTargetPort, byte[] buffer, int received, IPAddress targetIp, IPAddress sourceIp)
		{
			if (received < 56) // Minimum ICMPv6 + IPv6 + UDP header size.
				return ScanResult.open;

			// Check for Type 1 (Destination Unreachable) and Code 4 (Port Unreachable).
			if (!(buffer[0] == 1 && buffer[1] == 4))
				return ScanResult.open;

			int udpHOffset = 48; // Offset.

			// Extract the reported destination port.
			ushort reportedPort = (ushort)((buffer[udpHOffset + 2] << 8) | buffer[udpHOffset + 3]);

			// Extract the reported source and target IPs from the ICMPv6 message.
			byte[] repSourceIpBytes = new byte[16];
			Array.Copy(buffer, 16, repSourceIpBytes, 0, 16);
			IPAddress repSourceIp = new IPAddress(repSourceIpBytes);
			byte[] repTargetIpBytes = new byte[16];
			Array.Copy(buffer, 32, repTargetIpBytes, 0, 16);
			IPAddress repTargetIp = new IPAddress(repTargetIpBytes);

			// Check if the ICMPv6 error is for our sent UDP packet.
			if (reportedPort == originalTargetPort && repTargetIp.Equals(targetIp) && repSourceIp.Equals(sourceIp))
				return ScanResult.closed;

			return ScanResult.open; // Assume open if no response
		}

		// Builds a UDP segment
		private byte[] BuildUdpSegment(int sourcePort, int targetPort)
		{
			byte[] udpSegment = new byte[12]; // 8-byte header + 4-byte data
			byte byteMax = 0xFF;

			// Source port (2 bytes)
			udpSegment[0] = (byte)(sourcePort >> 8);
			udpSegment[1] = (byte)(sourcePort & byteMax);

			// Destination port (2 bytes)
			udpSegment[2] = (byte)(targetPort >> 8);
			udpSegment[3] = (byte)(targetPort & byteMax);

			// Length (2 bytes): Header (8) + Data (4) = 12
			ushort length = 12;
			udpSegment[4] = (byte)(length >> 8);
			udpSegment[5] = (byte)(length & byteMax);

			// Checksum (2 bytes) - will be calculated later
			udpSegment[6] = 0x00;
			udpSegment[7] = 0x00;

			// Data (4 bytes of null)
			udpSegment[8] = 0x00;
			udpSegment[9] = 0x00;
			udpSegment[10] = 0x00;
			udpSegment[11] = 0x00;

			return udpSegment;
		}

		// Computes the UDP checksum for IPv6 packets.
		private ushort ComputeUdpChecksumIPv6(IPAddress src, IPAddress dst, byte[] udpSegment)
		{
			byte[] srcBytes = src.GetAddressBytes();
			byte[] dstBytes = dst.GetAddressBytes();
			int udpLength = udpSegment.Length;

			// Build IPv6 pseudo-header (40 bytes).
			byte[] pseudoHeader = new byte[40];
			srcBytes.CopyTo(pseudoHeader, 0); // Source IP
			dstBytes.CopyTo(pseudoHeader, 16); // Destination IP
			pseudoHeader[32] = (byte)(udpLength >> 24); // UDP Length (network byte order)
			pseudoHeader[33] = (byte)(udpLength >> 16);
			pseudoHeader[34] = (byte)(udpLength >> 8);
			pseudoHeader[35] = (byte)(udpLength);
			pseudoHeader[39] = 17; // Next Header (UDP = 17)

			// Combine pseudo-header and UDP segment.
			byte[] checksumBuffer = new byte[pseudoHeader.Length + udpSegment.Length];
			pseudoHeader.CopyTo(checksumBuffer, 0);
			udpSegment.CopyTo(checksumBuffer, pseudoHeader.Length);

			// Pad with zero if the total length is odd.
			if (checksumBuffer.Length % 2 != 0)
			{
				Array.Resize(ref checksumBuffer, checksumBuffer.Length + 1);
			}

			// Calculate the checksum.
			return ComputeChecksum(checksumBuffer);
		}
	}
}