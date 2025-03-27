using static Project1_Omega.Utils;

namespace Project1_Omega.Scanners
{
	public class TcpScanner
	{
		// Target IP, TCP ports, timeout, and optional interface.
		private readonly string _targetIp;
		private readonly List<int> _tcpPorts;
		private readonly int _timeout;
		private readonly string? _interfaceName;

		// Initializes TcpScanner with target, ports, timeout, and interface.
		public TcpScanner(string targetIp, List<int> tcpPorts, int timeout, string? interfaceName = null)
		{
			_targetIp = targetIp;
			_tcpPorts = tcpPorts;
			_timeout = timeout;
			_interfaceName = interfaceName;
		}

		// Starts asynchronous TCP port scanning for all target ports.
		public async Task ScanTcpAsync()
		{
			List<Task> scanTasks = new();
			foreach (var port in _tcpPorts)
				scanTasks.Add(Task.Run(() => ScanTcpPort(port)));
			await Task.WhenAll(scanTasks);
		}

		// Scans a single TCP port.
		private void ScanTcpPort(int port)
		{
			IPAddress targetIp = IPAddress.Parse(_targetIp);
			AddressFamily addressFamily = targetIp.AddressFamily;

			// Create a raw socket based on the address family.
			using Socket rawSocket = addressFamily == AddressFamily.InterNetworkV6
				? CreateRawTcpSocketIPv6(_timeout)
				: CreateRawSocket(AddressFamily.InterNetwork, _timeout);

			// Include header if working with IPv4
			if (addressFamily == AddressFamily.InterNetwork)
				rawSocket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);

			Random rand = new Random();
			int sentSourcePort = rand.Next(1025, 63636);

			byte[] packet;
			if (addressFamily == AddressFamily.InterNetworkV6)
			{
				packet = BuildTcpSynSegment(sentSourcePort, port);
				IPAddress localIp = Utils.GetLocalIpFromDevice(_interfaceName, AddressFamily.InterNetworkV6);
				ushort tcpChecksum = ComputeTcpChecksumIPv6(localIp, targetIp, packet);
				packet[16] = (byte)(tcpChecksum >> 8);
				packet[17] = (byte)(tcpChecksum & 0xFF);
			}
			else
				packet = BuildIpv4TcpSynPacketRaw(targetIp, port, sentSourcePort);

			SendPacket(rawSocket, targetIp, packet);
			ScanResult result = WaitForTcpResponse(targetIp, port, sentSourcePort, _timeout);

			// Re-send SYN if no initial response.
			if (result == ScanResult.Unknown)
			{
				SendPacket(rawSocket, targetIp, packet);
				result = WaitForTcpResponse(targetIp, port, sentSourcePort, _timeout);
				if (result == ScanResult.Unknown)
					result = ScanResult.filtered;
			}

			Console.WriteLine($"{targetIp} {port} tcp {result}");
		}

		// Sends a raw packet to the specified target IP address.
		private void SendPacket(Socket socket, IPAddress targetIp, byte[] packet)
		{
			IPEndPoint endPoint = new IPEndPoint(targetIp, 0);
			socket.SendTo(packet, endPoint);
		}

		// Creates a raw socket for the specified address family and binds it to a local IP.
		private Socket CreateRawSocket(AddressFamily af, int timeoutMs)
		{
			Socket sock = new Socket(af, SocketType.Raw, ProtocolType.Raw);
			IPAddress localIp = GetLocalIpFromDevice(_interfaceName, af);
			sock.Bind(new IPEndPoint(localIp, 0));
			sock.ReceiveTimeout = timeoutMs;
			return sock;
		}

		// Creates a raw TCP socket  for IPv6.
		private Socket CreateRawTcpSocketIPv6(int timeoutMs)
		{
			Socket sock = new Socket(AddressFamily.InterNetworkV6, SocketType.Raw, ProtocolType.Tcp);
			sock.ReceiveTimeout = timeoutMs;
			return sock;
		}

		// Helper: Process an IPv4 packet response.
		private ScanResult? ProcessIPv4Response(byte[] buffer, int received, int targetPort, int sentSourcePort, IPAddress targetIp)
		{
			// IPv4 header minimum size
			if (received < 20)
				return null;

			int ipHeaderLength = (buffer[0] & 0x0F) * 4;
			if (received < ipHeaderLength + 20)
				return null;

			// IP Protocol field = TCP packet (value 6)
			if (buffer[9] != 6)
				return null;

			// Extract the IPv4 source IP (offset 12, length 4).
			byte[] srcIpBytes = new byte[4];
			Array.Copy(buffer, 12, srcIpBytes, 0, 4);
			IPAddress receivedSourceIp = new IPAddress(srcIpBytes);

			if (!receivedSourceIp.Equals(targetIp))
				return null;

			// TCP header after the IPv4 header.
			int tcpHeaderStart = ipHeaderLength;
			int tcpSourcePort = (buffer[tcpHeaderStart] << 8) | buffer[tcpHeaderStart + 1];
			int tcpDestinationPort = (buffer[tcpHeaderStart + 2] << 8) | buffer[tcpHeaderStart + 3];
			if (tcpSourcePort != targetPort || tcpDestinationPort != sentSourcePort)
				return null;

			// TCP flags at offset tcpHeaderStart + 13.
			byte tcpFlags = buffer[tcpHeaderStart + 13];
			if ((tcpFlags & (byte)Flags.Rst) != 0)
				return ScanResult.closed;
			if ((tcpFlags & (byte)Flags.SynAck) == (byte)Flags.SynAck)
				return ScanResult.open;

			return null;
		}

		// Helper: Process an IPv6 packet response.
		private ScanResult? ProcessIPv6Response(byte[] buffer, int received, int targetPort, int sentSourcePort)
		{
			if (received < 20)
				return null;

			int tcpHeaderStart = 0;

			// Extract and compare TCP source and destination ports.
			int tcpSourcePort = (buffer[tcpHeaderStart] << 8) | buffer[tcpHeaderStart + 1];
			int tcpDestinationPort = (buffer[tcpHeaderStart + 2] << 8) | buffer[tcpHeaderStart + 3];
			if (tcpSourcePort != targetPort || tcpDestinationPort != sentSourcePort)
				return null;

			// Check TCP flags for RST or SYN-ACK.
			byte tcpFlags = buffer[tcpHeaderStart + 13];
			if ((tcpFlags & (byte)Flags.Rst) != 0)
				return ScanResult.closed;
			if ((tcpFlags & (byte)Flags.SynAck) == (byte)Flags.SynAck)
				return ScanResult.open;

			return null;
		}

		// Waits for a TCP response (SYN-ACK or RST) within the specified timeout.
		private ScanResult WaitForTcpResponse(IPAddress targetIp, int targetPort, int sentSourcePort, int timeoutMs)
		{
			ScanResult result = ScanResult.Unknown;
			AddressFamily addressFamily = targetIp.AddressFamily;
			IPAddress localIp = GetLocalIpFromDevice(_interfaceName, addressFamily);

			// Creates a new raw TCP socket for the determined address family (IPv4 or IPv6).
			using Socket socket = new Socket(addressFamily, SocketType.Raw, ProtocolType.Tcp);
			try
			{
				socket.Bind(new IPEndPoint(localIp, sentSourcePort));
				socket.ReceiveTimeout = timeoutMs;

				byte[] buffer = new byte[4096];
				DateTime start = DateTime.Now;

				while ((DateTime.Now - start).TotalMilliseconds < timeoutMs)
				{
					int received;
					try
					{
						received = socket.Receive(buffer);
					}
					catch (SocketException) // Break out of the receive loop on SocketException.
					{
						break;
					}
					catch (Exception ex) // Break out of the receive loop on other exceptions.
					{
						Console.Error.WriteLine($"[Exception] Unexpected error: {ex.Message}");
						break;
					}

					ScanResult? scanResult = addressFamily == AddressFamily.InterNetwork
						? ProcessIPv4Response(buffer, received, targetPort, sentSourcePort, targetIp)
						: ProcessIPv6Response(buffer, received, targetPort, sentSourcePort);

					if (scanResult.HasValue)
					{
						result = scanResult.Value;
						break; // Exit the while loop if a valid scan result is obtained.
					}
				}
			}
			catch (SocketException ex)
			{
				Console.Error.WriteLine($"[SocketException] Error creating or binding socket: {ex.Message}");
			}

			finally
			{
				socket.Close();
			}

			return result;
		}

		// Builds a 24-byte TCP SYN segment with a 4-byte MSS option.
		private byte[] BuildTcpSynSegment(int sourcePort, int targetPort)
		{
			byte[] tcp = new byte[24];
			byte byteMax = 0xFF;

			Random rand = new Random();

			//Source port
			tcp[0] = (byte)(sourcePort >> 8);
			tcp[1] = (byte)(sourcePort & byteMax);
			//Source dest
			tcp[2] = (byte)(targetPort >> 8);
			tcp[3] = (byte)(targetPort & byteMax);
			//Seq number
			int seqNum = rand.Next();
			tcp[4] = (byte)((seqNum >> 24) & byteMax);
			tcp[5] = (byte)((seqNum >> 16) & byteMax);
			tcp[6] = (byte)((seqNum >> 8) & byteMax);
			tcp[7] = (byte)(seqNum & byteMax);
			//Acknowledgment number
			Array.Clear(tcp, 8, 4);
			//Data Offset defines TCP header in 32bit words
			tcp[12] = 0x60; // 24 bytes, offset = 6 (6 x 4 = 24)
			//store TCP Flags(SYN,ACK)
			tcp[13] = (byte)Flags.Syn;
			//Window size
			tcp[14] = 0x04;
			tcp[15] = 0x00;
			//checksum empty, compute later
			tcp[16] = 0x00;
			tcp[17] = 0x00;
			// Urgent Pointer (2 bytes): 0.
			tcp[18] = 0x00;
			tcp[19] = 0x00;

			// --- TCP Options ---
			// Adding the Maximum Segment Size (MSS) option
			// Option Kind: MSS (0x02), Option Length: 4
			tcp[20] = (byte)Flags.MssKind; // MSS option kind (0x02)
			tcp[21] = (byte)Flags.MssLength; // MSS option length (0x04)
			tcp[22] = 0x05; // MSS value high byte (1460 = 0x05B4)
			tcp[23] = 0xB4; // MSS value low byte

			return tcp;
		}

		// Computes the TCP checksum for IPv6.
		private ushort ComputeTcpChecksumIPv6(IPAddress src, IPAddress dst, byte[] tcpSegment)
		{
			byte[] srcBytes = src.GetAddressBytes();
			byte[] dstBytes = dst.GetAddressBytes();
			int tcpLength = tcpSegment.Length;

			// Build the IPv6 pseudo-header (40 bytes)
			byte[] pseudoHeader = new byte[40];
			// Source Address (16 bytes)
			Array.Copy(srcBytes, 0, pseudoHeader, 0, 16);
			// Destination Address (16 bytes)
			Array.Copy(dstBytes, 0, pseudoHeader, 16, 16);
			// TCP Length (4 bytes) in network byte order
			pseudoHeader[32] = (byte)(tcpLength >> 24);
			pseudoHeader[33] = (byte)(tcpLength >> 16);
			pseudoHeader[34] = (byte)(tcpLength >> 8);
			pseudoHeader[35] = (byte)(tcpLength);
			// Next Header TCP is 6
			pseudoHeader[39] = 6;

			// Create a buffer that is the concatenation of the pseudo-header and the TCP segment.
			byte[] checksumBuffer = new byte[pseudoHeader.Length + tcpSegment.Length];
			Array.Copy(pseudoHeader, 0, checksumBuffer, 0, pseudoHeader.Length);
			Array.Copy(tcpSegment, 0, checksumBuffer, pseudoHeader.Length, tcpSegment.Length);

			// Compute the checksum over the combined buffer.
			return ComputeChecksum(checksumBuffer);
		}

		//IPv4
		// Builds an IPv4 packet (IP header + TCP SYN segment) for raw socket transmission.
		private byte[] BuildIpv4TcpSynPacketRaw(IPAddress targetIp, int targetPort, int sourcePort)
		{
			IPAddress localIp = GetLocalIpFromDevice(_interfaceName, AddressFamily.InterNetwork);
			byte[] tcpSegment = BuildTcpSynSegment(sourcePort, targetPort);
			byte[] ipv4Packet = BuildIpv4Packet(localIp, targetIp, tcpSegment);
			return ipv4Packet;
		}

		// Builds an IPv4 packet that encapsulates the provided TCP segment.
		private byte[] BuildIpv4Packet(IPAddress localIp, IPAddress targetIp, byte[] tcpSegment)
		{
			byte[] ipHeader = new byte[20];
			byte byteMax = 0xFF;
			Random rand = new Random();

			ipHeader[0] = 0x45; // version 4, IHL 5
			ipHeader[1] = 0x00; // DSCP (for QoS) = 000000, ECN (signal congestion) = 00

			// Total length
			int totalLength = ipHeader.Length + tcpSegment.Length;
			ipHeader[2] = (byte)(totalLength >> 8);
			ipHeader[3] = (byte)(totalLength & byteMax);

			// Identification, random
			ushort ident = (ushort)rand.Next(0, ushort.MaxValue);
			ipHeader[4] = (byte)(ident >> 8);
			ipHeader[5] = (byte)(ident & byteMax); //!

			// Flags and Fragment Offset
			ipHeader[6] = 0x00; //dont fragment
			ipHeader[7] = 0x00;

			// TTL typical value such as 64.
			ipHeader[8] = 64;

			// Protocol TCP (6).
			ipHeader[9] = 6;

			// Checksum (2 bytes): initially 0.
			ipHeader[10] = 0x00;
			ipHeader[11] = 0x00;

			// src IP
			byte[] localIpBytes = localIp.GetAddressBytes();
			Array.Copy(localIpBytes, 0, ipHeader, 12, 4);

			// dest ip
			byte[] destIpBytes = targetIp.GetAddressBytes();
			Array.Copy(destIpBytes, 0, ipHeader, 16, 4);

			// IPv4 header checksum.
			ushort ipChecksum = ComputeChecksum(ipHeader);
			ipHeader[10] = (byte)(ipChecksum >> 8);
			ipHeader[11] = (byte)(ipChecksum & 0xFF);

			// TCP Checksum
			// pseudo-header for TCP checksum calculation.
			byte[] pseudoHeader = new byte[12];
			Array.Copy(localIpBytes, 0, pseudoHeader, 0, 4); //src ip, 4b
			Array.Copy(destIpBytes, 0, pseudoHeader, 4, 4); //dest ip, 4b
			pseudoHeader[8] = 0x00; // zero padding
			pseudoHeader[9] = 6; // TCP protocol number.
			pseudoHeader[10] = (byte)(tcpSegment.Length >> 8);
			pseudoHeader[11] = (byte)(tcpSegment.Length & 0xFF);

			// Concatenate the pseudo-header and the TCP segment, includes info that is needed for checksum calculation
			byte[] tcpChecksumData = new byte[pseudoHeader.Length + tcpSegment.Length];
			Array.Copy(pseudoHeader, 0, tcpChecksumData, 0, pseudoHeader.Length);
			Array.Copy(tcpSegment, 0, tcpChecksumData, pseudoHeader.Length, tcpSegment.Length);

			ushort tcpChecksum = ComputeChecksum(tcpChecksumData);
			// Set the computed TCP checksum into the TCP segment (bytes 16-17).
			tcpSegment[16] = (byte)(tcpChecksum >> 8);
			tcpSegment[17] = (byte)(tcpChecksum & 0xFF);

			// Assemble the IPv4 packet (IP header + TCP segment).
			byte[] ipv4Packet = new byte[totalLength];
			Array.Copy(ipHeader, 0, ipv4Packet, 0, ipHeader.Length);
			Array.Copy(tcpSegment, 0, ipv4Packet, ipHeader.Length, tcpSegment.Length);

			return ipv4Packet;
		}
	}
}