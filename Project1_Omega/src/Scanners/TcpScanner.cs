using System.Buffers.Binary;
using PacketDotNet.Utils;
using static Project1_Omega.Utils;

namespace Project1_Omega.Scanners
{
	public class TcpScanner
	{
		[Flags]
		public enum TcpFlags : byte
		{
			Fin = 0x01,
			Syn = 0x02,
			Rst = 0x04,
			Psh = 0x08,
			Ack = 0x10,
			Urg = 0x20,
			Ece = 0x40,
			Cwr = 0x80,
			SynAck = Syn | Ack, // 0x12

			MssKind = 0x02, // MSS option kind
			MssLength = 0x04 // MSS option length (should always be 4)
		}

		public enum TcpScanResult
		{
			Open,
			Closed,
			Filtered,
			Unknown // Unknown means no response was seen in one attempt.
		}

		private readonly string _targetIp;
		private readonly List<int> _tcpPorts;
		private readonly int _timeout;
		private readonly string? _interfaceName;

		public TcpScanner(string targetIp, List<int> tcpPorts, int timeout, string? interfaceName = null)
		{
			_targetIp = targetIp;
			_tcpPorts = tcpPorts;
			_timeout = timeout;
			_interfaceName = interfaceName;
		}


		//Starts asynchronous TCP port scanning through all input targets/ports
		public async Task ScanTcpAsync()
		{
			//Console.WriteLine($"Starting TCP SYN Scan on {_targetIp} using interface {_interfaceName ?? "default"}...");
			List<Task> scanTasks = new();
			Console.WriteLine("PORT STATE:");

			foreach (var port in _tcpPorts)
				scanTasks.Add(Task.Run(() => ScanTcpPort(port)));

			await Task.WhenAll(scanTasks);
		}

		// Scans one TCP port: sends a SYN packet via a raw socket, then waits for a response.
		private void ScanTcpPort(int port)
		{
			IPAddress targetIp = IPAddress.Parse(_targetIp);
			Console.WriteLine($"Scanning TCP Port {port} on {targetIp}");
			ICaptureDevice device = GetNetworkInterface(_interfaceName);

			Random rand = new Random();
			int sentSourcePort = rand.Next(1024, 59999);

			// Build the IPv4 packet (IP header + TCP SYN segment).
			byte[] packet = BuildIpv4TcpSynPacketRaw(device, targetIp, port, sentSourcePort);

			// Send the packet using a raw socket.
			SendSynPacketRaw(targetIp, packet);

			// Wait for a TCP response.
			TcpScanResult result = WaitForTcpResponse(device, targetIp, port, sentSourcePort, _timeout);

			// If no response, resend a second SYN to verify.
			if (result == TcpScanResult.Unknown)
			{
				Console.WriteLine("No response received; re-sending SYN to verify.");
				SendSynPacketRaw(targetIp, packet);
				result = WaitForTcpResponse(device, targetIp, port, sentSourcePort, _timeout);
				if (result == TcpScanResult.Unknown)
					result = TcpScanResult.Filtered;
			}

			Console.WriteLine($"Port {port} scan result: {result}");
		}

		// Builds an IPv4 packet (IP header + TCP SYN segment) for raw socket transmission.
		private byte[] BuildIpv4TcpSynPacketRaw(ICaptureDevice device, IPAddress targetIp, int targetPort, int sourcePort)
		{
			// Get the local IP address (implement GetLocalIp() as appropriate)
			IPAddress localIp = GetLocalIpFromDevice(device, AddressFamily.InterNetwork);
			byte[] tcpSegment = BuildTcpSynSegment(sourcePort, targetPort);
			byte[] ipv4Packet = BuildIpv4Packet(localIp, targetIp, tcpSegment);
			return ipv4Packet;
		}

		// Sends the constructed IPv4 packet via a raw socket.
		private void SendSynPacketRaw(IPAddress targetIp, byte[] packet)
		{                                  
			// Create a raw socket for IPv4 using the TCP protocol.
			using (Socket rawSocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Tcp))
			{
				// Set the IP_HDRINCL option so that the OS knows our packet contains its own IP header.
				rawSocket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
				rawSocket.SendTimeout = _timeout;

				IPEndPoint endPoint = new IPEndPoint(targetIp, 0);
				rawSocket.SendTo(packet, endPoint);
				Console.WriteLine($"Sent SYN packet to {targetIp}");
			}
		}

		// Waits for a TCP response using a raw socket. Returns the scan result based on TCP flags.
		private TcpScanResult WaitForTcpResponse(ICaptureDevice device, IPAddress targetIp, int targetPort, int sentSourcePort, int timeoutMs)
		{
			TcpScanResult result = TcpScanResult.Unknown;

			// Create a raw socket for receiving TCP packets.
			Socket recvSocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Tcp);
			recvSocket.Bind(new IPEndPoint(GetLocalIpFromDevice(device, AddressFamily.InterNetwork), 0));
			recvSocket.ReceiveTimeout = timeoutMs;

			byte[] buffer = new byte[4096];
			DateTime start = DateTime.Now;

			while ((DateTime.Now - start).TotalMilliseconds < timeoutMs)
			{
				try
				{
					int received = recvSocket.Receive(buffer);
					if (received < 20) // must at least have an IP header
						continue;

					// Determine IP header length.
					int ipHeaderLength = (buffer[0] & 0x0F) * 4;
					if (received < ipHeaderLength + 20)
						continue;

					// Extract the source IP (offset 12, length 4).
					byte[] srcIpBytes = new byte[4];
					Array.Copy(buffer, 12, srcIpBytes, 0, 4);
					IPAddress srcIp = new IPAddress(srcIpBytes);

					// Only consider packets coming from our target IP.
					if (!srcIp.Equals(targetIp))
						continue;

					// Locate the TCP header.
					int tcpHeaderStart = ipHeaderLength;

					// Get TCP source and destination ports.
					int tcpSourcePort = (buffer[tcpHeaderStart] << 8) | buffer[tcpHeaderStart + 1];
					int tcpDestinationPort = (buffer[tcpHeaderStart + 2] << 8) | buffer[tcpHeaderStart + 3];

					// Check that the response is for our connection.
					if (tcpSourcePort != targetPort || tcpDestinationPort != sentSourcePort)
						continue;

					// TCP flags are at offset tcpHeaderStart + 13.
					byte tcpFlags = buffer[tcpHeaderStart + 13];

					if ((tcpFlags & (byte)TcpFlags.Rst) != 0)
					{
						result = TcpScanResult.Closed;
						break;
					}
					else if ((tcpFlags & (byte)TcpFlags.SynAck) == (byte)TcpFlags.SynAck)
					{
						result = TcpScanResult.Open;
						break;
					}
				}
				catch (SocketException)
				{
					// A timeout or error during receive.
					break;
				}
			}

			recvSocket.Close();
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
			//4bits upper half data offset
			tcp[12] = 0x60; // 24 bytes, offset = 6 (6 x 4 = 24)
			//store TCP Flags(SYN,ACK)
			tcp[13] = (byte)TcpFlags.Syn;
			//Window size 16384 gen value
			tcp[14] = 0x40;
			tcp[15] = 0x00;
			//checksum empty, compute later
			tcp[16] = 0x00;
			tcp[17] = 0x00;
			// Urgent Pointer (2 bytes): 0.
			tcp[18] = 0x00;
			tcp[19] = 0x00;

			// --- TCP Options ---
			// Adding the Maximum Segment Size (MSS) option (4 bytes):
			// Option Kind: MSS (0x02), Option Length: 4, then the MSS value
			tcp[20] = (byte)TcpFlags.MssKind; // MSS option kind (0x02)
			tcp[21] = (byte)TcpFlags.MssLength; // MSS option length (0x04)
			tcp[22] = 0x05; // MSS value high byte (1460 = 0x05B4)
			tcp[23] = 0xB4; // MSS value low byte

			return tcp;
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
			ipHeader[6] = 0x40; //dont fragment
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

			//tcp heaader needs src and dest ip to calculate checksum
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

		private ushort ComputeChecksum(byte[] data)
		{
			uint sum = 0;
			int i = 0;
			while (i < data.Length - 1)
			{
				ushort word = (ushort)((data[i] << 8) + data[i + 1]);
				sum += word;
				i += 2;
			}

			if (i < data.Length)
			{
				ushort word = (ushort)(data[i] << 8);
				sum += word;
			}

			while ((sum >> 16) != 0)
			{
				sum = (sum & 0xFFFF) + (sum >> 16);
			}

			return (ushort)(~sum);
		}
	}
}