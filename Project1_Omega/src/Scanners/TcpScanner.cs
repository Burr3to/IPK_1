using PacketDotNet.Tcp;
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

		//Scans one port at a time, sends a SYN packet to the ip/port and analyses their response. (OPEN,CLOSED,FILTERED)
		private void ScanTcpPort(int port)
		{
			try
			{
				// Parse target IP address // get device interfaces
				IPAddress ipAddress = IPAddress.Parse(_targetIp);
				ICaptureDevice? device = GetNetworkInterface();

				//Capturing all packets
				device.Open(DeviceModes.Promiscuous, _timeout);

				int sourceport = 0;
				bool responseReceived = false;
				int sentSourcePort = 0;

				HashSet<int> processedPorts = new HashSet<int>(); // Ensure we process each port only once


				device.OnPacketArrival += (sender, e) =>
				{
					//Extracting data from captured packet
					var rawPacket = e.GetPacket();
					var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
					var ipPacket = packet.Extract<IPv4Packet>();
					var tcpPacket = packet.Extract<TcpPacket>();

					if (ipPacket == null || tcpPacket == null)
						return;


					// Skip irrelevant packets
					if (!ipPacket.SourceAddress.Equals(IPAddress.Parse(_targetIp)))
						return;
					if (tcpPacket.DestinationPort != sentSourcePort)
						return;

					responseReceived = true;

					// Detect Open or Closed Port
					if ((tcpPacket.Flags & (ushort)TcpFlags.SynAck) == (ushort)(TcpFlags.SynAck)) // SYN-ACK
						Console.WriteLine($"[OnPacketArrival] ✅ Port {port}/tcp is OPEN");
					else if ((tcpPacket.Flags & (ushort)TcpFlags.Rst) != 0) // RST
						Console.WriteLine($"[OnPacketArrival] ❌ Port {port}/tcp is CLOSED");
					else
						Console.WriteLine($"[OnPacketArrival] ⚠ Unexpected TCP flags: 0x{tcpPacket.Flags:X2}");

					// Track processed ports
					processedPorts.Add(tcpPacket.SourcePort);
					device.StopCapture();
					device.Close();
				};

				//Start capturing packets as response and send SYN packet
				device.StartCapture();
				SendSynPacket(device, ipAddress, port, out sentSourcePort);

				// Waiting for packet capture
				Thread.Sleep(_timeout);

				// Stop capturing after catch
				device.StopCapture();
				device.Close();

				if (!responseReceived)
					Console.WriteLine($"Port {port}/tcp is FILTERED (No response)");
			}
			catch (Exception ex)
			{
				Console.Error.WriteLine($"[ScanTcpPort] Error scanning port {port}/tcp: {ex.Message}");
			}
		}

		private ICaptureDevice? GetNetworkInterface()
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

		private void SendSynPacket(ICaptureDevice device, IPAddress ipAddress, int port, out int sentSourcePort)
		{
			byte[] bytepacketBytes = BuildTcpSynPacket(device, ipAddress, port, out sentSourcePort);

			if (device is ILiveDevice liveDevice)
			{
				liveDevice.SendPacket(bytepacketBytes);
				//Console.WriteLine($"Sent SYN packet to {_targetIp}:{port}");
			}
			else
			{
				Console.Error.WriteLine("Error: Selected device does not support packet injection.");
			}
		}

		private byte[] BuildTcpSynPacket(ICaptureDevice device, IPAddress targetIp, int targetPort, out int sourcePort)
		{
			try
			{
				// Get correct MAC addresses
				PhysicalAddress sourceMac = GetMacAddressFromDevice(device);
				PhysicalAddress destMac = GetDestinationMac(targetIp);

				// Create Ethernet packet
				var ethernetPacket = new EthernetPacket(sourceMac, destMac, EthernetType.IPv4);

				// Get local IP from device
				IPAddress localIp = GetLocalIpFromDevice(device, AddressFamily.InterNetwork)
				                    ?? throw new Exception("Could not determine local IP address.");

				// Create IP packet
				var ipPacket = new IPv4Packet(localIp, targetIp)
				{
					Protocol = PacketDotNet.ProtocolType.Tcp,
					TimeToLive = 64
				};

				// Generate a random source port
				sourcePort = new Random().Next(1024, 65535); // Use a lower port range

				// Create TCP SYN packet
				var tcpPacket = new TcpPacket((ushort)sourcePort, (ushort)targetPort)
				{
					Flags = (ushort)TcpFlags.Syn,
					SequenceNumber = (uint)new Random().Next(1000, 99999),
					WindowSize = 64240
				};

				int biggerHeadersize = 24;
				var bigHeader = new byte[biggerHeadersize];

				Array.Copy(tcpPacket.Bytes, 0, bigHeader, 0, tcpPacket.Bytes.Length);

				var finalTcp = new TcpPacket(new ByteArraySegment(bigHeader))
				{
					Flags = tcpPacket.Flags,
					SequenceNumber = tcpPacket.SequenceNumber,
					WindowSize = tcpPacket.WindowSize,
					SourcePort = tcpPacket.SourcePort,
					DestinationPort = tcpPacket.DestinationPort
				};

				finalTcp.DataOffset = (byte)(biggerHeadersize / 4);
				finalTcp.Options = new byte[] { (byte)TcpFlags.Syn, (byte)TcpFlags.Rst, (byte)TcpFlags.MssKind, (byte)TcpFlags.MssLength };

				// Ensure packets are properly linked before updating checksum
				ipPacket.PayloadPacket = finalTcp;
				ethernetPacket.PayloadPacket = ipPacket;
				finalTcp.ParentPacket = ipPacket;
				ipPacket.ParentPacket = ethernetPacket;

				finalTcp.UpdateTcpChecksum();
				ipPacket.UpdateIPChecksum();
				finalTcp.UpdateTcpChecksum();

				return ethernetPacket.Bytes;
			}
			catch (Exception ex)
			{
				Console.WriteLine($"Error building TCP SYN packet: {ex.Message}");
				sourcePort = -1;
				return Array.Empty<byte>(); // Return an empty array to prevent crashes
			}
		}
	}
}