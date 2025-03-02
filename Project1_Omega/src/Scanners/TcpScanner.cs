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
			// Parse target IP address // get device interfaces
			IPAddress targetIp = IPAddress.Parse(_targetIp);
			ICaptureDevice? device = GetNetworkInterface(_interfaceName) ?? throw new Exception("No network interface found.");
			PhysicalAddress targetMac = GetDestinationMac(targetIp, device);

			Console.WriteLine("target ip: " + targetIp);
			Console.WriteLine("target MAC: " + targetMac);
		}


		private void SendSynPacket(ICaptureDevice device, IPAddress ipAddress, int port, int sentSourcePort)
		{
			byte[] bytepacketBytes = BuildIpv4TcpSynPacket(device, ipAddress, port, sentSourcePort);

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

		private byte[] BuildIpv4TcpSynPacket(ICaptureDevice device, IPAddress targetIp, int targetPort, int sourcePort)
		{
			try
			{
				// Get correct MAC addresses
				PhysicalAddress sourceMac = GetMacAddressFromDevice(device);
				PhysicalAddress destMac = GetDestinationMac(targetIp, device) ?? throw new Exception($"Could not resolve MAC address for {targetIp}");
				Console.WriteLine("ARPACKET   " + destMac);

				IPAddress localIp = GetLocalIpFromDevice(device, AddressFamily.InterNetwork)
				                    ?? throw new Exception("Could not determine local IP address.");

				// Create IP packet


				return null;
				//return ethernetPacket.Bytes;
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