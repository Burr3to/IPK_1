using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace Project1_Omega.Scanners
{
	public class TcpScanner
	{
		private readonly string _targetIp;
		private readonly List<int> _tcpPorts;
		private readonly int _timeout;

		public TcpScanner(string targetIp, List<int> tcpPorts, int timeout)
		{
			_targetIp = targetIp;
			_tcpPorts = tcpPorts;
			_timeout = timeout;
		}

		public async Task ScanTcpAsync()
		{
			Console.WriteLine($"Starting TCP Connect Scan on {_targetIp}...");

			List<Task> scanTasks = new(); 

			foreach (var port in _tcpPorts)
			{
				scanTasks.Add(Task.Run(() => ScanTcpPort(port)));
			}

			await Task.WhenAll(scanTasks);
		}


		/*
		 *TCP Scanning

	    Sends only SYN packets.
	    Does not perform a full 3-way-handshake.
	    If an RST response is received → Port is closed.
	    If no response is received → Verify with another packet before marking as filtered.
	    If a SYN-ACK is received → Port is open.
		 */
		private void ScanTcpPort(int port)
		{
			using (TcpClient tcpClient = new TcpClient())
			{
				try
				{
					var task = tcpClient.ConnectAsync(_targetIp, port);
					if (!task.Wait(_timeout) || !tcpClient.Connected)
					{
						Console.WriteLine($"Port {port}/tcp is CLOSED (Timeout)");
						return;
					}

					Console.WriteLine($"Port {port}/tcp is OPEN");
				}
				catch
				{
					Console.WriteLine($"Port {port}/tcp is CLOSED");
				}
			}
		}
	}
}