using System;
using SharpPcap;
using System.Collections.Generic;
namespace Project1_Omega;

class CommandLineParser
{
    public string? Interface { get; private set; }
    public string? DomainOrIp { get; private set; }
    public int Timeout { get; private set; } = 5000; // Default timeout
    public List<int> TcpPorts { get; private set; } = new();
    public List<int> UdpPorts { get; private set; } = new();

    public CommandLineParser(string[] args)
    {
        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];

            switch (arg)
            {
                case "-i":
                case "--interface":
                    if (i + 1 < args.Length && !args[i + 1].StartsWith("-"))
                    {
                        Interface = args[++i]; // Move to next value
                    }
                    else
                    {
                        PrintActiveInterfaces();
                        return;
                    }
                    break;

                case "-t":
                case "--pt":
                    if (i + 1 < args.Length && !args[i + 1].StartsWith("-"))
                    {
                        TcpPorts = ParsePortRanges(args[++i]);
                    }
                    break;

                case "-u":
                case "--pu":
                    if (i + 1 < args.Length && !args[i + 1].StartsWith("-"))
                    {
                        UdpPorts = ParsePortRanges(args[++i]);
                    }
                    break;

                case "-w":
                case "--wait":
                    if (i + 1 < args.Length && int.TryParse(args[i + 1], out int timeout))
                    {
                        Timeout = timeout;
                        i++; // Move to next value
                    }
                    break;

                default:
                    if (!arg.StartsWith("-") && DomainOrIp == null)
                    {
                        DomainOrIp = arg; // Assume this is the domain/IP
                    }
                    break;
            }
        }
    }
    private void PrintActiveInterfaces()
    {
        Console.WriteLine("Active Interfaces:");
        foreach (var dev in CaptureDeviceList.Instance)
        {
            Console.WriteLine($"  - {dev.Name} ({dev.Description})");
        }
        
    }

    private List<int> ParsePortRanges(string input)
    {
        var ports = new List<int>();
        var ranges = input.Split(',');

        foreach (var range in ranges)
        {
            if (range.Contains('-'))
            {
                var parts = range.Split('-');
                if (int.TryParse(parts[0], out int start) && int.TryParse(parts[1], out int end))
                {
                    for (int i = start; i <= end; i++)
                        ports.Add(i);
                }
            }
            else if (int.TryParse(range, out int singlePort))
            {
                ports.Add(singlePort);
            }
        }
        return ports;
    }
}
