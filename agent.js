/**
 *  for more details check (https://www.npmjs.com/package/pcap)
 */
const pcap = require("pcap");

/**
 *  customized internal logger utilizing [winston] pkg
 */
const Logger = require("./logger");
const logger = Logger._logger;

/// eht0 used for linux docker interface
/// lo used for linux docker loopback (isolated)
/// lo0 used for mac host machine local loopback
const networkInterface = "eth0";

/**
 *  create a pcap session to listen on the specified interface for HTTP traffic
 *  @argument {string} networkInterface - device network interface that want to capture
 *  @argument {string || object} options - more pcap options to be passed
 *  @example "tcp" || "tcp port 80"
 *
 */
const pcapSession = pcap.createSession(networkInterface, "tcp");

pcapSession.on("packet", async function (rawPacket) {
  /**
   *  @event packet
   *  @example
   *  PcapPacket {
   *    link_type: 'LINKTYPE_ETHERNET',
   *    pcap_header: PcapHeader {
   *      tv_sec: 1725618042,
   *      tv_usec: 693395,
   *      caplen: 66,
   *      len: 66
   *    },
   *    payload: EthernetPacket {
   *      emitter: undefined,
   *      dhost: EthernetAddr { addr: [Array] },
   *      shost: EthernetAddr { addr: [Array] },
   *      ethertype: 2048,
   *      vlan: null,
   *      payload: IPv4 {
   *        emitter: undefined,
   *        version: 4,
   *        headerLength: 20,
   *        diffserv: 0,
   *        length: 52,
   *        identification: 0,
   *        flags: [IPFlags],
   *        fragmentOffset: 0,
   *        ttl: 64,
   *        protocol: 6,
   *        headerChecksum: 61369,
   *        saddr: [IPv4Addr],
   *        daddr: [IPv4Addr],
   *        protocolName: undefined,
   *        payload: [TCP]
   *      }
   *    },
   *    emitter: undefined
   *  }
   *
   *
   */
  const packet = pcap.decode.packet(rawPacket);

  /**
   *  ipLayer object is being stored to access [consumer] and [producer]
   *  http requests
   *
   *  @property {object} ipLayer
   *  @property {string} ipLayer.saddr   (from)
   *  @property {string} ipLayer.daddr   (to)
   */
  const ipLayer = packet.payload.payload;
  const tcpLayer = ipLayer.payload;
  const httpData = tcpLayer?.data?.toString();

  if (httpData?.includes("HTTP") && !httpData?.includes("X-Agent-Logs")) {
    
    let request = {}, headers = {}, payload = {};

    const [requestLine, ...headerLines] = httpData.split("\r\n");

    for (const line of headerLines) {
      if (line === "") {
        payload = headerLines.slice(headerLines.indexOf(line) + 1).join("\r\n");
        break;
      }
      const [key, ...valueParts] = line.split(": ");
      if (key && valueParts.length > 0) {
        headers[key] = valueParts.join(": ");
      }
    }

    let method, url, code, message;

    if (/^(PUT|GET|POST|DELETE|PATCH|OPTIONS|HEAD) /.test(requestLine)) {
      [method, url] = requestLine.split(" ");
    } else {
      [, code, ...messageParts] = requestLine.split(" ");
      message = messageParts.join(" ");
    }

    request = {
      timestamp: new Date().toISOString(),
      code,
      message,
      method,
      url,
      headers,
      payload: () => {
        try {
          return JSON.parse(payload);
        } catch {
          return payload;
        }
      },
      from: ipLayer.saddr.toString(),
      to: ipLayer.daddr.toString(),
    };
    
    /// logging for debugging purposes
    ///
    /// I'd highly recommend to not log in prod env as it will be
    /// resources extensive also it might be used to pull the logs
    /// for different solutions
    logger.info(request);

    /// Send data to a centralized host [logmink.hub]
    await fetch(`${process.env.LOGMINK_HUB_URL}:${process.env.PORT}/capture`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        /// custom header to identify internal requests
        "X-Agent-Logs": "true",
      },
      body: JSON.stringify(request),
    });
  }
});

console.log(`Listening on interface ${networkInterface} for HTTP traffic...`);
