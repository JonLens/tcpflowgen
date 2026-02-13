#include "FlowExtractor.h"
#include "FlowUtils.h"
#include "SystemUtils.h"
#include "PcapFileDevice.h"
#include "Packet.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include <string>
#ifdef __linux__
    #include <netinet/in.h>  // Linux needs this for IPPROTO_TCP, sockaddr_in, etc.
    #include <arpa/inet.h>   // Linux needs this for htons(), htonl(), etc.
#endif
#include <Logger.h>

const size_t IP_HEADER_SIZE = 20;


static uint8_t extract_tcp_flags(const pcpp::tcphdr* tcpHeader) {
    uint8_t flags = 0;
    if (tcpHeader->finFlag) flags |= 0x01;
    if (tcpHeader->synFlag) flags |= 0x02;
    if (tcpHeader->rstFlag) flags |= 0x04;
    if (tcpHeader->pshFlag) flags |= 0x08;
    if (tcpHeader->ackFlag) flags |= 0x10;
    if (tcpHeader->urgFlag) flags |= 0x20;
    return flags;
}

static std::vector<uint8_t> extract_tcp_options(const pcpp::TcpLayer* tcpLayer,
                                                 const pcpp::tcphdr* tcpHeader) {
    std::vector<uint8_t> options;
    size_t options_length = tcpLayer->getHeaderLen() - sizeof(pcpp::tcphdr);
    if (options_length > 0) {
        const uint8_t* options_data = reinterpret_cast<const uint8_t*>(tcpHeader) + sizeof(pcpp::tcphdr);
        options.assign(options_data, options_data + options_length);
    }
    return options;
}

static std::string determine_direction(const std::string& src_ip, uint16_t src_port,
                                        const FlowKey& flow_key,
                                        const std::map<FlowKey, bool>& client_is_first) {
    auto it = client_is_first.find(flow_key);
    if (it != client_is_first.end()) {
        bool client_first = it->second;
        bool matches_src = (src_ip == flow_key.src_ip && src_port == flow_key.src_port);
        bool matches_dst = (src_ip == flow_key.dst_ip && src_port == flow_key.dst_port);
        
        if (client_first) {
            return matches_src ? "forward" : (matches_dst ? "reverse" : "forward");
        } else {
            return matches_dst ? "forward" : (matches_src ? "reverse" : "forward");
        }
    }
    return (src_ip == flow_key.src_ip) ? "forward" : "reverse";
}

static std::string categorize_flow(const std::vector<PacketInfo>& packets) {
    if (packets.size() < 7) return "free";

    size_t last = packets.size() - 1;
    bool has_handshake = (packets[0].flags == 0x02) &&
                         (packets[1].flags == 0x12) &&
                         (packets[2].flags == 0x10);
    bool has_termination = (packets[last-3].flags == 0x11) &&
                           (packets[last-2].flags == 0x10) &&
                           (packets[last-1].flags == 0x11) &&
                           (packets[last].flags == 0x10);

    if (has_handshake && has_termination) return "complete";
    if (has_handshake)                   return "start";
    if (has_termination)                 return "end";
    return "free";
}

void process_pcap_file(const std::string& pcapFileName, 
                      std::map<FlowKey, FlowInfo>& categorized_flows,
                      uint64_t& packet_count,
                      std::map<std::string, int>& flow_type_counts) {
    
    pcpp::Logger::getInstance().suppressLogs();
    pcpp::PcapFileReaderDevice reader(pcapFileName.c_str());
    pcpp::PcapNgFileReaderDevice readerNg(pcapFileName.c_str());
    pcpp::IFileReaderDevice* activeReader = nullptr;

    // Try .pcap first
    if (reader.open()) {
        activeReader = &reader;
    } 
    // Fall back to .pcapng if .pcap fails
    else if (readerNg.open()) {
        activeReader = &readerNg;
    } 
    // Both failed
    else {
        throw std::runtime_error("Error opening pcap file (tried both pcap and pcapng formats)");
    }
    std::map<FlowKey, std::vector<PacketInfo>> flows;
    std::map<FlowKey, bool> client_is_first;
    std::map<FlowKey, uint64_t> last_timestamps;
    
    pcpp::RawPacket rawPacket;
    packet_count = 0;

    while (activeReader->getNextPacket(rawPacket)) {
        // Only keep packets with TCP and IP layers
        pcpp::Packet parsedPacket(&rawPacket);
        pcpp::TcpLayer* tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
        if (tcpLayer == nullptr) continue;
        pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
        if (ipLayer == nullptr) continue;

        packet_count++;

        std::string src_ip = ipLayer->getSrcIPAddress().toString();
        std::string dst_ip = ipLayer->getDstIPAddress().toString();
        pcpp::tcphdr* tcpHeader = tcpLayer->getTcpHeader();
        uint16_t src_port = tcpLayer->getSrcPort();
        uint16_t dst_port = tcpLayer->getDstPort();
        uint8_t flags = extract_tcp_flags(tcpHeader);
        
        FlowKey flow_key(src_ip, src_port, dst_ip, dst_port); // Construct the quadruple
        if (flags == 0x02){
            client_is_first[flow_key] = (src_ip == flow_key.src_ip);
        }

        std::string direction = determine_direction(src_ip, src_port, flow_key, client_is_first);

        uint64_t current_time = rawPacket.getPacketTimeStamp().tv_sec * 1000000 + 
                              rawPacket.getPacketTimeStamp().tv_nsec / 1000;
        
        uint64_t time_delta = 0;
        auto ts_it = last_timestamps.find(flow_key);
        if (ts_it != last_timestamps.end()) {
            time_delta = current_time - ts_it->second;
        }
        last_timestamps[flow_key] = current_time;
        
        PacketInfo pktInfo;
        pktInfo.src_ip = src_ip;
        pktInfo.dst_ip = dst_ip;
        pktInfo.src_port = src_port;
        pktInfo.dst_port = dst_port;
        pktInfo.flags = flags;
        pktInfo.seq = pcpp::netToHost32(tcpHeader->sequenceNumber);
        pktInfo.ack = pcpp::netToHost32(tcpHeader->ackNumber);
        pktInfo.data_offset = tcpHeader->dataOffset;
        pktInfo.window_size = pcpp::netToHost16(tcpHeader->windowSize);
        // pktInfo.checksum = ntohs(tcpHeader->headerChecksum);
        pktInfo.urgent_ptr = pcpp::netToHost16(tcpHeader->urgentPointer);
        pktInfo.options = extract_tcp_options(tcpLayer, tcpHeader);
        pktInfo.data_len = tcpLayer->getLayerPayloadSize();
        pktInfo.pkt_size = ntohs(ipLayer->getIPv4Header()->totalLength) - IP_HEADER_SIZE; 
        pktInfo.direction = direction;
        pktInfo.timestamp_microsec = current_time;
        pktInfo.time_delta_microsec = time_delta;
        
        flows[flow_key].push_back(pktInfo);
        
    }
    
    activeReader->close();
    
    // Categorize flows
    for (auto& [flow_key, packets] : flows) {
        std::string flow_type = categorize_flow(packets);
        flow_type_counts[flow_type]++;

        FlowInfo flow_info;
        flow_info.packets = packets;
        flow_info.flow_type = flow_type;
        categorized_flows[flow_key] = flow_info;
    }

}
