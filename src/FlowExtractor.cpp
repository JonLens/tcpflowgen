#include "FlowExtractor.h"
#include "FlowUtils.h"
#include "SystemUtils.h"
#include "PcapFileDevice.h"
#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#ifdef __linux__
    #include <netinet/in.h>  // Linux needs this for IPPROTO_TCP, sockaddr_in, etc.
    #include <arpa/inet.h>   // Linux needs this for htons(), htonl(), etc.
#endif
#include <Logger.h>
#include <chrono>

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
    const size_t IP_HEADER_SIZE = 20;
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
        uint8_t flags = 0;

        if (tcpHeader->finFlag) flags |= 0x01;
        if (tcpHeader->synFlag) flags |= 0x02;
        if (tcpHeader->rstFlag) flags |= 0x04;
        if (tcpHeader->pshFlag) flags |= 0x08;
        if (tcpHeader->ackFlag) flags |= 0x10;
        if (tcpHeader->urgFlag) flags |= 0x20;
        
        FlowKey flow_key(src_ip, src_port, dst_ip, dst_port); // Construct the quadruple
        if (flags == 0x02){
            if (src_ip == flow_key.src_ip){
                client_is_first[flow_key] = true;     // In the ordered key, the Client IP is 1st
            }else{
                client_is_first[flow_key] = false;    // In the ordered key, the Client IP is 2nd
            }
        }
        std::string direction;
        if (client_is_first.find(flow_key) != client_is_first.end()) { // Flowkey has a clear client
            if (client_is_first[flow_key]){
                if (src_ip == flow_key.src_ip && src_port == flow_key.src_port){
                    direction = "forward";
                }else if(src_ip == flow_key.dst_ip && src_port == flow_key.dst_port){
                    direction = "reverse";
                }
            }else{
                if(src_ip == flow_key.dst_ip && src_port == flow_key.dst_port){
                    direction = "forward";
                }else if (src_ip == flow_key.src_ip && src_port == flow_key.src_port){
                    direction = "reverse";
                }
            }
        }else{
            direction = (src_ip == flow_key.src_ip) ? "forward" : "reverse";
        }

        std::vector<uint8_t> options;
        size_t options_length = tcpLayer->getHeaderLen() - sizeof(pcpp::tcphdr);
        if (options_length > 0) {
            const uint8_t* options_data = reinterpret_cast<const uint8_t*>(tcpHeader) + sizeof(pcpp::tcphdr);
            options.assign(options_data, options_data + options_length);
        }

        uint64_t current_time = rawPacket.getPacketTimeStamp().tv_sec * 1000000 + 
                              rawPacket.getPacketTimeStamp().tv_nsec / 1000;
        
        uint64_t time_delta = 0;
        if (last_timestamps.find(flow_key) != last_timestamps.end()) {
            time_delta = current_time - last_timestamps[flow_key];
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
        pktInfo.options = options;
        pktInfo.data_len = tcpLayer->getLayerPayloadSize();
        pktInfo.pkt_size = ntohs(ipLayer->getIPv4Header()->totalLength) - IP_HEADER_SIZE; 
        pktInfo.direction = direction;
        pktInfo.timestamp_microsec = current_time;
        pktInfo.time_delta_microsec = time_delta;
        
        flows[flow_key].push_back(pktInfo);
        
    }
    
    activeReader->close();
    
    // Categorize flows
    for (auto& flow_entry : flows) {
        const FlowKey& flow_key = flow_entry.first;
        std::vector<PacketInfo>& packets = flow_entry.second;
        int handshake_state = 0;
        int termination_state = 0;
        size_t last_idx = packets.size() - 1;
        
        if (packets.size() >= 7) {
            // SYN -> SYN-ACK -> ACK
            if ((packets[0].flags == 0x02) && (packets[1].flags == 0x12) && (packets[2].flags == 0x10)) {
                handshake_state = 1 ;
            }
            // FIN-ACK -> ACK -> FIN-ACK -> ACK
            if((packets[last_idx-3].flags == 0x11) && (packets[last_idx-2].flags == 0x10) && (packets[last_idx-1].flags == 0x11) && (packets[last_idx].flags == 0x10)){
                termination_state = 1;

            }   
        }
        
        std::string flow_type;
        if ((handshake_state == 1) && (termination_state == 1)) {
            flow_type = "complete";
        } else if ((handshake_state == 1) && (termination_state != 1)) {
            flow_type = "start";
        } else if ((handshake_state != 1) && (termination_state == 1)) {
            flow_type = "end";
        } else {
            flow_type = "free";
        }
        
        flow_type_counts[flow_type]++;
        
        FlowInfo flow_info;
        flow_info.packets = packets;
        flow_info.flow_type = flow_type;
        
        categorized_flows[flow_key] = flow_info;
    }

}