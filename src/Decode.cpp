#include "Decode.h"
#define NOMINMAX
#include "Encode.h"
#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "PayloadLayer.h"
#include "TcpLayer.h"
#include <IpAddress.h>
#ifdef __linux__
    #include <netinet/in.h>
    #include <arpa/inet.h>
#endif
#include <vector>
#include <iostream>
#include <algorithm>
#include <random>

static const size_t ETH_HEADER_SIZE = 14;
static const size_t IP_HEADER_SIZE  = 20;

// ============================================================================
// Flow validation
// ============================================================================

FlowValidationStats validateFlowSemantics(const std::vector<pcpp::Packet>& packets) {
    FlowValidationStats stats;
    
    // Check SYN sequence (first 3 packets: SYN, SYN-ACK, ACK)
    if (packets.size() >= 3) {
        auto pkt1 = packets[0].getLayerOfType<pcpp::TcpLayer>();
        auto pkt2 = packets[1].getLayerOfType<pcpp::TcpLayer>();
        auto pkt3 = packets[2].getLayerOfType<pcpp::TcpLayer>();
        
        bool valid_syn     = pkt1 && pkt1->getTcpHeader()->synFlag && !pkt1->getTcpHeader()->ackFlag;
        bool valid_syn_ack = pkt2 && pkt2->getTcpHeader()->synFlag &&  pkt2->getTcpHeader()->ackFlag;
        bool valid_ack     = pkt3 && !pkt3->getTcpHeader()->synFlag && pkt3->getTcpHeader()->ackFlag;
        
        if (valid_syn && valid_syn_ack && valid_ack) {
            stats.has_valid_syn_sequence = true;
        } else {
            if (!valid_syn)     stats.missing_flags.push_back("SYN in first packet");
            if (!valid_syn_ack) stats.missing_flags.push_back("SYN-ACK in second packet");
            if (!valid_ack)     stats.missing_flags.push_back("ACK in third packet");
        }
    } else {
        stats.missing_flags.push_back("Not enough packets for SYN sequence");
    }
    
    // Check FIN sequence (last 4 packets should have at least 2 FIN-ACKs)
    if (packets.size() >= 7) {
        size_t fin_ack_count = 0;
        for (size_t i = packets.size() - 4; i < packets.size(); i++) {
            auto tcpLayer = packets[i].getLayerOfType<pcpp::TcpLayer>();
            if (tcpLayer && tcpLayer->getTcpHeader()->finFlag && tcpLayer->getTcpHeader()->ackFlag) {
                fin_ack_count++;
            }
        }
        if (fin_ack_count >= 2) {
            stats.has_valid_fin_sequence = true;
        } else {
            stats.missing_flags.push_back("Not enough FIN-ACK packets in last 4 packets");
        }
    } else {
        stats.missing_flags.push_back("Not enough packets for FIN sequence");
    }
    
    return stats;
}

// ============================================================================
// Arrow I/O
// ============================================================================

std::vector<std::vector<int>> load_tokens_arrow(const std::string& filename) {
    std::vector<std::vector<int>> tokenized_flows;

    try {
        auto input_file = arrow::io::ReadableFile::Open(filename).ValueOrDie();
        auto reader = arrow::ipc::RecordBatchFileReader::Open(input_file).ValueOrDie();

        if (reader->num_record_batches() == 0) {
            throw std::runtime_error("No record batches in file");
        }
        auto batch = reader->ReadRecordBatch(0).ValueOrDie();
        
        if (batch->num_columns() != 1) {
            throw std::runtime_error("Expected exactly one column in the Arrow file");
        }
        
        auto list_array = std::static_pointer_cast<arrow::ListArray>(batch->column(0));
        auto values_array = std::static_pointer_cast<arrow::Int32Array>(list_array->values());
        
        for (int64_t i = 0; i < list_array->length(); i++) {
            auto start = list_array->value_offset(i);
            auto end   = list_array->value_offset(i + 1);
            
            std::vector<int> flow_tokens;
            flow_tokens.reserve(end - start);
            for (int64_t j = start; j < end; j++) {
                flow_tokens.push_back(values_array->Value(j));
            }
            tokenized_flows.push_back(std::move(flow_tokens));
        }
    } catch (const std::exception& e) {
        std::cerr << "Error loading Arrow file: " << e.what() << std::endl;
        throw;
    }

    return tokenized_flows;
}

// ============================================================================
// Packet creation from tokens
// ============================================================================

std::string generateRandomIP() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(1, 254);
    return "192.168." + std::to_string(dis(gen)) + "." + std::to_string(dis(gen));
}

static void setTcpFlags(pcpp::tcphdr* hdr, uint8_t flags) {
    hdr->finFlag = (flags & 0x01) ? 1 : 0;
    hdr->synFlag = (flags & 0x02) ? 1 : 0;
    hdr->rstFlag = (flags & 0x04) ? 1 : 0;
    hdr->pshFlag = (flags & 0x08) ? 1 : 0;
    hdr->ackFlag = (flags & 0x10) ? 1 : 0;
    hdr->urgFlag = (flags & 0x20) ? 1 : 0;
}

pcpp::Packet createTcpPacketFromIntSequence(
    const std::vector<int>& flow_tokens,
    const std::string& srcIP,
    const std::string& dstIP,
    size_t& index,
    PacketCreationStats& stats,
    size_t packet_number) {
    
    std::map<std::string, std::string> current_packet_errors;
    bool packet_valid = true;

    auto recordError = [&](const std::string& field, const std::string& reason, int value = -1) {
        std::string error_msg = reason;
        if (value != -1) {
            error_msg += " (value: " + std::to_string(value) + ")";
        }
        current_packet_errors[field] = error_msg;
        stats.field_failures[field + "_" + reason]++;
    };

    // Default values
    uint16_t tcpDataLen    = 0;
    uint16_t srcPort       = 12345;
    uint16_t dstPort       = 80;
    uint32_t seqNum        = 0;
    uint32_t ackNum        = 0;
    uint8_t  dataOffset    = 5;
    uint8_t  reserved      = 0;
    uint8_t  flags         = 0;
    uint16_t windowSize    = 65535;
    uint16_t checksum      = 0;
    uint16_t urgentPointer = 0;

    // 1. Parse packet size
    if (index >= flow_tokens.size() - 1 || flow_tokens[index] != TOKEN_PKT_SIZE) {
        recordError("HEADER", "MISSING_PKT_SIZE_TOKEN", flow_tokens[index]);
        packet_valid = false;
    } else {
        index++;
        tcpDataLen = static_cast<uint16_t>(flow_tokens[index]);
        if (tcpDataLen > 65495) {
            recordError("TCP_DATA_LENGTH", "TOO_LARGE", tcpDataLen);
            tcpDataLen = 0;
            packet_valid = false;
        }
    }
    index++;

    // 2. Create packet with exact size
    size_t totalPacketSize = ETH_HEADER_SIZE + IP_HEADER_SIZE + tcpDataLen;
    pcpp::Packet tcpPacket(totalPacketSize);
    
    // 3. Add Ethernet and IP layers
    auto* ethLayer = new pcpp::EthLayer(
        pcpp::MacAddress("00:00:00:00:00:00"),
        pcpp::MacAddress("00:00:00:00:00:00"),
        PCPP_ETHERTYPE_IP
    );
    auto* ipLayer = new pcpp::IPv4Layer(
        pcpp::IPv4Address(srcIP.c_str()),
        pcpp::IPv4Address(dstIP.c_str())
    );
    ipLayer->getIPv4Header()->timeToLive = 64; 
    ipLayer->getIPv4Header()->protocol = IPPROTO_TCP;
    tcpPacket.addLayer(ethLayer, true);
    tcpPacket.addLayer(ipLayer, true); 

    // 4. Find HEAD token
    while (index < flow_tokens.size() && flow_tokens[index] != TOKEN_HEAD) {
        index++;
    }
    if (index >= flow_tokens.size() - 13) {
        recordError("HEADER", "MISSING_HEAD_TOKEN");
        packet_valid = false;    
    } else {
        index++;
    }

    // 5. Extract header fields with bounds checking
    auto safeExtract = [&](auto& var, const std::string& fieldName, auto minVal, auto maxVal) {
        if (index >= flow_tokens.size()) {
            recordError("NO_END_TOKEN", "MISSING_VALUE");
            packet_valid = false;
            return;
        }
        int value = flow_tokens[index];
        try {
            using VarType = std::decay_t<decltype(var)>;
            var = static_cast<VarType>(value);
            if (var < static_cast<VarType>(minVal) || var > static_cast<VarType>(maxVal)) {
                recordError(fieldName, "OUT_OF_RANGE", value);
                packet_valid = false;
            }
        } catch (...) {
            recordError(fieldName, "INVALID_VALUE", value);
            packet_valid = false;
        }
        index++;
    };

    safeExtract(srcPort, "SRC_PORT", 1, 65535);
    safeExtract(dstPort, "DST_PORT", 1, 65535);
    
    uint32_t seqHigh = 0, seqLow = 0;
    safeExtract(seqHigh, "SEQ_HIGH", 0, 65535);
    safeExtract(seqLow,  "SEQ_LOW",  0, 65535);
    seqNum = (seqHigh << 16) | seqLow;
    
    uint32_t ackHigh = 0, ackLow = 0;
    safeExtract(ackHigh, "ACK_HIGH", 0, 65535);
    safeExtract(ackLow,  "ACK_LOW",  0, 65535);
    ackNum = (ackHigh << 16) | ackLow;
    
    safeExtract(dataOffset,    "DATA_OFFSET",    5, 15);
    safeExtract(reserved,      "RESERVED",       0, 255);
    safeExtract(flags,         "FLAGS",          0, 255);
    safeExtract(windowSize,    "WINDOW_SIZE",    0, 65535);
    safeExtract(checksum,      "CHECKSUM",       0, 65535);
    safeExtract(urgentPointer, "URGENT_POINTER", 0, 65535);

    // 6. Build TCP layer
    auto* tcpLayer = new pcpp::TcpLayer(srcPort, dstPort);
    pcpp::tcphdr* tcpHdr = tcpLayer->getTcpHeader();
    
    tcpHdr->sequenceNumber = htonl(seqNum);
    tcpHdr->ackNumber      = htonl(ackNum);
    tcpHdr->dataOffset     = dataOffset;
    tcpHdr->reserved       = reserved;
    tcpHdr->windowSize     = htons(windowSize);
    tcpHdr->headerChecksum = checksum;
    tcpHdr->urgentPointer  = htons(urgentPointer);
    setTcpFlags(tcpHdr, flags);
    
    int tcpHeaderLength = dataOffset * 4;
    if (tcpHeaderLength < static_cast<int>(sizeof(pcpp::tcphdr)) || tcpHeaderLength > 60) {
        recordError("TCP_HEADER", "INVALID_LENGTH", tcpHeaderLength);
        tcpHeaderLength = sizeof(pcpp::tcphdr);
        packet_valid = false;
    }

    // 7. Parse TCP options
    int optionsLengthBytes = tcpHeaderLength - sizeof(pcpp::tcphdr);
    std::vector<uint8_t> optionsData;
    while (static_cast<int>(optionsData.size()) < optionsLengthBytes && index < flow_tokens.size()) {
        if (flow_tokens[index] == TOKEN_FORWARD || 
            flow_tokens[index] == TOKEN_REVERSE || 
            flow_tokens[index] == TOKEN_EOS) {
            break;
        }
        try {
            uint16_t chunk = static_cast<uint16_t>(flow_tokens[index++]);
            if (static_cast<int>(optionsData.size()) < optionsLengthBytes) {
                optionsData.push_back(static_cast<uint8_t>((chunk >> 8) & 0xFF));
            }
            if (static_cast<int>(optionsData.size()) < optionsLengthBytes) {
                optionsData.push_back(static_cast<uint8_t>(chunk & 0xFF));
            }
        } catch (...) {
            recordError("TCP_OPTIONS", "INVALID_VALUE");
            packet_valid = false;
            break;
        }
    }

    // Walk the options structure-aware to find the real EOL marker.
    // The original code treated any 0x00 byte as EOL, but 0x00 can appear
    // as a data byte inside multi-byte options (e.g. timestamps, SACK blocks).
    // Only kind=0x00 at an option boundary is the true EOL.
    {
        size_t i = 0;
        while (i < optionsData.size()) {
            uint8_t kind = optionsData[i];
            if (kind == 0x00) {
                // True EOL — zero the rest
                std::fill(optionsData.begin() + i + 1, optionsData.end(), 0x00);
                break;
            }
            if (kind == 0x01) {
                i++;        // NOP is a single byte
                continue;
            }
            // Multi-byte option: kind + length + data
            if (i + 1 >= optionsData.size()) break;
            uint8_t len = optionsData[i + 1];
            if (len < 2) break;  // Malformed
            i += len;
        }
    }

    if (static_cast<int>(optionsData.size()) < optionsLengthBytes) {
        optionsData.resize(optionsLengthBytes, 0x00);
    }

    // 8. Add TCP layer to packet (Packet takes ownership)
    tcpPacket.addLayer(tcpLayer, true);
    
    if (optionsLengthBytes > 0 && !optionsData.empty()) {        
        uint8_t* tcpHeaderPtr = tcpLayer->getData();
        uint8_t* optionsPtr = tcpHeaderPtr + sizeof(pcpp::tcphdr);
        size_t maxOptionsSize = tcpLayer->getDataLen() - sizeof(pcpp::tcphdr);
        size_t copySize = std::min(
            static_cast<size_t>(optionsLengthBytes),
            std::min(optionsData.size(), maxOptionsSize)
        );
        if (copySize > 0) {
            memcpy(optionsPtr, optionsData.data(), copySize);
        }
    }

    size_t payloadLength = tcpDataLen - tcpHeaderLength;
    if (payloadLength > 0) {
        std::vector<uint8_t> payloadData(payloadLength, 0x00);
        auto* payloadLayer = new pcpp::PayloadLayer(payloadData.data(), payloadLength);
        tcpPacket.addLayer(payloadLayer, true);
    }
    
    uint16_t ipTotalLength = IP_HEADER_SIZE + tcpLayer->getDataLen();
    ipLayer->getIPv4Header()->totalLength = htons(ipTotalLength);
    
    if (!current_packet_errors.empty()) {
        stats.packet_failure_details.push_back(current_packet_errors);
    }

    if (packet_valid) {
        tcpPacket.computeCalculateFields();
        stats.packets_created_successfully++;
    } else {
        stats.recovery_attempts["INVALID_PACKET"]++;
        throw std::runtime_error("Packet contained invalid fields");
    }

    return tcpPacket;
}

// ============================================================================
// Flow processing
// ============================================================================

static void skipToNextPacket(const std::vector<int>& flow_tokens, size_t& index) {
    index++;
    while (index < flow_tokens.size() && 
           flow_tokens[index] != TOKEN_PKT_SIZE && 
           flow_tokens[index] != TOKEN_FORWARD && 
           flow_tokens[index] != TOKEN_REVERSE && 
           flow_tokens[index] != TOKEN_EOS) {
        index++;
    }
}

static void printFlowStats(const PacketCreationStats& stats) {
    std::cout << "\nTotal packets attempted: " << stats.total_packets_attempted << std::endl;
    std::cout << "Packets created successfully: " << stats.packets_created_successfully << std::endl;
    
    double success_rate = stats.total_packets_attempted > 0 
        ? 100.0 * stats.packets_created_successfully / stats.total_packets_attempted 
        : 0.0;
    std::cout << "Success rate: " << success_rate << "%" << std::endl;
    
    if (!stats.packet_failure_details.empty()) {
        std::cout << "\nPer-packet failure details:" << std::endl;
        for (size_t i = 0; i < stats.packet_failure_details.size(); i++) {
            std::cout << "  Packet " << (i+1) << " failures:" << std::endl;
            for (const auto& [field, reason] : stats.packet_failure_details[i]) {
                std::cout << "    - " << field << ": " << reason << std::endl;
            }
        }
    }
    
    if (!stats.field_failures.empty()) {
        std::cout << "\nField failure summary:" << std::endl;
        for (const auto& [field, count] : stats.field_failures) {
            std::cout << "  " << field << ": " << count << " occurrences" << std::endl;
        }
    }
}

std::pair<std::vector<pcpp::Packet>, PacketCreationStats> processFlowTokens(const std::vector<int>& flow_tokens) {
    std::vector<pcpp::Packet> packets;
    PacketCreationStats stats;
    if (flow_tokens.empty()) return {packets, stats};

    size_t index = 0;
    size_t packet_number = 0;

    // Skip flow type token
    int flow_type = flow_tokens[index++];

    // Generate IPs for this flow
    std::string ip1 = generateRandomIP();
    std::string ip2 = generateRandomIP();
    bool current_direction_forward = true;
    
    while (index < flow_tokens.size()) {
        int current_token = flow_tokens[index];
        
        if (current_token == TOKEN_FORWARD || current_token == TOKEN_REVERSE) {
            current_direction_forward = (current_token == TOKEN_FORWARD);
            index++;
            continue;
        }
        
        if (current_token == TOKEN_EOS) {
            break;
        }
        
        if (current_token == TOKEN_PKT_SIZE) {
            stats.total_packets_attempted++;
            packet_number++;
            
            try {
                pcpp::Packet packet = createTcpPacketFromIntSequence(
                    flow_tokens,
                    current_direction_forward ? ip1 : ip2,
                    current_direction_forward ? ip2 : ip1,
                    index, stats, packet_number);
                packets.push_back(packet);
            } catch (const std::exception& e) {
                skipToNextPacket(flow_tokens, index);
            }
        } else {
            index++;
        }
    }

    printFlowStats(stats);
    return {packets, stats};
}
