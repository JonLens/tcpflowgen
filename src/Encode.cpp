#include "Encode.h"
#include "FlowUtils.h"
#include <vector>
#include <map>
#include <algorithm>

// ============================================================================
// Encoding helpers
// ============================================================================

static std::vector<int> process_tcp_options(const std::vector<uint8_t>& options_raw) {
    std::vector<int> tokens;
    
    for (size_t i = 0; i < options_raw.size(); i += 2) {
        uint16_t high = options_raw[i];
        uint16_t low  = (i + 1 < options_raw.size()) ? options_raw[i + 1] : 0x00;
        tokens.push_back(static_cast<int>((high << 8) | low));
    }
    
    return tokens;
}

// ============================================================================
// Packet tokenization
// ============================================================================

static void push_token(std::vector<int>& tokens, uint32_t value, int num_bytes) {
    uint32_t mask = (num_bytes >= 4) ? 0xFFFFFFFF : (1u << (num_bytes * 8)) - 1;
    tokens.push_back(static_cast<int>(value & mask));
}

static void tokenize_packet(const PacketInfo& pkt, std::vector<int>& token_ids) {
    // Direction
    token_ids.push_back(pkt.direction == "forward" ? TOKEN_FORWARD : TOKEN_REVERSE);
    
    // Packet size
    token_ids.push_back(TOKEN_PKT_SIZE);
    token_ids.push_back(static_cast<int>(pkt.pkt_size));
    
    // Header marker
    token_ids.push_back(TOKEN_HEAD);
    
    // Source & destination ports (2 bytes each)
    push_token(token_ids, pkt.src_port, 2);
    push_token(token_ids, pkt.dst_port, 2);
    
    // Sequence number (4 bytes -> 2 tokens)
    push_token(token_ids, pkt.seq >> 16, 2);
    push_token(token_ids, pkt.seq & 0xFFFF, 2);
    
    // ACK number (4 bytes -> 2 tokens)
    push_token(token_ids, pkt.ack >> 16, 2);
    push_token(token_ids, pkt.ack & 0xFFFF, 2);
    
    // Data offset, reserved, flags (1 byte each)
    push_token(token_ids, pkt.data_offset, 1);
    push_token(token_ids, 0, 1);  // Reserved bits always 0
    push_token(token_ids, pkt.flags, 1);
    
    // Window size (2 bytes)
    push_token(token_ids, pkt.window_size, 2);
    
    // Checksum placeholder
    token_ids.push_back(0);
    
    // Urgent pointer (2 bytes)
    push_token(token_ids, pkt.urgent_ptr, 2);
    
    // TCP options
    for (int token : process_tcp_options(pkt.options)) {
        token_ids.push_back(token);
    }
}

// ============================================================================
// Flow tokenization
// ============================================================================

static int flow_type_to_token(const std::string& flow_type) {
    if (flow_type == "complete") return TOKEN_COMPLETE;
    if (flow_type == "start")    return TOKEN_START;
    if (flow_type == "end")      return TOKEN_END;
    return TOKEN_FREE;
}

std::vector<std::vector<int>> tokenize_headers(const std::map<FlowKey, FlowInfo>& tcp_flows) {
    std::vector<std::vector<int>> flow_token_ids;
    
    for (const auto& [flow_key, flow_info] : tcp_flows) {
        std::vector<int> token_ids;
        
        token_ids.push_back(flow_type_to_token(flow_info.flow_type));
        
        for (const auto& pkt_info : flow_info.packets) {
            tokenize_packet(pkt_info, token_ids);
        }
        
        token_ids.push_back(TOKEN_EOS);
        flow_token_ids.push_back(token_ids);
    }
    
    return flow_token_ids;
}
