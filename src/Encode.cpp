#include "Encode.h"
#include "FlowUtils.h"
#include <iomanip>
#include <sstream>
#include <vector>
#include <map>
#include <algorithm>
#include <iostream>

// Helper to convert value to 4-character hex string (0000-FFFF)
static std::string to_fixed_hex(uint32_t value, int num_bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0') << std::uppercase;
    
    // Calculate maximum value for the given number of bytes
    uint32_t max_val = (1 << (num_bytes * 8)) - 1;
    value &= max_val;  // Ensure value fits in the specified bytes
    
    // Always output 4 chars, padding with zeros if needed
    ss << std::setw(4) << value;
    return ss.str();
}

// Process TCP options into 4-character hex chunks
static std::vector<std::string> process_tcp_options(const std::vector<uint8_t>& options_raw) {
    std::vector<std::string> hex_chunks;
    std::string hex_str;
    
    // Convert all bytes to 2-character hex strings
    for (uint8_t byte : options_raw) {
        hex_str += to_fixed_hex(byte, 1).substr(2, 2); // Get just the 2 hex chars
    }
    
    // Split into 4-character chunks (2 bytes each)
    for (size_t i = 0; i < hex_str.length(); i += 4) {
        // Get up to 4 characters (or whatever remains)
        size_t chunk_len = std::min((size_t)4, hex_str.length() - i);
        std::string chunk = hex_str.substr(i, chunk_len);
        
        // Pad with zeros if needed to make 4 characters
        if (chunk_len < 4) {
            chunk.append(4 - chunk_len, '0');
        }
        
        hex_chunks.push_back(chunk);
    }
    
    return hex_chunks;
}

std::vector<std::vector<int>> tokenize_headers(const std::map<FlowKey, FlowInfo>& tcp_flows) {
    std::vector<std::vector<int>> flow_token_ids;
    // bool first_flow_processed = false; // Comment this out
    
    for (const auto& [flow_key, flow_info] : tcp_flows) {
        // if (first_flow_processed) { // Comment this out
        //     break; // Stop after first flow
        // }
        
        std::vector<int> token_ids;
        
        // std::cout << "=== Processing new flow ===" << std::endl;
        
        // Add flow type token
        const char* flow_type_str = "";
        if (flow_info.flow_type == "complete") {
            token_ids.push_back(TOKEN_COMPLETE);
            flow_type_str = "COMPLETE";
        } else if (flow_info.flow_type == "start") {
            token_ids.push_back(TOKEN_START);
            flow_type_str = "START";
        } else if (flow_info.flow_type == "end") {
            token_ids.push_back(TOKEN_END);
            flow_type_str = "END";
        } else {
            token_ids.push_back(TOKEN_FREE);
            flow_type_str = "FREE";
        }
        // std::cout << "Flow type: " << flow_type_str << " = " << token_ids.back() 
        //           << " (0x" << to_fixed_hex(token_ids.back(), 2) << ")" << std::endl;
        
        int packet_count = 0;
        for (const auto& pkt_info : flow_info.packets) {
            packet_count++;
            //bool print_details = (packet_count <= 5); // Only print first x packets
            bool print_details = false;
            
            if (print_details) {
                std::cout << "\nProcessing packet " << packet_count << " (" << pkt_info.direction << ")" << std::endl;
            }
            
            // Add direction token
            token_ids.push_back(pkt_info.direction == "forward" ? TOKEN_FORWARD : TOKEN_REVERSE);
            if (print_details) {
                const char* direction_str = pkt_info.direction == "forward" ? "FORWARD" : "REVERSE";
                std::cout << "Direction: " << direction_str << " = " << token_ids.back() 
                          << " (0x" << to_fixed_hex(token_ids.back(), 2) << ")" << std::endl;
            }
            
            // Add packet size
            token_ids.push_back(TOKEN_PKT_SIZE);
            uint64_t pkt_size = pkt_info.pkt_size;
            if(print_details){
                std::cout << "TCP Data length: " << pkt_size << std::endl;
            }
            token_ids.push_back(pkt_size);            

            // Add header token
            token_ids.push_back(TOKEN_HEAD);
            if (print_details) {
                std::cout << "Header start: HEAD = " << token_ids.back() 
                          << " (0x" << to_fixed_hex(token_ids.back(), 2) << ")" << std::endl;
            }
            
            // Source port (2 bytes)
            std::string src_port_hex = to_fixed_hex(pkt_info.src_port, 2);
            token_ids.push_back(std::stoi(src_port_hex, nullptr, 16));
            if (print_details) {
                std::cout << "Source port: " << pkt_info.src_port << " = " << token_ids.back() 
                          << " (0x" << src_port_hex << ")" << std::endl;
            }
            
            // Destination port (2 bytes)
            std::string dst_port_hex = to_fixed_hex(pkt_info.dst_port, 2);
            token_ids.push_back(std::stoi(dst_port_hex, nullptr, 16));
            if (print_details) {
                std::cout << "Dest port: " << pkt_info.dst_port << " = " << token_ids.back() 
                          << " (0x" << dst_port_hex << ")" << std::endl;
            }
            
            // Sequence number (4 bytes -> 2 tokens)

            uint16_t seq_high = pkt_info.seq >> 16;
            std::string seq_high_hex = to_fixed_hex(seq_high, 2);
            token_ids.push_back(std::stoi(seq_high_hex, nullptr, 16));
            if (print_details) {
                std::cout << "Sequence Number: " << pkt_info.seq << std::endl;
                std::cout << "\nSeq high: " << seq_high << " = " << token_ids.back() 
                          << " (0x" << seq_high_hex << ")" << std::endl;
            }
            
            uint16_t seq_low = pkt_info.seq & 0xFFFF;
            std::string seq_low_hex = to_fixed_hex(seq_low, 2);
            token_ids.push_back(std::stoi(seq_low_hex, nullptr, 16));
            if (print_details) {
                std::cout << "Seq low: " << seq_low << " = " << token_ids.back() 
                          << " (0x" << seq_low_hex << ")" << std::endl;
            }
            
            // ACK number (4 bytes -> 2 tokens)
            uint16_t ack_high = pkt_info.ack >> 16;
            std::string ack_high_hex = to_fixed_hex(ack_high, 2);
            token_ids.push_back(std::stoi(ack_high_hex, nullptr, 16));
            if (print_details) {
                std::cout << "Ack high: " << ack_high << " = " << token_ids.back() 
                          << " (0x" << ack_high_hex << ")" << std::endl;
            }
            
            uint16_t ack_low = pkt_info.ack & 0xFFFF;
            std::string ack_low_hex = to_fixed_hex(ack_low, 2);
            token_ids.push_back(std::stoi(ack_low_hex, nullptr, 16));
            if (print_details) {
                std::cout << "Ack low: " << ack_low << " = " << token_ids.back() 
                          << " (0x" << ack_low_hex << ")" << std::endl;
            }
            
            // Data offset (4 bits) - separate token
            uint8_t data_offset = pkt_info.data_offset;
            std::string data_offset_hex = to_fixed_hex(data_offset, 1);
            token_ids.push_back(std::stoi(data_offset_hex, nullptr, 16));
            if (print_details) {
                std::cout << "Data offset: " << (int)data_offset << " = " << token_ids.back()
                          << " (0x" << data_offset_hex << ")" << std::endl;
            }
            
            // Reserved bits (4 bits) - separate token
            uint8_t reserved = 0; // Reserved bits are always 0 in standard TCP
            std::string reserved_hex = to_fixed_hex(reserved, 1);
            token_ids.push_back(std::stoi(reserved_hex, nullptr, 16));
            if (print_details) {
                std::cout << "Reserved: " << (int)reserved << " = " << token_ids.back()
                          << " (0x" << reserved_hex << ")" << std::endl;
            }
            
            // Flags (8 bits)
            uint8_t tcp_flags = pkt_info.flags;
            std::string flags_hex = to_fixed_hex(tcp_flags, 1);
            token_ids.push_back(std::stoi(flags_hex, nullptr, 16));
            if (print_details) {
                std::cout << "Flags: ";
                if (tcp_flags & 0x80) std::cout << "CWR ";
                if (tcp_flags & 0x40) std::cout << "ECE ";
                if (tcp_flags & 0x20) std::cout << "URG ";
                if (tcp_flags & 0x10) std::cout << "ACK ";
                if (tcp_flags & 0x08) std::cout << "PSH ";
                if (tcp_flags & 0x04) std::cout << "RST ";
                if (tcp_flags & 0x02) std::cout << "SYN ";
                if (tcp_flags & 0x01) std::cout << "FIN ";
                std::cout << "= " << token_ids.back() 
                          << " (0x" << flags_hex << ")" << std::endl;
            }
            
            // Window size (2 bytes)
            std::string window_hex = to_fixed_hex(pkt_info.window_size, 2);
            token_ids.push_back(std::stoi(window_hex, nullptr, 16));
            if (print_details) {
                std::cout << "Window: " << pkt_info.window_size << " = " << token_ids.back() 
                          << " (0x" << window_hex << ")" << std::endl;
            }
            
            // Checksum (2 bytes)
            // std::string checksum_hex = to_fixed_hex(pkt_info.checksum, 2);
            // token_ids.push_back(std::stoi(checksum_hex, nullptr, 16));
            token_ids.push_back(0);
            if (print_details) {
                // std::cout << "Checksum: " << pkt_info.checksum << " = " << token_ids.back() 
                //           << " (0x" << checksum_hex << ")" << std::endl;
                std::cout << "Checksum: " << "0" << " = " << token_ids.back() 
                          << std::endl;
            }
            
            // Urgent pointer (2 bytes)
            std::string urgent_hex = to_fixed_hex(pkt_info.urgent_ptr, 2);
            token_ids.push_back(std::stoi(urgent_hex, nullptr, 16));
            if (print_details) {
                std::cout << "Urgent ptr: " << pkt_info.urgent_ptr << " = " << token_ids.back() 
                          << " (0x" << urgent_hex << ")" << std::endl;
            }
            
            // TCP options
            auto option_chunks = process_tcp_options(pkt_info.options);
            if (print_details && !option_chunks.empty()) {
                std::cout << "TCP Options:" << std::endl;
            }
            for (const auto& chunk : option_chunks) {
                token_ids.push_back(std::stoi(chunk, nullptr, 16));
                if (print_details) {
                    std::cout << "  Option chunk: " << token_ids.back() 
                              << " (0x" << chunk << ")" << std::endl;
                }
            }
            
            // if (packet_count == 2 && flow_info.packets.size() > 2) {
            //     std::cout << "\n... (skipping detailed output for remaining " 
            //               << (flow_info.packets.size() - 2) << " packets in flow)\n";
            // }
        }
        token_ids.push_back(TOKEN_EOS);
        flow_token_ids.push_back(token_ids);
        // first_flow_processed = true; // Comment this out
    }
    
    return flow_token_ids;
}