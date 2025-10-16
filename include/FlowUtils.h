#ifndef FLOW_UTILS_H
#define FLOW_UTILS_H

#include <string>
#include <arrow/api.h>
#include <arrow/ipc/api.h>
#include <arrow/io/api.h>
#include <arrow/builder.h>
#include <memory>
#include <vector>
#include <iostream>
#include <map>
#include <cstdint>

struct PacketInfo {
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t flags;
    uint32_t seq;
    uint32_t ack;
    uint8_t data_offset;
    uint16_t window_size;
    // uint16_t checksum;
    uint16_t urgent_ptr;
    std::vector<uint8_t> options;
    size_t pkt_size;
    size_t data_len;
    std::string direction;
    uint64_t timestamp_microsec;
    uint64_t time_delta_microsec;
};

struct FlowKey {
    std::string src_ip;
    uint16_t src_port;
    std::string dst_ip;
    uint16_t dst_port;
    // bool is_client;
    
    FlowKey(const std::string& ip1, uint16_t port1, const std::string& ip2, uint16_t port2);
    bool operator<(const FlowKey& other) const;
};

struct FlowInfo {
    std::vector<PacketInfo> packets;
    std::string flow_type;
};

arrow::Status save_tokens_arrow(const std::vector<std::vector<int>>& tokens, 
    const std::string& filepath);
    
#endif // FLOW_UTILS_H