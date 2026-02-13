#ifndef DECODE_H
#define DECODE_H

#include <vector>
#include <map>
#include <string>
#include "Packet.h"
#include "FlowUtils.h"

struct GlobalStats {
    size_t total_flows = 0;
    size_t total_packets_attempted = 0;
    size_t total_packets_successful = 0;
    std::map<std::string, size_t> field_failures;
    std::vector<std::map<std::string, std::string>> packet_failure_details;
    size_t flows_with_valid_syn = 0;
    size_t flows_with_valid_fin = 0;
    size_t flows_with_both_valid = 0;
    std::map<std::string, size_t> missing_flags_counts;
};

struct PacketCreationStats {
    size_t total_packets_attempted = 0;
    size_t packets_created_successfully = 0;
    std::map<std::string, size_t> field_failures;
    std::map<std::string, size_t> recovery_attempts;
    std::vector<std::map<std::string, std::string>> packet_failure_details;
};

struct FlowValidationStats {
    bool has_valid_syn_sequence = false;
    bool has_valid_fin_sequence = false;
    std::vector<std::string> missing_flags;
    std::vector<std::string> unexpected_flags;
};

FlowValidationStats validateFlowSemantics(const std::vector<pcpp::Packet>& packets);

std::vector<std::vector<int>> load_tokens_arrow(const std::string& filename);

std::string generateRandomIP();

pcpp::Packet createTcpPacketFromIntSequence(
    const std::vector<int>& flow_tokens,
    const std::string& srcIP,
    const std::string& dstIP,
    size_t& index,
    PacketCreationStats& stats,
    size_t packet_number);

std::pair<std::vector<pcpp::Packet>, PacketCreationStats> processFlowTokens(
    const std::vector<int>& flow_tokens);

#endif // DECODE_H
