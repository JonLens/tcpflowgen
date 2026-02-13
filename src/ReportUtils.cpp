#include "ReportUtils.h"
#include <iostream>
#include <numeric>
#include <algorithm>

// ============================================================================
// Formatting helpers
// ============================================================================

std::string format_flags(uint8_t flags) {
    std::string result;
    if (flags & 0x01) result += "FIN,";
    if (flags & 0x02) result += "SYN,";
    if (flags & 0x04) result += "RST,";
    if (flags & 0x08) result += "PSH,";
    if (flags & 0x10) result += "ACK,";
    if (flags & 0x20) result += "URG,";
    if (flags & 0x40) result += "ECE,";
    if (flags & 0x80) result += "CWR,";
    if (!result.empty()) result.pop_back();
    return result;
}

void print_table_row(const char* label, size_t value, int label_width) {
    printf("| %-*s | %-10zu |\n", label_width, label, value);
}

void print_table_row_pct(const char* label, double value, int label_width) {
    printf("| %-*s | %-10.1f%% |\n", label_width, label, value);
}

void print_table_separator(int label_width) {
    std::cout << "+" << std::string(label_width + 2, '-') << "+" << std::string(12, '-') << "+" << std::endl;
}

void print_table_header(const char* col1, const char* col2, int label_width) {
    print_table_separator(label_width);
    printf("| %-*s | %-10s |\n", label_width, col1, col2);
    print_table_separator(label_width);
}

// ============================================================================
// Summary printing
// ============================================================================

void print_processing_summary(const std::string& title,
                              const std::string& inputPath,
                              const std::string& outputDir,
                              size_t processed_files,
                              size_t total_files,
                              size_t total_count,
                              const std::string& count_label,
                              long long duration_ms) {
    std::cout << "\n=== " << title << " ===" << std::endl;
    std::cout << "Input: " << inputPath << std::endl;
    std::cout << "Output directory: " << outputDir << std::endl;
    std::cout << "Files processed: " << processed_files << "/" << total_files << std::endl;
    std::cout << count_label << ": " << total_count << std::endl;
    std::cout << "Total processing time: " << duration_ms << " ms" << std::endl;
    std::cout << "Average time per file: " << (total_files == 0 ? 0 : duration_ms / total_files) << " ms" << std::endl;
}

void print_complete_flow_summary(const FlowKey& flow_key, const FlowInfo& flow_info) {
    std::cout << "\nFlow: " << flow_key.src_ip << ":" << flow_key.src_port 
              << " → " << flow_key.dst_ip << ":" << flow_key.dst_port << std::endl;
    std::cout << "Last 4 packets flags:" << std::endl;
    
    size_t start_idx = flow_info.packets.size() > 4 ? flow_info.packets.size() - 4 : 0;
    for (size_t i = start_idx; i < flow_info.packets.size(); i++) {
        std::cout << "  Packet " << i+1 << "/" << flow_info.packets.size() 
                  << ": " << format_flags(flow_info.packets[i].flags) << std::endl;
    }
}

// ============================================================================
// CSV helpers
// ============================================================================

bool save_csv(const fs::path& path,
              const std::string& header,
              const std::function<void(std::ofstream&)>& writer) {
    std::ofstream file(path);
    if (!file.is_open()) {
        std::cerr << "Warning: Could not open " << path.string() << " for writing\n";
        return false;
    }
    file << header << "\n";
    writer(file);
    file.close();
    std::cout << "Saved data to " << path.string() << std::endl;
    return true;
}

// ============================================================================
// Decode stats & reporting
// ============================================================================

void accumulate_global_stats(GlobalStats& global_stats,
                             const PacketCreationStats& stats,
                             const FlowValidationStats& flow_validation) {
    global_stats.total_flows++;
    global_stats.total_packets_attempted += stats.total_packets_attempted;
    global_stats.total_packets_successful += stats.packets_created_successfully;

    for (const auto& [field, count] : stats.field_failures) {
        global_stats.field_failures[field] += count;
    }
    global_stats.packet_failure_details.insert(
        global_stats.packet_failure_details.end(),
        stats.packet_failure_details.begin(),
        stats.packet_failure_details.end()
    );

    if (flow_validation.has_valid_syn_sequence) global_stats.flows_with_valid_syn++;
    if (flow_validation.has_valid_fin_sequence) global_stats.flows_with_valid_fin++;
    if (flow_validation.has_valid_syn_sequence && flow_validation.has_valid_fin_sequence) {
        global_stats.flows_with_both_valid++;
    }
    for (const auto& flag : flow_validation.missing_flags) {
        global_stats.missing_flags_counts[flag]++;
    }
}

void save_decode_csvs(const fs::path& outputDir,
                      const std::map<size_t, size_t>& packet_count_distribution,
                      const GlobalStats& global_stats,
                      const std::vector<std::tuple<size_t, FlowValidationStats>>& all_flow_validations) {
    // Packet distribution
    save_csv(outputDir / "packet_distribution.csv", "packets_per_flow,flow_count",
        [&](std::ofstream& f) {
            for (const auto& [pkt_count, flow_count] : packet_count_distribution) {
                f << pkt_count << "," << flow_count << "\n";
            }
        });

    // Field failures (sorted by count descending)
    save_csv(outputDir / "field_failures.csv", "field,count",
        [&](std::ofstream& f) {
            std::vector<std::pair<std::string, size_t>> sorted(
                global_stats.field_failures.begin(), global_stats.field_failures.end());
            std::sort(sorted.begin(), sorted.end(),
                [](const auto& a, const auto& b) { return a.second > b.second; });
            for (const auto& [field, count] : sorted) {
                f << field << "," << count << "\n";
            }
        });

    // Flow validation
    save_csv(outputDir / "flow_validation.csv", "validation_type,count",
        [&](std::ofstream& f) {
            size_t valid_syn_only = 0, valid_fin_only = 0, valid_both = 0, invalid_both = 0;
            std::map<std::string, size_t> missing_flag_counts;
            
            for (const auto& [idx, v] : all_flow_validations) {
                if (v.has_valid_syn_sequence && v.has_valid_fin_sequence) valid_both++;
                else if (v.has_valid_syn_sequence) valid_syn_only++;
                else if (v.has_valid_fin_sequence) valid_fin_only++;
                else invalid_both++;
                for (const auto& flag : v.missing_flags) missing_flag_counts[flag]++;
            }
            
            f << "valid_syn_only," << valid_syn_only << "\n";
            f << "valid_fin_only," << valid_fin_only << "\n";
            f << "valid_both," << valid_both << "\n";
            f << "invalid_both," << invalid_both << "\n";
            
            f << "\nmissing_flag,count\n";
            for (const auto& [flag, count] : missing_flag_counts) {
                f << flag << "," << count << "\n";
            }
            
            f << "\nflow_details\n";
            f << "flow_index,valid_syn,valid_fin,missing_flags\n";
            for (const auto& [idx, v] : all_flow_validations) {
                f << idx << "," << v.has_valid_syn_sequence << "," << v.has_valid_fin_sequence << ",\"";
                for (size_t i = 0; i < v.missing_flags.size(); i++) {
                    if (i > 0) f << ";";
                    f << v.missing_flags[i];
                }
                f << "\"\n";
            }
        });
}

void print_decode_metrics(const GlobalStats& global_stats,
                          const std::vector<size_t>& packets_per_flow,
                          const std::map<size_t, size_t>& packet_count_distribution) {
    std::cout << "\n\n=== Evaluation Metrics Summary ===" << std::endl;
    print_table_header("Metric", "Value");
    print_table_row("Total Flows", global_stats.total_flows);
    print_table_row("Total Packets Attempted", global_stats.total_packets_attempted);
    print_table_row("Successful Packets", global_stats.total_packets_successful);
    double success_rate = global_stats.total_packets_attempted > 0 
        ? 100.0 * global_stats.total_packets_successful / global_stats.total_packets_attempted : 0;
    print_table_row_pct("Success Rate", success_rate);
    print_table_separator();

    if (!packets_per_flow.empty()) {
        size_t min_p = *std::min_element(packets_per_flow.begin(), packets_per_flow.end());
        size_t max_p = *std::max_element(packets_per_flow.begin(), packets_per_flow.end());
        double avg_p = std::accumulate(packets_per_flow.begin(), packets_per_flow.end(), 0.0) / packets_per_flow.size();
        
        std::cout << "\nPacket Distribution per Flow:" << std::endl;
        print_table_header("Metric", "Value");
        print_table_row("Minimum packets per flow", min_p);
        print_table_row("Maximum packets per flow", max_p);
        printf("| %-24s | %-10.1f |\n", "Average packets per flow", avg_p);
        print_table_separator();
        
        std::cout << "\nPacket Count Distribution:" << std::endl;
        print_table_header("Packets", "Flows", 10);
        for (const auto& [count, flows] : packet_count_distribution) {
            printf("| %-10zu | %-10zu |\n", count, flows);
        }
        print_table_separator(10);
    }

    if (!global_stats.field_failures.empty()) {
        std::cout << "\nTop Field Failures:" << std::endl;
        print_table_header("Field", "Count");
        for (const auto& [field, count] : global_stats.field_failures) {
            printf("| %-24s | %-10zu |\n", field.c_str(), count);
        }
        print_table_separator();
    }

    std::cout << "\nFlow Validation Summary:" << std::endl;
    print_table_header("Metric", "Value", 30);
    print_table_row("Flows with valid SYN sequence", global_stats.flows_with_valid_syn, 30);
    print_table_row("Flows with valid FIN sequence", global_stats.flows_with_valid_fin, 30);
    print_table_row("Flows with both valid", global_stats.flows_with_both_valid, 30);
    
    auto safe_pct = [&](size_t num) { 
        return global_stats.total_flows > 0 ? 100.0 * num / global_stats.total_flows : 0; 
    };
    print_table_row_pct("Valid SYN sequence rate", safe_pct(global_stats.flows_with_valid_syn), 30);
    print_table_row_pct("Valid FIN sequence rate", safe_pct(global_stats.flows_with_valid_fin), 30);
    print_table_row_pct("Complete flow rate", safe_pct(global_stats.flows_with_both_valid), 30);
    print_table_separator(30);

    if (!global_stats.missing_flags_counts.empty()) {
        std::cout << "\nMissing Flags Summary:" << std::endl;
        print_table_header("Missing Flag", "Count", 30);
        for (const auto& [flag, count] : global_stats.missing_flags_counts) {
            printf("| %-30s | %-10zu |\n", flag.c_str(), count);
        }
        print_table_separator(30);
    }
}
