#include <iostream>
#include <chrono>
#include <filesystem>
namespace fs = std::filesystem;
#include "FlowExtractor.h"
#include "Encode.h"
#include "Decode.h"
#include "Packet.h"
#include "PcapFileDevice.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "SystemUtils.h"

void print_usage() {
    std::cerr << "Usage:\n"
              << "  Encode mode: " << program_invocation_short_name << " encode <input_pcap_or_directory> <output_arrow_directory>\n"
              << "  Decode mode: " << program_invocation_short_name << " decode <input_arrow_directory> <output_pcap_directory>\n";
}

int encode_mode(const std::string& inputPath, const std::string& outputDir) {
    // Create output directory if it doesn't exist
    if (!fs::exists(outputDir)) {
        if (!fs::create_directories(outputDir)) {
            std::cerr << "Error: Failed to create output directory " << outputDir << std::endl;
            return 1;
        }
    }

    std::vector<fs::path> pcapFiles;

    // Check if input is directory or single file
    if (fs::is_directory(inputPath)) {
        // Collect all .pcap files in directory
        for (const auto& entry : fs::directory_iterator(inputPath)) {
            if (entry.path().extension() == ".pcap" || 
                entry.path().extension() == ".pcapng") {
                pcapFiles.push_back(entry.path());
            }
        }
        
        if (pcapFiles.empty()) {
            std::cerr << "Error: No .pcap files found in directory " << inputPath << std::endl;
            return 1;
        }
    } else {
        // Single file mode
        if (!fs::exists(inputPath)) {
            std::cerr << "Error: Input file " << inputPath << " does not exist" << std::endl;
            return 1;
        }
        pcapFiles.push_back(inputPath);
    }

    auto start_time = std::chrono::high_resolution_clock::now();
    size_t total_flows = 0;
    size_t total_packets = 0;
    size_t processed_files = 0;

    try {
        for (const auto& pcapFile : pcapFiles) {
            std::cout << "\nProcessing file: " << pcapFile.string() << std::endl;
            
            std::map<FlowKey, FlowInfo> categorized_flows;
            uint64_t packet_count = 0;
            std::map<std::string, int> flow_type_counts;

            process_pcap_file(pcapFile.string(), categorized_flows, packet_count, flow_type_counts);
            total_packets += packet_count;

            // Filter for complete flows only
            std::map<FlowKey, FlowInfo> complete_flows;
            for (const auto& [flow_key, flow_info] : categorized_flows) {
                if (flow_info.flow_type == "complete") {
                    complete_flows[flow_key] = flow_info;
                    // std::cout << "\nFlow: " << flow_key.src_ip << ":" << flow_key.src_port << " → " << flow_key.dst_ip << ":" << flow_key.dst_port;
                    // Print the last 4 packets' flags for each flow
                    std::cout << "\nFlow: " << flow_key.src_ip << ":" << flow_key.src_port 
                              << " → " << flow_key.dst_ip << ":" << flow_key.dst_port << std::endl;
                    std::cout << "Last 4 packets flags:" << std::endl;
                    
                    // Get the last 4 packets (or all if less than 4)
                    size_t start_idx = flow_info.packets.size() > 4 ? flow_info.packets.size() - 4 : 0;
                    for (size_t i = start_idx; i < flow_info.packets.size(); i++) {
                        const auto& packet = flow_info.packets[i];
                        std::cout << "  Packet " << i+1 << "/" << flow_info.packets.size() 
                                  << ": ";
                        
                        // Print flags based on the flags byte
                        if (packet.flags & 0x01) std::cout << "FIN,";
                        if (packet.flags & 0x02) std::cout << "SYN,";
                        if (packet.flags & 0x04) std::cout << "RST,";
                        if (packet.flags & 0x08) std::cout << "PSH,";
                        if (packet.flags & 0x10) std::cout << "ACK,";
                        if (packet.flags & 0x20) std::cout << "URG,";
                        if (packet.flags & 0x40) std::cout << "ECE,";
                        if (packet.flags & 0x80) std::cout << "CWR,";
                        
                        // // Remove trailing comma if any
                        // std::string flags_str = std::cout.str();
                        // if (!flags_str.empty() && flags_str.back() == ',') {
                        //     flags_str.pop_back();
                        // }
                        // std::cout << flags_str << std::endl;
                    }
                }
            }

            // Tokenize the flows
            auto tokenized_flows = tokenize_headers(complete_flows);
            if (tokenized_flows.empty()) {
                std::cout << "Warning: No complete flows found in " << pcapFile.filename() << std::endl;
                continue;
            }
            
            total_flows += tokenized_flows.size();
            
            std::cout << "\nNumber of flows: " << tokenized_flows.size() << std::endl;
            size_t total_tokens = 0;
            for(const auto& seq : tokenized_flows) {
                total_tokens += seq.size();
            }
            std::cout << "Total number of tokens: " << total_tokens << std::endl;

            // Create output filename in the specified directory
            fs::path outputPath = fs::path(outputDir) / pcapFile.filename().replace_extension(".arrow");
            
            // Save to arrow file
            arrow::Status status = save_tokens_arrow(tokenized_flows, outputPath.string());
            if (!status.ok()) {
                std::cerr << "Error saving tokens: " << status.ToString() << std::endl;
                continue;  // Skip to next file instead of exiting
            }
            processed_files++;
            std::cout << "Tokens saved successfully to " << outputPath.string() << std::endl;

            // Print file-specific stats
            std::cout << "Processed " << packet_count << " TCP packets" << std::endl;
            std::cout << "Flow type statistics:" << std::endl;
            for (const auto& count : flow_type_counts) {
                std::cout << "  " << count.first << ": " << count.second << std::endl;
            }
            // std::cout << "\nTokenized flows sample:" << std::endl;
            // for (size_t i = 0; i < std::min(tokenized_flows.size(), static_cast<size_t>(3)); i++) {
            //     std::cout << "Flow " << i << " tokens: ";
            //     for (const auto& token : tokenized_flows[i]) {
            //         std::cout << token << " ";
            //     }
            //     std::cout << std::endl;
            // }
        }

        // Print overall statistics
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
        
        std::cout << "\n=== Processing Summary ===" << std::endl;
        std::cout << "Input: " << inputPath << std::endl;
        std::cout << "Output directory: " << outputDir << std::endl;
        std::cout << "Files processed: " << processed_files << "/" << pcapFiles.size() << std::endl;
        std::cout << "Total packets processed: " << total_packets << std::endl;
        std::cout << "Total flows extracted: " << total_flows << std::endl;
        std::cout << "Total processing time: " << duration << " ms" << std::endl;
        std::cout << "Average time per file: " << (pcapFiles.empty() ? 0 : duration/pcapFiles.size()) << " ms" << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}

int decode_mode(const std::string& inputPath, const std::string& outputDir) {
    GlobalStats global_stats;
    // Create output directory if it doesn't exist
    if (!fs::exists(outputDir)) {
        if (!fs::create_directories(outputDir)) {
            std::cerr << "Error: Failed to create output directory " << outputDir << std::endl;
            return 1;
        }
    }

    std::vector<fs::path> arrowFiles;
    
    // Check if input is directory or single file
    if (fs::is_directory(inputPath)) {
        // Collect all .pcap files in directory
        for (const auto& entry : fs::directory_iterator(inputPath)) {
            if (entry.path().extension() == ".arrow") {
                arrowFiles.push_back(entry.path());
            }
        }
        
        if (arrowFiles.empty()) {
            std::cerr << "Error: No .arrow files found in directory " << inputPath << std::endl;
            return 1;
        }
    } else {
        // Single file mode
        if (!fs::exists(inputPath)) {
            std::cerr << "Error: Input file " << inputPath << " does not exist" << std::endl;
            return 1;
        }
        arrowFiles.push_back(inputPath);
    }    

    auto start_time = std::chrono::high_resolution_clock::now();
    size_t total_flows = 0;
    size_t processed_files = 0;
    std::vector<size_t> packets_per_flow;
    std::map<size_t, size_t> packet_count_distribution;
    std::vector<std::tuple<size_t, FlowValidationStats>> all_flow_validations;
    
    try {
        for (const auto& arrowFile : arrowFiles) {
            std::cout << "\nProcessing file: " << arrowFile.string() << std::endl;
            
            // Load tokenized flows from arrow file
            auto tokenized_flows = load_tokens_arrow(arrowFile.string());
            if (tokenized_flows.empty()) {
                std::cout << "Warning: No flows found in " << arrowFile.filename() << std::endl;
                continue;
            }
            // std::cout << "\nTokenized flows sample:" << std::endl;
            // for (size_t i = 0; i < std::min(tokenized_flows.size(), static_cast<size_t>(3)); i++) {
            //     std::cout << "Flow " << i << " tokens: ";
            //     for (const auto& token : tokenized_flows[i]) {
            //         std::cout << token << " ";
            //     }
            //     std::cout << std::endl;
            // }
            total_flows += tokenized_flows.size();
            std::cout << "Number of flows to decode: " << tokenized_flows.size() << std::endl;

            // Create output filename in the specified directory
            fs::path outputPath = fs::path(outputDir) / arrowFile.filename().replace_extension(".pcap");
            
            pcpp::PcapFileWriterDevice writer(outputPath.string());
            if (!writer.open()) {
                throw std::runtime_error("Cannot open output file " + outputPath.string());
            }
            
            // Process all flows
            for (size_t flow_idx = 0; flow_idx < tokenized_flows.size(); flow_idx++) {
                std::cout << "\n=============================" << std::endl;
                std::cout << "===== Processing Flow " << flow_idx + 1 << " =====" << std::endl;
                std::cout << "=============================" << std::endl;

                const auto& flow_tokens = tokenized_flows[flow_idx];
                
                // std::vector<pcpp::Packet> packets = processFlowTokens(flow_tokens);
                auto [packets, stats] = processFlowTokens(flow_tokens);
                size_t packet_count = packets.size();
                packets_per_flow.push_back(packet_count);
                packet_count_distribution[packet_count]++;
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
                // Semantic validity    
                auto flow_validation = validateFlowSemantics(packets);
                all_flow_validations.emplace_back(flow_idx, flow_validation);
                if (flow_validation.has_valid_syn_sequence) {
                    global_stats.flows_with_valid_syn++;
                }
                if (flow_validation.has_valid_fin_sequence) {
                    global_stats.flows_with_valid_fin++;
                }
                if (flow_validation.has_valid_syn_sequence && flow_validation.has_valid_fin_sequence) {
                    global_stats.flows_with_both_valid++;
                }

                for (const auto& flag : flow_validation.missing_flags) {
                    global_stats.missing_flags_counts[flag]++;
                }       
                // Write the packets         
                for (const auto& packet : packets) {
                    writer.writePacket(*packet.getRawPacket());
                }
            }
            
            writer.close();
            processed_files++;
            std::cout << "Decoded flows saved successfully to " << outputPath.string() << std::endl;
        }

        // Save packet count distribution to CSV
        fs::path statsPath = fs::path(outputDir) / "packet_distribution.csv";
        std::ofstream statsFile(statsPath);
        if (statsFile.is_open()) {
            statsFile << "packets_per_flow,flow_count\n";
            for (const auto& [packet_count, flow_count] : packet_count_distribution) {
                statsFile << packet_count << "," << flow_count << "\n";
            }
            statsFile.close();
            std::cout << "\nSaved packet distribution data to " << statsPath.string() << std::endl;
        } else {
            std::cerr << "Warning: Could not open " << statsPath.string() << " for writing packet distribution data\n";
        }
        // Save field failures to CSV
        fs::path errorsPath = fs::path(outputDir) / "field_failures.csv";
        std::ofstream errorsFile(errorsPath);
        if (errorsFile.is_open()) {
            errorsFile << "field,count\n";
            // Sort by count (descending) before saving
            std::vector<std::pair<std::string, size_t>> sorted_failures(
                global_stats.field_failures.begin(),
                global_stats.field_failures.end()
            );
            std::sort(
                sorted_failures.begin(),
                sorted_failures.end(),
                [](const auto& a, const auto& b) { return a.second > b.second; }
            );
            
            for (const auto& [field, count] : sorted_failures) {
                errorsFile << field << "," << count << "\n";
            }
            errorsFile.close();
            std::cout << "Saved field failure data to " << errorsPath.string() << std::endl;
        } else {
            std::cerr << "Warning: Could not open " << errorsPath.string() << " for writing field failure data\n";
        }

        // Save flow validation results to CSV with distribution counts
        fs::path validationPath = fs::path(outputDir) / "flow_validation.csv";
        std::ofstream validationFile(validationPath);
        if (validationFile.is_open()) {
            // First count all possible validation states
            size_t valid_syn_only = 0;
            size_t valid_fin_only = 0;
            size_t valid_both = 0;
            size_t invalid_both = 0;
            std::map<std::string, size_t> missing_flag_counts;
            
            for (const auto& [idx, validation] : all_flow_validations) {
                bool has_syn = validation.has_valid_syn_sequence;
                bool has_fin = validation.has_valid_fin_sequence;
                
                if (has_syn && has_fin) {
                    valid_both++;
                } else if (has_syn) {
                    valid_syn_only++;
                } else if (has_fin) {
                    valid_fin_only++;
                } else {
                    invalid_both++;
                }
                
                for (const auto& flag : validation.missing_flags) {
                    missing_flag_counts[flag]++;
                }
            }
            
            // Write the distribution summary
            validationFile << "validation_type,count\n";
            validationFile << "valid_syn_only," << valid_syn_only << "\n";
            validationFile << "valid_fin_only," << valid_fin_only << "\n";
            validationFile << "valid_both," << valid_both << "\n";
            validationFile << "invalid_both," << invalid_both << "\n";
            
            // Write missing flags distribution
            validationFile << "\nmissing_flag,count\n";
            for (const auto& [flag, count] : missing_flag_counts) {
                validationFile << flag << "," << count << "\n";
            }
            
            // Optional: Write per-flow details for debugging
            validationFile << "\nflow_details\n";
            validationFile << "flow_index,valid_syn,valid_fin,missing_flags\n";
            for (const auto& [idx, validation] : all_flow_validations) {
                validationFile << idx << "," 
                            << validation.has_valid_syn_sequence << ","
                            << validation.has_valid_fin_sequence << ",\"";
                for (size_t i = 0; i < validation.missing_flags.size(); i++) {
                    if (i > 0) validationFile << ";";
                    validationFile << validation.missing_flags[i];
                }
                validationFile << "\"\n";
            }
            
            validationFile.close();
            std::cout << "Saved detailed flow validation data to " << validationPath.string() << std::endl;
        } else {
            std::cerr << "Warning: Could not open " << validationPath.string() << " for writing flow validation data\n";
        }

        // At the end, print the summary table:
        std::cout << "\n\n=== Evaluation Metrics Summary ===" << std::endl;
        std::cout << "+--------------------------+------------+" << std::endl;
        std::cout << "| Metric                   | Value      |" << std::endl;
        std::cout << "+--------------------------+------------+" << std::endl;
        printf("| %-24s | %-10zu |\n", "Total Flows", global_stats.total_flows);
        printf("| %-24s | %-10zu |\n", "Total Packets Attempted", global_stats.total_packets_attempted);
        printf("| %-24s | %-10zu |\n", "Successful Packets", global_stats.total_packets_successful);
        printf("| %-24s | %-10.2f%% |\n", "Success Rate", 
            (global_stats.total_packets_attempted > 0 ? 
            (100.0 * global_stats.total_packets_successful / global_stats.total_packets_attempted) : 0));
        std::cout << "+--------------------------+------------+" << std::endl;

        // Print packet distribution per flow
        if (!packets_per_flow.empty()) {
            size_t min_packets = *std::min_element(packets_per_flow.begin(), packets_per_flow.end());
            size_t max_packets = *std::max_element(packets_per_flow.begin(), packets_per_flow.end());
            double avg_packets = std::accumulate(packets_per_flow.begin(), packets_per_flow.end(), 0.0) / packets_per_flow.size();
            
            std::cout << "\nPacket Distribution per Flow:" << std::endl;
            std::cout << "+--------------------------+------------+" << std::endl;
            printf("| %-24s | %-10zu |\n", "Minimum packets per flow", min_packets);
            printf("| %-24s | %-10zu |\n", "Maximum packets per flow", max_packets);
            printf("| %-24s | %-10.1f |\n", "Average packets per flow", avg_packets);
            std::cout << "+--------------------------+------------+" << std::endl;
            
            // Optional: Print histogram of packet counts
            std::map<size_t, size_t> packet_count_distribution;
            for (size_t count : packets_per_flow) {
                packet_count_distribution[count]++;
            }
            
            std::cout << "\nPacket Count Distribution:" << std::endl;
            std::cout << "+------------+------------+" << std::endl;
            std::cout << "| Packets    | Flows      |" << std::endl;
            std::cout << "+------------+------------+" << std::endl;
            for (const auto& [count, flows] : packet_count_distribution) {
                printf("| %-10zu | %-10zu |\n", count, flows);
            }
            std::cout << "+------------+------------+" << std::endl;
        }

        // Print top field failures if needed
        if (!global_stats.field_failures.empty()) {
            std::cout << "\nTop Field Failures:\n";
            std::cout << "+--------------------------+------------+" << std::endl;
            std::cout << "| Field                   | Count      |" << std::endl;
            std::cout << "+--------------------------+------------+" << std::endl;
            for (const auto& [field, count] : global_stats.field_failures) {
                printf("| %-24s | %-10zu |\n", field.c_str(), count);
            }
            std::cout << "+--------------------------+------------+" << std::endl;
        }

        std::cout << "\nFlow Validation Summary:" << std::endl;
        std::cout << "+--------------------------------+------------+" << std::endl;
        std::cout << "| Metric                         | Value      |" << std::endl;
        std::cout << "+--------------------------------+------------+" << std::endl;
        printf("| %-30s | %-10zu |\n", "Flows with valid SYN sequence", global_stats.flows_with_valid_syn);
        printf("| %-30s | %-10zu |\n", "Flows with valid FIN sequence", global_stats.flows_with_valid_fin);
        printf("| %-30s | %-10zu |\n", "Flows with both valid", global_stats.flows_with_both_valid);
        printf("| %-30s | %-10.1f%% |\n", "Valid SYN sequence rate", 
            (global_stats.total_flows > 0 ? 100.0 * global_stats.flows_with_valid_syn / global_stats.total_flows : 0));
        printf("| %-30s | %-10.1f%% |\n", "Valid FIN sequence rate", 
            (global_stats.total_flows > 0 ? 100.0 * global_stats.flows_with_valid_fin / global_stats.total_flows : 0));
        printf("| %-30s | %-10.1f%% |\n", "Complete flow rate", 
            (global_stats.total_flows > 0 ? 100.0 * global_stats.flows_with_both_valid / global_stats.total_flows : 0));
        std::cout << "+--------------------------------+------------+" << std::endl;

        if (!global_stats.missing_flags_counts.empty()) {
            std::cout << "\nMissing Flags Summary:" << std::endl;
            std::cout << "+--------------------------------+------------+" << std::endl;
            std::cout << "| Missing Flag                   | Count      |" << std::endl;
            std::cout << "+--------------------------------+------------+" << std::endl;
            for (const auto& [flag, count] : global_stats.missing_flags_counts) {
                printf("| %-30s | %-10zu |\n", flag.c_str(), count);
            }
            std::cout << "+--------------------------------+------------+" << std::endl;
        }

        // Print overall statistics
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();

        std::cout << "\n========================" << std::endl;
        std::cout << "=== Decoding Summary ===" << std::endl;
        std::cout << "========================" << std::endl;
        std::cout << "Input path: " << inputPath << std::endl;
        std::cout << "Output directory: " << outputDir << std::endl;
        std::cout << "Files processed: " << processed_files << "/" << arrowFiles.size() << std::endl;
        std::cout << "Total flows decoded: " << total_flows << std::endl;
        std::cout << "Total processing time: " << duration << " ms" << std::endl;
        std::cout << "Average time per file: " << (arrowFiles.empty() ? 0 : duration/arrowFiles.size()) << " ms" << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        print_usage();
        return 1;
    }

    std::string mode = argv[1];
    std::string inputPath = argv[2];
    std::string outputDir = argv[3];

    if (mode == "encode") {
        return encode_mode(inputPath, outputDir);
    } else if (mode == "decode") {
        return decode_mode(inputPath, outputDir);
    } else {
        std::cerr << "Error: Invalid mode '" << mode << "'. Must be either 'encode' or 'decode'." << std::endl;
        print_usage();
        return 1;
    }
}