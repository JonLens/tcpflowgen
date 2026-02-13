#include <iostream>
#include <chrono>
#include <filesystem>
#include <vector>
namespace fs = std::filesystem;
#include "FlowExtractor.h"
#include "Encode.h"
#include "Decode.h"
#include "ReportUtils.h"
#include "Packet.h"
#include "PcapFileDevice.h"

// ============================================================================
// Argument handling
// ============================================================================

void print_usage() {
    std::cerr << "Usage:\n"
              << "  Encode mode: " << program_invocation_short_name << " encode <input_pcap_or_directory> <output_arrow_directory>\n"
              << "  Decode mode: " << program_invocation_short_name << " decode <input_arrow_directory> <output_pcap_directory>\n";
}

std::vector<fs::path> check_arguments(const std::string& inputPathStr, const std::string& outputDirStr,
                                      const std::vector<std::string>& fileTypes) {
    fs::path inputPath(inputPathStr);
    fs::path outputDir(outputDirStr);

    if (fs::exists(outputDir) && fs::is_regular_file(outputDir)) {
        throw std::runtime_error("outputDir is an existing file, not a directory: " + outputDirStr);
    }
    if (!fs::exists(outputDir) && !outputDir.extension().empty()) {
        throw std::runtime_error("outputDir looks like a filename, not a directory: " + outputDirStr);
    }
    if (!fs::exists(outputDir)) {
        if (!fs::create_directories(outputDir)) {
            throw std::runtime_error("Failed to create output directory " + outputDirStr);
        }
    }

    auto has_allowed_extension = [&fileTypes](const fs::path& p) -> bool {
        auto extension = p.extension().string();
        for (const auto& ft : fileTypes) {
            if (extension == ft) return true;
        }
        return false;
    };

    std::vector<fs::path> files;

    if (fs::is_directory(inputPath)) {
        for (const auto& entry : fs::directory_iterator(inputPath)) {
            if (entry.is_regular_file() && has_allowed_extension(entry.path())) {
                files.push_back(entry.path());
            }
        }
        if (files.empty()) {
            throw std::runtime_error("Failed to find input files " + inputPathStr);
        }
    } else {
        if (!fs::exists(inputPath) || !fs::is_regular_file(inputPath)) {
            throw std::runtime_error("Failed to find input file " + inputPathStr);
        }
        if (!has_allowed_extension(inputPath)) {
            throw std::runtime_error("Input file has the wrong extension " + inputPathStr);
        }
        files.push_back(inputPath);
    }
    return files;
}

// ============================================================================
// Encode mode
// ============================================================================

int encode_mode(const std::string& inputPath, const std::string& outputDir) {
    auto start_time = std::chrono::high_resolution_clock::now();
    size_t total_flows = 0;
    size_t total_packets = 0;
    size_t processed_files = 0;

    try {
        auto pcapFiles = check_arguments(inputPath, outputDir, {".pcap", ".pcapng"});

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
                    print_complete_flow_summary(flow_key, flow_info);
                }
            }

            // Tokenize the flows
            auto tokenized_flows = tokenize_headers(complete_flows);
            if (tokenized_flows.empty()) {
                std::cout << "Warning: No complete flows found in " << pcapFile.filename() << std::endl;
                continue;
            }
            
            total_flows += tokenized_flows.size();
            
            size_t total_tokens = 0;
            for (const auto& seq : tokenized_flows) {
                total_tokens += seq.size();
            }
            std::cout << "\nNumber of flows: " << tokenized_flows.size() << std::endl;
            std::cout << "Total number of tokens: " << total_tokens << std::endl;

            // Save to arrow file
            fs::path outputPath = fs::path(outputDir) / pcapFile.filename().replace_extension(".arrow");
            arrow::Status status = save_tokens_arrow(tokenized_flows, outputPath.string());
            if (!status.ok()) {
                std::cerr << "Error saving tokens: " << status.ToString() << std::endl;
                continue;
            }
            processed_files++;
            std::cout << "Tokens saved successfully to " << outputPath.string() << std::endl;

            // Print file-specific stats
            std::cout << "Processed " << packet_count << " TCP packets" << std::endl;
            std::cout << "Flow type statistics:" << std::endl;
            for (const auto& [type, count] : flow_type_counts) {
                std::cout << "  " << type << ": " << count << std::endl;
            }
        }

        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
        print_processing_summary("Processing Summary", inputPath, outputDir,
                                 processed_files, pcapFiles.size(), total_flows,
                                 "Total flows extracted", duration);
        std::cout << "Total packets processed: " << total_packets << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}

// ============================================================================
// Decode mode
// ============================================================================

int decode_mode(const std::string& inputPath, const std::string& outputDir) {
    GlobalStats global_stats;
    auto start_time = std::chrono::high_resolution_clock::now();
    size_t total_flows = 0;
    size_t processed_files = 0;
    std::vector<size_t> packets_per_flow;
    std::map<size_t, size_t> packet_count_distribution;
    std::vector<std::tuple<size_t, FlowValidationStats>> all_flow_validations;
    
    try {
        auto arrowFiles = check_arguments(inputPath, outputDir, {".arrow"});

        for (const auto& arrowFile : arrowFiles) {
            std::cout << "\nProcessing file: " << arrowFile.string() << std::endl;
            
            auto tokenized_flows = load_tokens_arrow(arrowFile.string());
            if (tokenized_flows.empty()) {
                std::cout << "Warning: No flows found in " << arrowFile.filename() << std::endl;
                continue;
            }
            total_flows += tokenized_flows.size();
            std::cout << "Number of flows to decode: " << tokenized_flows.size() << std::endl;

            fs::path outputPath = fs::path(outputDir) / arrowFile.filename().replace_extension(".pcap");
            pcpp::PcapFileWriterDevice writer(outputPath.string());
            if (!writer.open()) {
                throw std::runtime_error("Cannot open output file " + outputPath.string());
            }
            
            for (size_t flow_idx = 0; flow_idx < tokenized_flows.size(); flow_idx++) {
                std::cout << "\n===== Processing Flow " << flow_idx + 1 << " =====" << std::endl;

                auto [packets, stats] = processFlowTokens(tokenized_flows[flow_idx]);
                
                packets_per_flow.push_back(packets.size());
                packet_count_distribution[packets.size()]++;

                auto flow_validation = validateFlowSemantics(packets);
                all_flow_validations.emplace_back(flow_idx, flow_validation);
                accumulate_global_stats(global_stats, stats, flow_validation);

                for (const auto& packet : packets) {
                    writer.writePacket(*packet.getRawPacket());
                }
            }
            
            writer.close();
            processed_files++;
            std::cout << "Decoded flows saved successfully to " << outputPath.string() << std::endl;
        }

        // Save CSV reports
        save_decode_csvs(fs::path(outputDir), packet_count_distribution, 
                         global_stats, all_flow_validations);

        // Print metrics
        print_decode_metrics(global_stats, packets_per_flow, packet_count_distribution);

        // Print summary
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
        print_processing_summary("Decoding Summary", inputPath, outputDir,
                                 processed_files, arrowFiles.size(), total_flows,
                                 "Total flows decoded", duration);

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}

// ============================================================================
// Entry point
// ============================================================================

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
