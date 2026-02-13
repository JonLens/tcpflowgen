#ifndef REPORT_UTILS_H
#define REPORT_UTILS_H

#include <string>
#include <vector>
#include <map>
#include <tuple>
#include <filesystem>
#include <functional>
#include <fstream>
#include "Decode.h"

namespace fs = std::filesystem;

// Formatting
std::string format_flags(uint8_t flags);
void print_table_row(const char* label, size_t value, int label_width = 24);
void print_table_row_pct(const char* label, double value, int label_width = 24);
void print_table_separator(int label_width = 24);
void print_table_header(const char* col1, const char* col2, int label_width = 24);

// Summaries
void print_processing_summary(const std::string& title,
                              const std::string& inputPath,
                              const std::string& outputDir,
                              size_t processed_files,
                              size_t total_files,
                              size_t total_count,
                              const std::string& count_label,
                              long long duration_ms);

void print_complete_flow_summary(const FlowKey& flow_key, const FlowInfo& flow_info);

// Decode reporting
void accumulate_global_stats(GlobalStats& global_stats,
                             const PacketCreationStats& stats,
                             const FlowValidationStats& flow_validation);

void save_decode_csvs(const fs::path& outputDir,
                      const std::map<size_t, size_t>& packet_count_distribution,
                      const GlobalStats& global_stats,
                      const std::vector<std::tuple<size_t, FlowValidationStats>>& all_flow_validations);

void print_decode_metrics(const GlobalStats& global_stats,
                          const std::vector<size_t>& packets_per_flow,
                          const std::map<size_t, size_t>& packet_count_distribution);

// CSV helper
bool save_csv(const fs::path& path,
              const std::string& header,
              const std::function<void(std::ofstream&)>& writer);

#endif // REPORT_UTILS_H
