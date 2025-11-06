#ifndef FLOW_EXTRACTOR_H
#define FLOW_EXTRACTOR_H

#include <string>
#include <map>
#include "FlowUtils.h"

void process_pcap_file(const std::string& pcapFileName, 
                      std::map<FlowKey, FlowInfo>& categorized_flows,
                      uint64_t& packet_count,
                      std::map<std::string, int>& flow_type_counts);

#endif // FLOW_EXTRACTOR_H
