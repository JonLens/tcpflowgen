#ifndef ENCODE_H
#define ENCODE_H

#include <vector>
#include <map>
#include "FlowUtils.h"

// Special token values
const int TOKEN_COMPLETE = 65536;
const int TOKEN_START = 65537;
const int TOKEN_END = 65538;
const int TOKEN_FREE = 65539;
const int TOKEN_FORWARD = 65540;
const int TOKEN_REVERSE = 65541;
const int TOKEN_HEAD = 65542;
const int TOKEN_PKT_SIZE = 65543;
const int TOKEN_EOS = 65544;

std::vector<std::vector<int>> tokenize_headers(const std::map<FlowKey, FlowInfo>& tcp_flows);

#endif // ENCODE_H