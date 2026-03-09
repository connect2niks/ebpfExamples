#ifndef TYPES_HPP
#define TYPES_HPP

#include <stdint.h>
#include <string>
#include <unordered_map>
#include <vector>

struct user_space_filter {
  std::unordered_map<std::string, uint8_t> exclude_extension;
  std::vector<std::string> exclude_suffix;
  std::vector<std::string> exclude_prefix;
  std::vector<std::string> exclude_pattern;
};

#endif
