#include "userspacefilter.hpp"
#include "parser.hpp"
#include "shared_types.h"
#include <filesystem>
#include <string>

std::string getFullPath(unsigned char path[MAX_FILENAME_LEN]) {
  return "/home/abinash/Desktop/ebpfExamples/C++";
};

UserspaceFilter::UserspaceFilter() {}

UserspaceFilter::~UserspaceFilter() {}

void UserspaceFilter::initFilter(void *parser) {

  Parser *parserObj = (Parser *)parser;
  if (parserObj == nullptr) {
    printf("Parser object is null\n");
    return;
  }
  filter = parserObj->getUserSpaceFilter();
}

bool UserspaceFilter::filterEvent(void *event) {

  EVENT *eventObj = (EVENT *)event;
  if (eventObj == nullptr) {
    printf("Event object is null\n");
    return false;
  }

  // build full path from the buffer
  std::string fullPath = getFullPath(eventObj->dentry_ctx.filepath);
  std::filesystem::path p(fullPath);

  // check extension
  std::string ext = p.extension().string();
  if (filter.exclude_extension.count(ext)) {
    return true;
  }

  std::string filename = p.filename().string();

  // check suffix
  for (auto &suffix : filter.exclude_suffix) {
    if (filename.ends_with(suffix)) {
      return true;
    }
  }

  // check prefix
  for (auto &prefix : filter.exclude_prefix) {
    if (filename.starts_with(prefix)) {
      return true;
    }
  }

  // check pattern
  for (auto &pattern : filter.exclude_pattern) {
    if (filename.find(pattern) != std::string::npos) {
      return true;
    }
  }

  return false;
}

#ifdef DEBUG_USERSPACE_FILTER
void UserspaceFilter::printFilter() const {

  printf("Exclude extension: ");
  for (auto &ext : filter.exclude_extension) {
    printf("%s ", ext.first.c_str());
  }
  printf("\n");

  printf("Exclude suffix: ");
  for (auto &suffix : filter.exclude_suffix) {
    printf("%s ", suffix.c_str());
  }
  printf("\n");

  printf("Exclude prefix: ");
  for (auto &prefix : filter.exclude_prefix) {
    printf("%s ", prefix.c_str());
  }
  printf("\n");

  printf("Exclude pattern: ");
  for (auto &pattern : filter.exclude_pattern) {
    printf("%s ", pattern.c_str());
  }
  printf("\n");
}
#endif