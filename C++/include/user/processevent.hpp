#ifndef PROCESS_EVENT_HPP
#define PROCESS_EVENT_HPP
#include "payload.hpp"
#include <cstdio>
#include <cstring>
#include <stdint.h>
#include <string>
#include <unordered_map>

class ProcessEvent {

private:
  std::unordered_map<int, std::string> driver_map;

public:
  int initProcessEvent();
  Payload Process(struct EVENT *event);
  void print_event(Payload *p);

private:
  std::string resolveTty(int major, int minor);
  std::string resolveUserName(int uid);
  std::string resolveIp();
  std::string TimeStamp();
  std::string changeType(uint32_t type);
  std::string pathconstruction(EVENT *event);
  void loadDrivers();
};

#endif /* PROCESS_EVENT_HPP */