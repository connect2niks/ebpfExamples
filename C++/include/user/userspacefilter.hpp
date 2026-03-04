#ifndef USERSSPACEFILTER_HPP
#define USERSSPACEFILTER_HPP

#include "types.hpp"

class UserspaceFilter {
public:
  UserspaceFilter();
  ~UserspaceFilter();

  void initFilter(void *parser);
  bool filterEvent(void *event);
#ifdef DEBUG_USERSPACE_FILTER
  void printFilter() const;
#endif

private:
  user_space_filter filter;
};

#endif