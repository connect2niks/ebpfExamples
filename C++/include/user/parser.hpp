#ifndef PARSER_H
#define PARSER_H

#include "shared_types.h"
#include "types.hpp"
#include <stdint.h>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

/* ---------------------------------------------------------
   Token
---------------------------------------------------------*/
class Token {
public:
  Token(int lineNumber, const std::string &command,
        const std::string &argument);
#ifdef DEBUG_TOKENS
  void printToken() const;
#endif

public:
  int lineNumber;
  std::string command;
  std::string argument;
};

/* ---------------------------------------------------------
   Parser
---------------------------------------------------------*/
class Parser {

public:
  explicit Parser(const std::string &policyFilePath);
  ~Parser() = default;

  void parsePolicyFile();

  const user_space_filter &getUserSpaceFilter() const;
  const std::vector<std::string> &getApiUrl() const;
  const std::vector<std::pair<std::string, std::string>> &getApiHeader() const;
  const std::unordered_map<KEY, VALUE> &getIncludeDir() const;
#ifdef DEBUG_PARSER
  void printParser() const;
#endif

private:
  std::string policyFilePath;

  std::vector<Token> tokens;

  /* API configuration */
  std::vector<std::string> api_url;
  std::vector<std::pair<std::string, std::string>> api_header;

  /* exclusion rules */
  std::unordered_map<KEY, uint8_t> exclude_dir;
  user_space_filter userSpaceFilter;

  /* inclusion rules */
  std::unordered_map<KEY, VALUE> include_dir;

  /* parser pipeline */
  void tokenize();
  void syntaxValidation();
  void semanticValidation();
};

#endif