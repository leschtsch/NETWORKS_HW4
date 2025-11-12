#include <arpa/inet.h>
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/if_ether.h>
#include <linux/netfilter.h>
#include <memory>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <vector>

#define CHECK_OR_DROP(condition)                                               \
  if (!(condition)) {                                                          \
    std::cout << "DROP: " #condition " not true\n";                            \
    return false;                                                              \
  }

#define CHECK_OR_ACCEPT(condition)                                             \
  if (!(condition)) {                                                          \
    std::cout << "ACCEPT: " #condition " not true\n";                          \
    return true;                                                               \
  }

static constexpr std::size_t kBufsize = 4096;
static constexpr const char *kRulesFile = "rules.txt";

bool StartsWithCaseIgnorant(const std::string_view &str,
                            const std::string_view &pref) {
  if (pref.size() > str.size()) {
    return false;
  }

  return std::equal(pref.begin(), pref.end(), str.begin(),
                    [](char chr1, char chr2) {
                      return std::tolower(chr1) == std::tolower(chr2);
                    });
}

bool EqualCaseIgnorant(const std::string_view &str,
                       const std::string_view &pref) {
  if (pref.size() != str.size()) {
    return false;
  }

  return std::equal(pref.begin(), pref.end(), str.begin(),
                    [](char chr1, char chr2) {
                      return std::tolower(chr1) == std::tolower(chr2);
                    });
}

std::string_view SkipWs(const std::string_view &orig) {
  std::size_t start = orig.find_first_not_of(" \t\n\v\r\f");
  return (start <= orig.size()) ? orig.substr(start) : std::string_view();
}
std::string_view SkipWord(std::string_view orig) {
  orig = SkipWs(orig);
  std::size_t start = orig.find_first_of(" \t\n\v\r\f");
  orig = (start <= orig.size()) ? orig.substr(start) : std::string_view();
  return SkipWs(orig);
}
std::string_view GetWord(std::string_view orig) {
  orig = SkipWs(orig);
  std::size_t stop = orig.find_first_of(" \t\n\v\r\f");
  orig = orig.substr(0, stop);
  return orig;
}

bool IsHttpRequest(char *data, int len) {
  std::size_t slen = len;
  auto sdata = std::string(data, slen);

  static std::array kPatterns = {"GET",     "HEAD",   "POST",
                                 "PUT",     "DELETE", "CONNECT",
                                 "OPTIONS", "TRACE",  "PATCH"};

  for (auto *pat : kPatterns) {
    if (StartsWithCaseIgnorant(sdata, pat)) {
      return true;
    }
  }

  return false;
}

bool IsHttpResponse(char *data, int len) {
  std::size_t slen = len;
  auto sdata = std::string(data, slen);

  return StartsWithCaseIgnorant(sdata, "HTTP");
}

bool IsHttpHeader(char *data, int len) {
  return IsHttpResponse(data, len) || IsHttpRequest(data, len);
}

enum class RuleAction { Accept, Drop, None };

class Rule {
public:
  virtual ~Rule() = default;
  RuleAction action{RuleAction::Accept};
  RuleAction Matches(char *data, int len) {
    // TODO print action
    return this->DoMatches(data, len);
  }

protected:
  virtual RuleAction DoMatches(char *data, int len) = 0;
};

class DefaultRule : public Rule {
public:
  virtual ~DefaultRule() = default;

protected:
  virtual RuleAction DoMatches(char * /*data*/, int /*len*/) override {
    std::cout << "packet matched DEFAULT rule\n";
    return action;
  }
};

class RequestRule : public Rule {
public:
  virtual ~RequestRule() = default;

protected:
  virtual RuleAction DoMatches(char *data, int len) override {
    bool matches = IsHttpRequest(data, len);
    if (matches) {
      std::cout << "packet matched REQUEST rule\n";
      return action;
    } else {
      std::cout << "packet didn't match REQUEST rule\n";
      return RuleAction::None;
    }
  }
};

class ResponseRule : public Rule {
public:
  virtual ~ResponseRule() = default;

protected:
  virtual RuleAction DoMatches(char *data, int len) override {
    bool matches = IsHttpResponse(data, len);
    if (matches) {
      std::cout << "packet matched RESPONSE rule\n";
      return action;
    } else {
      std::cout << "packet didn't match RESPONSE rule\n";
      return RuleAction::None;
    }
  }
};

class RequestMethodRule : public Rule {
public:
  RequestMethodRule(auto method) : method_(method) {}

  virtual ~RequestMethodRule() = default;

protected:
  virtual RuleAction DoMatches(char *data, int len) override {
    std::size_t slen = len;
    auto sdata = std::string(data, slen);

    bool matches = StartsWithCaseIgnorant(sdata, method_);

    if (matches) {
      std::cout << "packet matched REQUEST_METHOD rule\n";
      return action;
    } else {
      std::cout << "packet didn't match REQUEST_METHOD rule\n";
      return RuleAction::None;
    }
  }

private:
  std::string method_;
};

class ResponseCodeRule : public Rule {
public:
  ResponseCodeRule(auto code) : code_(code) {}

  virtual ~ResponseCodeRule() = default;

protected:
  virtual RuleAction DoMatches(char *data, int len) override {
    std::size_t slen = len;
    auto sdata = std::string(data, slen);

    bool matches = StartsWithCaseIgnorant(sdata, "HTTP "+code_);

    if (matches) {
      std::cout << "packet matched RESPONSE_CODE rule\n";
      return action;
    } else {
      std::cout << "packet didn't match RESPONSE_CODE rule\n";
      return RuleAction::None;
    }
  }

private:
  std::string code_;
};

std::vector<std::unique_ptr<Rule>> g_rules;

std::unique_ptr<RequestMethodRule>
ReadRequestMethodRule(const std::string_view &line) {
  auto method = GetWord(line);
  std::cout << "added REQUEST_METHOD " << method << " rule\n";
  return std::make_unique<RequestMethodRule>(method.data());
}

std::unique_ptr<ResponseCodeRule>
ReadResponseCodeRule(const std::string_view &line) {
  auto code = GetWord(line);
  std::cout << "added RESPONSE_CODE " << code << " rule\n";
  return std::make_unique<ResponseCodeRule>(code.data());
}

void ReadOneRule(std::string_view line) {
  line = SkipWs(line);
  if (line.size() == 0) {
    return;
  }

  RuleAction action = RuleAction::None;

  if (StartsWithCaseIgnorant(line, "ACCEPT")) {
    action = RuleAction::Accept;
  } else if (StartsWithCaseIgnorant(line, "DROP")) {
    action = RuleAction::Drop;
  } else {
    std::cerr << "unknown rule action\n";
    std::exit(-1);
  }

  line = SkipWord(line);
  auto rule_name = GetWord(line);

  std::unique_ptr<Rule> rule{nullptr};

  if (EqualCaseIgnorant(rule_name, "DEFAULT")) {
    std::cout << "added rule DEFAULT\n";
    rule = std::unique_ptr<DefaultRule>(new DefaultRule);
  } else if (EqualCaseIgnorant(rule_name, "REQUEST")) {
    std::cout << "added rule REQUEST\n";
    rule = std::unique_ptr<RequestRule>(new RequestRule);
  } else if (EqualCaseIgnorant(rule_name, "RESPONSE")) {
    std::cout << "added rule RESPONSE\n";
    rule = std::unique_ptr<ResponseRule>(new ResponseRule);
  } else if (EqualCaseIgnorant(rule_name, "REQUEST_METHOD")) {
    line = SkipWord(line);
    rule = ReadRequestMethodRule(line);
  } else if (EqualCaseIgnorant(rule_name, "RESPONSE_CODE")) {
    line = SkipWord(line);
    rule = ReadResponseCodeRule(line);
  }

  if (!rule) {
    std::exit(-1);
  }

  rule->action = action;
  g_rules.push_back(std::move(rule));
}

void ReadRules(const std::string &rules_file) {
  std::ifstream ifile(rules_file);
  if (!ifile) {
    std::cerr << "filed to open rules.txt";
    std::exit(-1);
  }

  std::string line;
  while (std::getline(ifile, line)) {
    std::string_view line_sv(line);
    ReadOneRule(line_sv);
  }
}

bool HandleHTTP(char *data, int len) {
  CHECK_OR_ACCEPT(IsHttpHeader(data, len));

  RuleAction action = RuleAction::None;

  for (const auto &rule : g_rules) {
    RuleAction next_action = rule->Matches(data, len);

    if (next_action != RuleAction::None) {
      action = next_action;
    }
  }

  bool accept = action == RuleAction::Accept;
  if (accept) {
    std::cout << "ACCEPT: rules\n";
  } else {
    std::cout << "DROP: rules\n";
  }

  return accept;
}

bool HandleTCP(char *data, int len) {
  CHECK_OR_ACCEPT(static_cast<std::size_t>(len) >= sizeof(struct tcphdr));

  struct tcphdr *tcp_header = reinterpret_cast<struct tcphdr *>(data);

  std::size_t hdr_len = tcp_header->doff * 4;

  CHECK_OR_ACCEPT(hdr_len >= sizeof(struct tcphdr));
  CHECK_OR_ACCEPT(hdr_len <= static_cast<std::size_t>(len));

  return HandleHTTP(data + hdr_len, len - hdr_len);
  return true;
}

bool HandleIP(char *data, int len) {
  CHECK_OR_ACCEPT(static_cast<std::size_t>(len) >= sizeof(struct iphdr));

  struct iphdr *ip_header = reinterpret_cast<struct iphdr *>(data);

  CHECK_OR_ACCEPT(ip_header->version == 4);
  CHECK_OR_ACCEPT(ip_header->protocol == IPPROTO_TCP);

  std::size_t hdr_len = ip_header->ihl * 4;

  CHECK_OR_ACCEPT(hdr_len >= sizeof(struct iphdr));
  CHECK_OR_ACCEPT(hdr_len <= static_cast<std::size_t>(len));

  return HandleTCP(data + hdr_len, len - hdr_len);
}

static int callback(struct nfq_q_handle *qh, struct nfgenmsg * /*nfmsg*/,
                    struct nfq_data *nfad, void * /*data*/) {
  struct nfqnl_msg_packet_hdr *packet_header = nfq_get_msg_packet_hdr(nfad);
  int packet_id = ntohl(packet_header->packet_id);

  int protocol = htons(packet_header->hw_protocol);

  if (protocol != ETH_P_IP) {
    std::cout << "ACCEPT: not ip\n";
    return nfq_set_verdict(qh, packet_id, NF_ACCEPT, 0, nullptr);
  }

  unsigned char *data = nullptr;
  int len = nfq_get_payload(nfad, &data);

  if (len < 0) {
    std::cout << "ACCEPT: len < 0\n";
    return nfq_set_verdict(qh, packet_id, NF_ACCEPT, 0, nullptr);
  }

  bool accept = HandleIP(reinterpret_cast<char *>(data), len);

  if (accept) {
    return nfq_set_verdict(qh, packet_id, NF_ACCEPT, 0, nullptr);
  }
  return nfq_set_verdict(qh, packet_id, NF_DROP, 0, nullptr);
}

int main(int argc, char **argv) {
  int queue_num = 0;

  if (argc > 1) {
    queue_num = atoi(argv[1]);
  }

  std::cout << "reading rules\n";
  ReadRules(kRulesFile);

  std::cout << "filtering queue " << queue_num << "\n";

  struct nfq_handle *nfq_h = nfq_open();
  if (!nfq_h) {
    std::perror("nfq_open");
    std::exit(-1);
  }

  struct nfq_q_handle *nfq_qh =
      nfq_create_queue(nfq_h, queue_num, &callback, nullptr);
  if (!nfq_qh) {
    std::perror("nfq_open");
    nfq_close(nfq_h);
    std::exit(-1);
  }

  int qfd = 0;

  if (nfq_set_mode(nfq_qh, NFQNL_COPY_PACKET, kBufsize) < 0) {
    std::perror("nfq_set_mode");
    goto error;
  }

  qfd = nfq_fd(nfq_h);

  while (true) {
    std::cout << "waiting packet\n";

    static char buf[kBufsize];
    int bytes_received = recv(qfd, buf, kBufsize, 0);
    if (bytes_received < 0) {
      std::perror("recv");
      goto error;
    }

    std::cout << "handling packet\n";

    if (nfq_handle_packet(nfq_h, buf, bytes_received) != 0) {
      std::perror("nfq_handle_packet");
      goto error;
    }
  }

  return 0;

error:
  nfq_destroy_queue(nfq_qh);
  nfq_close(nfq_h);
  std::exit(-1);
}
