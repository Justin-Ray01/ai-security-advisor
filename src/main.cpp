#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

struct Findings {
    int total_lines = 0;

    int ssh_failed = 0;
    int ssh_accepted = 0;

    // counts
    std::map<std::string,int> failed_by_ip;
    std::map<std::string,int> failed_by_user;
    std::map<std::string,int> success_by_ip;
    std::map<std::string,int> success_by_user;

    // correlation: did an IP have fails then a success?
    std::map<std::string,bool> ip_has_success_after_fails;

    // scoring
    int risk_score = 0; // 0-100
    std::vector<std::string> signals; // reasons contributing to score
};

static std::string trim(const std::string& s) {
    size_t a = 0;
    while (a < s.size() && std::isspace((unsigned char)s[a])) a++;
    size_t b = s.size();
    while (b > a && std::isspace((unsigned char)s[b-1])) b--;
    return s.substr(a, b-a);
}

static std::vector<std::pair<std::string,int>> top_n(const std::map<std::string,int>& m, int n) {
    std::vector<std::pair<std::string,int>> v(m.begin(), m.end());
    std::sort(v.begin(), v.end(), [](auto& A, auto& B){
        if (A.second != B.second) return A.second > B.second;
        return A.first < B.first;
    });
    if ((int)v.size() > n) v.resize(n);
    return v;
}

static void add_score(Findings& f, int points, const std::string& reason) {
    f.risk_score += points;
    f.signals.push_back(reason + " (+" + std::to_string(points) + ")");
}

static Findings analyze_auth_log(const fs::path& path) {
    Findings f;

    std::ifstream in(path);
    if (!in) {
        throw std::runtime_error("Could not open log file: " + path.string());
    }

    // Very common auth.log patterns (Ubuntu/Debian style). We keep regexes simple on purpose.
    // Failed ssh:
    // "Failed password for invalid user admin from 10.0.2.15 port 5555 ssh2"
    // "Failed password for root from 192.168.1.50 port 4444 ssh2"
    std::regex re_failed(R"(Failed password for (invalid user )?([A-Za-z0-9_\-\.]+) from ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+))");

    // Successful ssh:
    // "Accepted password for vmuser from 10.0.2.15 port 5555 ssh2"
    std::regex re_accepted(R"(Accepted (password|publickey) for ([A-Za-z0-9_\-\.]+) from ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+))");

    std::string line;
    while (std::getline(in, line)) {
        f.total_lines++;

        std::smatch m;
        if (std::regex_search(line, m, re_failed)) {
            f.ssh_failed++;
            std::string user = m[2].str();
            std::string ip   = m[3].str();
            f.failed_by_ip[ip]++;
            f.failed_by_user[user]++;
        } else if (std::regex_search(line, m, re_accepted)) {
            f.ssh_accepted++;
            std::string user = m[2].str();
            std::string ip   = m[3].str();
            f.success_by_ip[ip]++;
            f.success_by_user[user]++;

            // mark correlation if this IP already had failures
            if (f.failed_by_ip.find(ip) != f.failed_by_ip.end()) {
                f.ip_has_success_after_fails[ip] = true;
            }
        }
    }

    // --- Risk scoring heuristics (simple, explainable "AI") ---
    // Base risk: failures indicate probing
    if (f.ssh_failed >= 5) add_score(f, 10, "Multiple SSH failures detected");
    if (f.ssh_failed >= 20) add_score(f, 15, "High volume of SSH failures (possible brute-force)");

    // Top offending IPs
    int max_ip_fails = 0;
    std::string worst_ip;
    for (const auto& kv : f.failed_by_ip) {
        if (kv.second > max_ip_fails) { max_ip_fails = kv.second; worst_ip = kv.first; }
    }
    if (max_ip_fails >= 5) add_score(f, 15, "Single IP shows repeated failures: " + worst_ip);
    if (max_ip_fails >= 10) add_score(f, 15, "Strong brute-force signal from IP: " + worst_ip);

    // Many usernames targeted suggests spraying
    if ((int)f.failed_by_user.size() >= 5) add_score(f, 10, "Multiple usernames targeted (possible password spraying)");
    if ((int)f.failed_by_user.size() >= 10) add_score(f, 10, "Large number of usernames targeted");

    // Success after failures is a big deal
    int correlated = 0;
    for (auto& kv : f.ip_has_success_after_fails) if (kv.second) correlated++;
    if (correlated >= 1) add_score(f, 25, "Successful login observed after failures (possible compromise)");

    // Any successful login at all (context)
    if (f.ssh_accepted >= 1) add_score(f, 5, "SSH successful logins present (review for legitimacy)");

    // Clamp 0-100
    f.risk_score = std::max(0, std::min(100, f.risk_score));
    return f;
}

static std::string risk_level(int score) {
    if (score >= 70) return "HIGH";
    if (score >= 35) return "MEDIUM";
    if (score >= 10) return "LOW";
    return "INFO";
}

static std::string generate_report(const Findings& f, const std::string& log_name) {
    std::ostringstream out;

    out << "AI Security Advisor Report\n";
    out << "==========================\n\n";

    out << "Log analyzed: " << log_name << "\n";
    out << "Lines processed: " << f.total_lines << "\n\n";

    out << "Summary\n";
    out << "-------\n";
    out << "- SSH failed logins: " << f.ssh_failed << "\n";
    out << "- SSH successful logins: " << f.ssh_accepted << "\n";
    out << "- Risk score: " << f.risk_score << "/100 (" << risk_level(f.risk_score) << ")\n\n";

    out << "What this likely means\n";
    out << "----------------------\n";
    if (f.ssh_failed == 0 && f.ssh_accepted == 0) {
        out << "No SSH authentication activity was detected in the provided log.\n\n";
    } else if (f.ssh_failed > 0 && f.ssh_accepted == 0) {
        out << "The system appears to be receiving failed SSH login attempts. This can indicate\n";
        out << "automated scanning or brute-force attempts, especially if concentrated from one IP.\n\n";
    } else if (f.ssh_failed > 0 && f.ssh_accepted > 0) {
        out << "Both failed and successful SSH logins were detected. If a success follows a burst\n";
        out << "of failures from the same IP, this can indicate a compromised credential.\n\n";
    } else {
        out << "Successful SSH logins were detected without recorded failures in this dataset.\n";
        out << "This may be normal administrative access, but review for expected users/IPs.\n\n";
    }

    auto top_failed_ips = top_n(f.failed_by_ip, 5);
    auto top_failed_users = top_n(f.failed_by_user, 5);
    auto top_success_ips = top_n(f.success_by_ip, 5);
    auto top_success_users = top_n(f.success_by_user, 5);

    out << "Top signals contributing to score\n";
    out << "--------------------------------\n";
    if (f.signals.empty()) out << "- No major risk signals triggered.\n";
    else for (const auto& s : f.signals) out << "- " << s << "\n";
    out << "\n";

    out << "Top failed SSH sources\n";
    out << "----------------------\n";
    if (top_failed_ips.empty()) out << "(none)\n";
    else for (auto& kv : top_failed_ips) out << "- " << kv.first << " : " << kv.second << "\n";
    out << "\n";

    out << "Top targeted usernames\n";
    out << "----------------------\n";
    if (top_failed_users.empty()) out << "(none)\n";
    else for (auto& kv : top_failed_users) out << "- " << kv.first << " : " << kv.second << "\n";
    out << "\n";

    out << "Successful logins (context)\n";
    out << "---------------------------\n";
    if (top_success_ips.empty()) out << "(none)\n";
    else {
        out << "IPs:\n";
        for (auto& kv : top_success_ips) out << "- " << kv.first << " : " << kv.second << "\n";
        out << "Users:\n";
        for (auto& kv : top_success_users) out << "- " << kv.first << " : " << kv.second << "\n";
    }
    out << "\n";

    out << "Recommended actions\n";
    out << "-------------------\n";
    if (f.risk_score >= 70) {
        out << "- Immediately review successful SSH logins that follow repeated failures.\n";
        out << "- Consider blocking top offending IPs at the firewall.\n";
        out << "- Enforce key-based auth, disable password auth where possible.\n";
        out << "- Rotate credentials for any targeted accounts.\n";
    } else if (f.risk_score >= 35) {
        out << "- Review the top failing IPs and targeted usernames.\n";
        out << "- Ensure SSH is hardened (disable root login, consider fail2ban).\n";
        out << "- Confirm successful logins are expected.\n";
    } else if (f.risk_score >= 10) {
        out << "- Monitor for repeated attempts; consider rate limiting or fail2ban.\n";
        out << "- Verify SSH configuration aligns with policy.\n";
    } else {
        out << "- No immediate action required based on this dataset.\n";
        out << "- Continue monitoring and keep SSH hardening controls enabled.\n";
    }

    return out.str();
}

static std::string generate_findings_text(const Findings& f) {
    std::ostringstream out;
    out << "Findings\n";
    out << "========\n";
    out << "lines_processed=" << f.total_lines << "\n";
    out << "ssh_failed=" << f.ssh_failed << "\n";
    out << "ssh_accepted=" << f.ssh_accepted << "\n";
    out << "risk_score=" << f.risk_score << "\n";
    out << "risk_level=" << risk_level(f.risk_score) << "\n\n";

    out << "top_failed_ips:\n";
    for (auto& kv : top_n(f.failed_by_ip, 5)) out << "  - " << kv.first << " : " << kv.second << "\n";

    out << "\ntop_failed_usernames:\n";
    for (auto& kv : top_n(f.failed_by_user, 5)) out << "  - " << kv.first << " : " << kv.second << "\n";

    out << "\ncorrelation_success_after_fails:\n";
    if (f.ip_has_success_after_fails.empty()) out << "  (none)\n";
    else {
        for (auto& kv : f.ip_has_success_after_fails) {
            if (kv.second) out << "  - " << kv.first << "\n";
        }
    }

    out << "\nsignals:\n";
    if (f.signals.empty()) out << "  (none)\n";
    else for (auto& s : f.signals) out << "  - " << s << "\n";

    return out.str();
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage:\n";
        std::cout << "  ./ai_security_advisor <path_to_auth_log> [--save]\n\n";
        std::cout << "Example:\n";
        std::cout << "  ./ai_security_advisor sample-logs/auth_sample.log --save\n";
        return 1;
    }

    fs::path log_path = argv[1];
    bool save = false;
    for (int i = 2; i < argc; i++) {
        if (std::string(argv[i]) == "--save") save = true;
    }

    try {
        Findings f = analyze_auth_log(log_path);

        std::string findings = generate_findings_text(f);
        std::string report = generate_report(f, log_path.filename().string());

        // Console output (human-friendly)
        std::cout << report << "\n";

        // Optional save outputs for portfolio proof
        if (save) {
            fs::create_directories("sample-output");
            std::ofstream("sample-output/findings.txt") << findings;
            std::ofstream("sample-output/report.txt") << report;
            std::cout << "\nSaved:\n";
            std::cout << "  - sample-output/findings.txt\n";
            std::cout << "  - sample-output/report.txt\n";
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 2;
    }

    return 0;
}
