Basic Vulnerability Scanner
A lightweight network vulnerability scanner written in pure Python. Performs TCP port scanning, service banner grabbing, HTTP security header analysis, and SSL/TLS certificate checks — then outputs a prioritized findings report.

How It Works
1. TCP Connect Scan
Opens a full TCP connection to each port. If the connection succeeds → open. If refused → closed. If it times out → filtered (likely firewalled).
2. Banner Grabbing
For open ports, the scanner reads up to 1 KB of data sent by the service on connect. Many protocols (SSH, FTP, SMTP, Telnet) send a greeting banner immediately, revealing software name and version.
3. Risky Port Detection
Cross-references open ports against a known-risky list with pre-mapped severities based on common real-world exposure (e.g., Redis/MongoDB with no auth, Telnet in cleartext, publicly exposed RDP).
4. HTTP Security Headers
Makes an HTTP GET request and inspects response headers against the OWASP Secure Headers Project baseline.
5. SSL/TLS Certificate
Performs a TLS handshake and reads the certificate's notAfter field. Reports CRITICAL for expired, HIGH for <14 days, MEDIUM for <30 days.


  ----
  Legal
This tool is for authorized security testing only. The author is not responsible for misuse. Always obtain written permission before scanning any system you do not own.
