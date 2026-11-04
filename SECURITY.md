# SMS Shield — Security Architecture & Threat Mitigation

SMS Shield handles untrusted and potentially hostile inputs, including malicious links, phishing messages, and adversary-crafted payloads. The following controls are enforced across the system.

---

## 1. Safe URL Inspection & SSRF Mitigation

To evaluate URLs without exposing the backend infrastructure to Server-Side Request Forgery (SSRF) or remote code execution:

1. **Deny Localhost & Private Networks**:
   Before initiating any outbound network probes (e.g. following redirects or resolving DNS), the destination host is validated against a blacklist of non-routable IP blocks:
   - `127.0.0.0/8` (Loopback)
   - `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (Private RFC 1918)
   - `169.254.0.0/16` (Link-local & AWS/GCP cloud metadata services)
   - `::1` and IPv6 unique local / site-local addresses.
2. **DNS Rebinding Prevention**:
   DNS queries are resolved before connection, and the socket is pinned to the verified IP address, preventing DNS rebinding attacks between inspection and request.
3. **Execution Prohibition**:
   The URL inspector never evaluates JavaScript, executes downloaded binaries, or loads media assets. It examines HTTP headers, status codes, and final redirected domains only.
4. **Enforced Timeouts & Size Caps**:
   - Outbound probe timeouts capped at 3.0 seconds.
   - Maximum redirect depth capped at 5 hops.
   - Maximum response body size capped at 64 KB.

---

## 2. API & Secret Security

- **Server-Side API Keys**: API keys for external threat intelligence services (Google Safe Browsing, VirusTotal) reside strictly in server-side environment variables. No client APK or web frontend bundle ever contains upstream API secrets.
- **Input Validation**: All incoming requests are strictly validated using Pydantic v2 schemas. Payloads exceeding maximum size limits (e.g. > 10,000 characters) are rejected with `413 Payload Too Large`.
- **CORS Protection**: The FastAPI backend restricts Cross-Origin Resource Sharing (CORS) to designated dashboard origins.
