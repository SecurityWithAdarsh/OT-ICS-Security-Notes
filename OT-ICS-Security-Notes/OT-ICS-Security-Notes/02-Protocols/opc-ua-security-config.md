# OPC UA Security Configuration Guide

## Security Mode Configuration

### What Each Mode Means in Practice
```
SecurityMode = None
→ All traffic in plaintext
→ No message integrity checks
→ Any client can connect without a certificate
→ NEVER use in production

SecurityMode = Sign
→ Messages are signed (HMAC)
→ Tampering/MitM detected
→ Still NO encryption — data visible on wire
→ Acceptable for isolated control networks with strong physical security

SecurityMode = Sign & Encrypt
→ Full protection
→ AES-256 encryption
→ Certificate-based authentication
→ USE THIS in all production deployments
```

## OPC UA Security Checklist
```
[ ] SecurityMode set to Sign & Encrypt on all endpoints
[ ] Server certificates issued by internal PKI (not self-signed)
[ ] Client certificate trust list maintained (only approved clients)
[ ] Rejected certificates reviewed and not auto-accepted
[ ] User authentication enabled (not anonymous)
[ ] Role-based access configured (read-only for historian, operator for HMI)
[ ] Audit logging enabled for security events
[ ] GetEndpoints response does not expose unnecessary endpoints
[ ] OPC UA server port (4840) not internet-accessible
[ ] OPC UA firewall rules: only authorized client IPs permitted
```

## Common OPC UA Misconfigurations
```
1. SecurityMode = None         ← Most common; "enabled later" that never happens
2. Anonymous authentication    ← No user credentials required to connect
3. Auto-accept certificates    ← Any client cert accepted without review
4. Self-signed certs with no PKI ← No real trust chain
5. No endpoint filtering       ← GetEndpoints exposes all security mode options
6. Excessive user permissions  ← Historian client has write access it doesn't need
```
