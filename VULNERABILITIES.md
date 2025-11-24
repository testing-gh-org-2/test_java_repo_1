# Vulnerable Java Test Project

This project contains **intentional security vulnerabilities** for testing purposes. It includes both code-level vulnerabilities detectable by CodeQL and vulnerable dependencies with known CVEs.

⚠️ **WARNING**: This code is intentionally insecure and should NEVER be used in production!

## Vulnerable Dependencies

### Critical Severity
1. **Log4j 2.14.1** - CVE-2021-44228 (Log4Shell)
   - Remote code execution vulnerability
   - CVSS Score: 10.0

2. **Apache Commons Collections 3.2.1** - CVE-2015-6420
   - Remote code execution via deserialization
   - CVSS Score: 9.8

3. **Apache Struts 2.3.20** - CVE-2017-5638
   - Remote code execution
   - CVSS Score: 10.0

4. **H2 Database 1.4.199** - CVE-2018-10054
   - Remote code execution
   - CVSS Score: 9.8

### High Severity
5. **Spring Framework 5.2.0** - CVE-2020-5398, CVE-2020-5421
   - Path traversal and RFD vulnerabilities
   - CVSS Score: 7.5+

6. **Jackson Databind 2.9.8** - CVE-2019-12384, CVE-2019-14540
   - Deserialization vulnerabilities
   - CVSS Score: 7.5+

7. **Apache Commons FileUpload 1.3.1** - CVE-2016-1000031
   - Denial of service
   - CVSS Score: 7.5

8. **Tomcat 9.0.0.M1** - Multiple CVEs
   - Various security issues
   - CVSS Score: 7.0+

### Medium Severity
9. **Netty 4.1.42** - CVE-2019-20444, CVE-2019-20445
   - HTTP request smuggling
   - CVSS Score: 6.5

10. **MySQL Connector 5.1.23** - CVE-2018-3258
    - Security vulnerabilities
    - CVSS Score: 6.5

11. **Apache HttpClient 4.3.1** - CVE-2015-5262
    - Man-in-the-middle vulnerability
    - CVSS Score: 5.9

12. **Bouncy Castle 1.60** - CVE-2018-1000613
    - Cryptographic weakness
    - CVSS Score: 5.5

## Code-Level Vulnerabilities (CodeQL Detectable)

### Injection Vulnerabilities
- **SQL Injection (CWE-89)** - `App.java`, `VulnerableInjection.java`
- **Command Injection (CWE-78)** - `App.java`, `VulnerableInjection.java`
- **LDAP Injection (CWE-90)** - `App.java`, `VulnerableInjection.java`
- **XPath Injection (CWE-643)** - `VulnerableInjection.java`
- **XSS (CWE-79)** - `App.java`
- **XXE (CWE-611)** - `App.java`
- **NoSQL Injection (CWE-943)** - `VulnerableInjection.java`
- **Log Injection (CWE-117)** - `VulnerableInjection.java`
- **Expression Language Injection (CWE-917)** - `VulnerableInjection.java`

### Path Traversal & File Operations
- **Path Traversal (CWE-22)** - `App.java`, `VulnerableFileHandler.java`
- **Zip Slip (CWE-22)** - `VulnerableFileHandler.java`
- **Unrestricted File Upload (CWE-434)** - `VulnerableFileHandler.java`
- **External File Path Control (CWE-73)** - `VulnerableFileHandler.java`
- **Insecure File Permissions (CWE-732)** - `VulnerableFileHandler.java`

### Cryptographic Issues
- **Weak Hash Algorithms (CWE-327)** - `App.java`, `VulnerableAuth.java`
  - MD5, SHA1 usage
- **Weak Encryption (CWE-327)** - `VulnerableAuth.java`
  - DES encryption
- **ECB Mode Usage (CWE-326)** - `VulnerableAuth.java`
- **Static IV (CWE-329)** - `VulnerableAuth.java`
- **Weak Random (CWE-330, CWE-338)** - `App.java`, `VulnerableAuth.java`
- **Hardcoded Encryption Keys (CWE-321)** - `VulnerableAuth.java`
- **Disabled SSL Validation** - `VulnerableAuth.java`

### Deserialization Vulnerabilities
- **Insecure Deserialization (CWE-502)** - `App.java`, `VulnerableDeserialization.java`
- **XMLDecoder Usage (CWE-502)** - `VulnerableDeserialization.java`
- **Unsafe YAML Parsing (CWE-502)** - `VulnerableDeserialization.java`

### Security Misconfigurations
- **Hardcoded Credentials (CWE-798)** - `App.java`, `application.properties`
- **Hardcoded API Keys** - `App.java`, `application.properties`
- **Insecure Cookies (CWE-614)** - `App.java`
- **Debug Mode Enabled** - `application.properties`
- **CORS Misconfiguration** - `application.properties`
- **CSRF Disabled** - `application.properties`

### Resource Management
- **Resource Leaks (CWE-404, CWE-775)** - `App.java`, `VulnerableFileHandler.java`
- **Unclosed Streams** - Multiple files
- **File Descriptor Leaks** - `VulnerableFileHandler.java`

### Other Vulnerabilities
- **SSRF (CWE-918)** - `App.java`
- **Null Pointer Dereference** - `App.java`
- **Sensitive Data in Temp Files (CWE-377)** - `VulnerableFileHandler.java`

## File Structure

```
src/main/java/com/example/
├── App.java                        # Main app with multiple vulnerabilities
├── VulnerableAuth.java             # Cryptographic vulnerabilities
├── VulnerableFileHandler.java      # File operation vulnerabilities
├── VulnerableInjection.java        # Injection vulnerabilities
└── VulnerableDeserialization.java  # Deserialization vulnerabilities

src/main/resources/
├── application.properties          # Configuration with hardcoded secrets
└── log4j2.xml                     # Log4j configuration
```

## Testing Instructions

### Dependency Scanning
```bash
# Using Gradle dependency check
./gradlew dependencyCheckAnalyze

# Using OWASP Dependency-Check
dependency-check --project "VulnerableApp" --scan .

# Using Snyk
snyk test
```

### Static Code Analysis
```bash
# Using CodeQL
codeql database create codeql-db --language=java
codeql database analyze codeql-db --format=sarif-latest --output=results.sarif

# Using SpotBugs
./gradlew spotbugsMain

# Using SonarQube
./gradlew sonarqube
```

### Building the Project
```bash
# Build with Gradle
./gradlew build

# Run the application
./gradlew run
```

## Remediation Examples

For each vulnerability type, proper remediation would involve:

1. **Dependencies**: Update to latest patched versions
2. **SQL Injection**: Use PreparedStatements with parameterized queries
3. **Command Injection**: Avoid Runtime.exec(), use ProcessBuilder with validation
4. **Path Traversal**: Validate and sanitize file paths, use allowlists
5. **Weak Crypto**: Use strong algorithms (AES-256, SHA-256, BCrypt)
6. **Deserialization**: Implement allowlists, use safer serialization formats
7. **Hardcoded Secrets**: Use environment variables or secret management systems
8. **Resource Leaks**: Use try-with-resources statements

## License

This project is for educational and testing purposes only.
