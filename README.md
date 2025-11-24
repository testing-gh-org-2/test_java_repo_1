# Test Java Dependency Issues Repository

This is a test Java Gradle project that intentionally includes a vulnerable dependency for testing purposes.

## Project Structure

```
test_java_dependency_issues_repo/
├── build.gradle
├── settings.gradle
├── src/
│   ├── main/
│   │   ├── java/
│   │   │   └── com/
│   │   │       └── example/
│   │   │           └── App.java
│   │   └── resources/
│   │       └── log4j2.xml
│   └── test/
│       └── java/
│           └── com/
│               └── example/
│                   └── AppTest.java
└── README.md
```

## Vulnerable Dependencies

This project includes multiple vulnerable dependencies for testing purposes:

**⚠️ WARNING**: These vulnerabilities are intentionally included for testing purposes only. Do not use this project in production environments.

### 1. Log4j Vulnerability
- **Dependency**: `org.apache.logging.log4j:log4j-core:2.14.1`
- **CVE**: CVE-2021-44228 (Log4Shell)
- **Severity**: Critical (CVSS 10.0)
- **Description**: Remote code execution vulnerability in Log4j

### 2. OpenSSL Vulnerability (via Netty)
- **Dependency**: `io.netty:netty-tcnative-boringssl-static:2.0.20.Final`
- **OpenSSL Version**: 1.0.2r (bundled)
- **CVEs**: CVE-2019-1543, CVE-2019-1547, CVE-2019-1563
- **Severity**: High
- **Description**: Multiple vulnerabilities in OpenSSL 1.0.2r including padding oracle attacks and side-channel attacks

## Building the Project

```bash
./gradlew build
```

## Running the Application

```bash
./gradlew run
```

## Running Tests

```bash
./gradlew test
```

## Fixing the Vulnerabilities

To fix the vulnerabilities, upgrade to secure versions:

```gradle
dependencies {
    // Fixed Log4j version
    implementation 'org.apache.logging.log4j:log4j-core:2.17.1'
    implementation 'org.apache.logging.log4j:log4j-api:2.17.1'
    
    // Fixed Netty tcnative version (uses updated OpenSSL/BoringSSL)
    implementation 'io.netty:netty-tcnative-boringssl-static:2.0.54.Final'
}
```

## Purpose

This project is designed for:
- Testing dependency scanning tools
- Demonstrating vulnerability detection
- Training and educational purposes
- CI/CD pipeline testing
