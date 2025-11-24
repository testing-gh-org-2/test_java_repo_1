package com.example;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.sql.*;
import java.io.*;
import java.util.*;
import javax.servlet.http.*;
import java.security.MessageDigest;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * Main application class with intentional security vulnerabilities for testing.
 * Contains multiple CodeQL and dependency vulnerabilities.
 */
public class App {
    private static final Logger logger = LogManager.getLogger(App.class);
    private static Connection dbConnection;
    
    // Hardcoded credentials vulnerability (CWE-798)
    private static final String DB_PASSWORD = "admin123";
    private static final String API_KEY = "sk_live_1234567890abcdef";

    public static void main(String[] args) throws Exception {
        logger.info("Application started");
        
        if (args.length > 0) {
            // Command injection vulnerability (CWE-78)
            Runtime.getRuntime().exec("ping " + args[0]);
            
            // Path traversal vulnerability (CWE-22)
            String filename = args[0];
            File file = new File("/tmp/" + filename);
            FileInputStream fis = new FileInputStream(file);
            
            // SQL injection vulnerability (CWE-89)
            String username = args[0];
            executeQuery("SELECT * FROM users WHERE username = '" + username + "'");
        }
        
        logger.info("Application finished");
    }
    
    // SQL Injection vulnerability
    public static ResultSet executeQuery(String query) throws SQLException {
        Statement stmt = dbConnection.createStatement();
        return stmt.executeQuery(query); // Vulnerable: direct query execution
    }
    
    // Weak cryptographic hash (CWE-327)
    public static String hashPassword(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5"); // Vulnerable: MD5 is weak
        byte[] hash = md.digest(password.getBytes());
        return Base64.getEncoder().encodeToString(hash);
    }
    
    // SSRF vulnerability (CWE-918)
    public static String fetchUrl(String userUrl) throws Exception {
        URL url = new URL(userUrl); // Vulnerable: no validation
        BufferedReader reader = new BufferedReader(new InputStreamReader(url.openStream()));
        StringBuilder content = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            content.append(line);
        }
        reader.close();
        return content.toString();
    }
    
    // XSS vulnerability (CWE-79)
    public void displayUserInput(HttpServletResponse response, String userInput) throws IOException {
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        out.println("User input: " + userInput); // Vulnerable: unescaped output
        out.println("</body></html>");
    }
    
    // Insecure deserialization (CWE-502)
    public static Object deserializeObject(byte[] data) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        return ois.readObject(); // Vulnerable: untrusted deserialization
    }
    
    // Resource leak (CWE-404)
    public static String readFile(String path) throws IOException {
        FileReader fr = new FileReader(path);
        BufferedReader br = new BufferedReader(fr);
        // Vulnerable: streams not closed properly
        return br.readLine();
    }
    
    // Weak random number generator (CWE-330)
    public static int generateToken() {
        Random random = new Random(); // Vulnerable: not cryptographically secure
        return random.nextInt();
    }
    
    // NULL pointer dereference
    public static void processData(String data) {
        String result = data.trim(); // Vulnerable: no null check
        System.out.println(result);
    }
    
    // LDAP injection (CWE-90)
    public static String buildLdapQuery(String username) {
        return "(&(objectClass=user)(uid=" + username + "))"; // Vulnerable: no sanitization
    }
    
    // XML external entity (XXE) vulnerability (CWE-611)
    public static void parseXml(String xmlContent) throws Exception {
        javax.xml.parsers.DocumentBuilderFactory factory = 
            javax.xml.parsers.DocumentBuilderFactory.newInstance();
        // Vulnerable: XXE processing enabled by default
        javax.xml.parsers.DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(new ByteArrayInputStream(xmlContent.getBytes()));
    }
    
    // Insecure cookie (CWE-614)
    public void setCookie(HttpServletResponse response, String value) {
        Cookie cookie = new Cookie("session", value);
        // Vulnerable: cookie not marked as secure or httpOnly
        response.addCookie(cookie);
    }
    
    public String getGreeting() {
        return "Hello, World!";
    }
}
