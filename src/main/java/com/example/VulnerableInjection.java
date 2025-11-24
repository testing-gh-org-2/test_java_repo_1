package com.example;

import java.sql.*;
import javax.naming.*;
import javax.naming.directory.*;

/**
 * Class demonstrating various injection vulnerabilities
 */
public class VulnerableInjection {
    
    private static Connection connection;
    
    // SQL Injection - String concatenation (CWE-89)
    public static ResultSet getUserByUsername(String username) throws SQLException {
        Statement stmt = connection.createStatement();
        String query = "SELECT * FROM users WHERE username = '" + username + "'";
        return stmt.executeQuery(query); // Vulnerable: SQL injection
    }
    
    // SQL Injection - Dynamic ORDER BY (CWE-89)
    public static ResultSet getSortedUsers(String sortColumn) throws SQLException {
        Statement stmt = connection.createStatement();
        String query = "SELECT * FROM users ORDER BY " + sortColumn;
        return stmt.executeQuery(query); // Vulnerable: column name injection
    }
    
    // NoSQL Injection (CWE-943)
    public static String buildMongoQuery(String username, String password) {
        // Vulnerable: NoSQL injection in JSON query
        return "{ username: '" + username + "', password: '" + password + "' }";
    }
    
    // LDAP Injection (CWE-90)
    public static void authenticateUser(String username, String password) throws NamingException {
        DirContext ctx = new InitialDirContext();
        String filter = "(&(uid=" + username + ")(userPassword=" + password + "))";
        // Vulnerable: LDAP injection
        ctx.search("ou=users,dc=example,dc=com", filter, new SearchControls());
    }
    
    // OS Command Injection (CWE-78)
    public static void pingHost(String hostname) throws Exception {
        // Vulnerable: command injection
        Runtime.getRuntime().exec("ping -c 4 " + hostname);
    }
    
    // OS Command Injection with array (still vulnerable) (CWE-78)
    public static void executeCommand(String userInput) throws Exception {
        // Vulnerable: user input in command
        String[] cmd = {"/bin/sh", "-c", "echo " + userInput};
        Runtime.getRuntime().exec(cmd);
    }
    
    // XPath Injection (CWE-643)
    public static void queryXML(String username, String password) throws Exception {
        javax.xml.xpath.XPathFactory xpathFactory = javax.xml.xpath.XPathFactory.newInstance();
        javax.xml.xpath.XPath xpath = xpathFactory.newXPath();
        
        String expression = "//users/user[username/text()='" + username + 
                          "' and password/text()='" + password + "']";
        // Vulnerable: XPath injection
        xpath.compile(expression);
    }
    
    // Expression Language Injection (CWE-917)
    public static Object evaluateExpression(String userExpression) throws Exception {
        // Vulnerable: EL injection
        javax.el.ExpressionFactory factory = javax.el.ExpressionFactory.newInstance();
        javax.el.ELContext context = new javax.el.StandardELContext(factory);
        javax.el.ValueExpression expr = factory.createValueExpression(context, 
            "${" + userExpression + "}", Object.class);
        return expr.getValue(context);
    }
    
    // Template Injection (CWE-94)
    public static String renderTemplate(String userInput) {
        // Vulnerable: template injection (if used with template engine)
        return "Welcome, ${" + userInput + "}!";
    }
    
    // HTTP Header Injection (CWE-113)
    public static void setResponseHeader(javax.servlet.http.HttpServletResponse response, 
                                        String value) {
        // Vulnerable: CRLF injection in header
        response.setHeader("X-User-Data", value);
    }
    
    // Log Injection (CWE-117)
    public static void logUserInput(String userInput) {
        // Vulnerable: log forging
        System.out.println("User activity: " + userInput);
    }
}
