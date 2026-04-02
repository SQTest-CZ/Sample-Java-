package org.example;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

/**
 * Sample class containing intentional security vulnerabilities for SonarQube scanning demos.
 * DO NOT use this code in production.
 */
public class VulnerableService {

    // SONAR: S2068 - Hardcoded credentials
    private static final String DB_PASSWORD = "admin123";
    private static final String DB_URL = "jdbc:mysql://localhost:3306/mydb";
    private static final String DB_USER = "root";

    /**
     * SONAR: S3649 - SQL injection vulnerability.
     * User input is concatenated directly into the SQL query.
     */
    public ResultSet findUser(String username) throws Exception {
        Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
        Statement stmt = conn.createStatement();
        // Noncompliant: user-controlled input flows directly into the query
        String query = "SELECT * FROM users WHERE username = '" + username + "'";
        return stmt.executeQuery(query);
    }

    /**
     * SONAR: S2083 - Path traversal vulnerability.
     * User input is used to construct a file path without sanitization.
     */
    public byte[] readFile(String filename) throws IOException {
        // Noncompliant: attacker can pass "../../../etc/passwd" as filename
        File file = new File("/var/app/uploads/" + filename);
        try (FileInputStream fis = new FileInputStream(file)) {
            return fis.readAllBytes();
        }
    }

    /**
     * SONAR: S5131 - HTTP response splitting / reflected XSS via header injection.
     * User-controlled value is set directly as a response header.
     */
    public String buildRedirectHeader(String userSuppliedUrl) {
        // Noncompliant: attacker can inject newlines to split the HTTP response
        return "Location: " + userSuppliedUrl;
    }
}
