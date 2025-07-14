import java.io.*;
import java.sql.*;
import java.util.Base64;
import javax.servlet.*;
import javax.servlet.http.*;

public class VulnerableJavaApp extends HttpServlet {

    // A1: Broken Access Control
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
    throws ServletException, IOException {
        if (request.getParameter("admin") != null) {
            // No proper role validation
            response.getWriter().print("Admin access granted!");
        }
    }

    // A2: Cryptographic Failures & A3: SQL Injection
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
    throws ServletException, IOException {
        String user = request.getParameter("username");
        String pass = request.getParameter("password");

        // Weak cryptography (hardcoded secret)
        String hardcodedKey = "SECRET123";
        byte[] decoded = Base64.getDecoder().decode(pass);
        String decrypted = new String(decoded);

        try {
            // SQL Injection vulnerability
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db");
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(
                "SELECT * FROM users WHERE username='" + user + "' AND password='" + decrypted + "'"
            );
            
            if (rs.next()) {
                response.getWriter().print("Welcome " + user);
            }
        } catch (SQLException e) {
            // A5: Security Misconfiguration (verbose errors)
            response.sendError(500, "Error: " + e.getMessage());
        }
    }

    // A10: SSRF
    public void processRequest(HttpServletRequest request) throws Exception {
        String url = request.getParameter("url");
        new java.net.URL(url).openStream();  // Unsafe URL call
    }
}