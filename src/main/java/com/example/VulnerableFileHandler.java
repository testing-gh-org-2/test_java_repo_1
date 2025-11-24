package com.example;

import java.io.*;
import java.nio.file.*;
import java.util.zip.*;

/**
 * File handling class with path traversal and file operation vulnerabilities
 */
public class VulnerableFileHandler {
    
    // Path traversal vulnerability (CWE-22)
    public static File getFile(String filename) {
        // Vulnerable: no path validation
        return new File("/var/app/data/" + filename);
    }
    
    // Arbitrary file write (CWE-22)
    public static void saveUploadedFile(String filename, byte[] content) throws IOException {
        // Vulnerable: no sanitization of filename
        FileOutputStream fos = new FileOutputStream("/uploads/" + filename);
        fos.write(content);
        fos.close();
    }
    
    // Zip slip vulnerability (CWE-22)
    public static void unzip(String zipFilePath, String destDirectory) throws IOException {
        byte[] buffer = new byte[1024];
        ZipInputStream zis = new ZipInputStream(new FileInputStream(zipFilePath));
        ZipEntry zipEntry = zis.getNextEntry();
        
        while (zipEntry != null) {
            // Vulnerable: no validation of zip entry path
            File newFile = new File(destDirectory + File.separator + zipEntry.getName());
            
            new File(newFile.getParent()).mkdirs();
            FileOutputStream fos = new FileOutputStream(newFile);
            
            int len;
            while ((len = zis.read(buffer)) > 0) {
                fos.write(buffer, 0, len);
            }
            
            fos.close();
            zipEntry = zis.getNextEntry();
        }
        
        zis.closeEntry();
        zis.close();
    }
    
    // Unrestricted file upload (CWE-434)
    public static void handleFileUpload(String filename, InputStream content) throws IOException {
        // Vulnerable: no file type validation
        Files.copy(content, Paths.get("/var/www/uploads/" + filename));
    }
    
    // Sensitive data in temp files (CWE-377)
    public static File createTempFile(String sensitiveData) throws IOException {
        File temp = File.createTempFile("data", ".tmp"); // Vulnerable: predictable name
        FileWriter writer = new FileWriter(temp);
        writer.write(sensitiveData);
        writer.close();
        return temp;
    }
    
    // External control of file path (CWE-73)
    public static String readUserFile(String userProvidedPath) throws IOException {
        // Vulnerable: user controls file path completely
        return new String(Files.readAllBytes(Paths.get(userProvidedPath)));
    }
    
    // File descriptor leak (CWE-775)
    public static String readFileWithLeak(String path) throws IOException {
        FileInputStream fis = new FileInputStream(path);
        // Vulnerable: stream never closed
        return new String(fis.readAllBytes());
    }
    
    // Insecure file permissions (CWE-732)
    public static void createWorldWritableFile(String filename) throws IOException {
        File file = new File(filename);
        file.createNewFile();
        file.setWritable(true, false); // Vulnerable: world-writable
        file.setReadable(true, false); // Vulnerable: world-readable
    }
}
