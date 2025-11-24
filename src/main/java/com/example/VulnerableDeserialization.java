package com.example;

import java.io.*;
import java.beans.*;

/**
 * Class demonstrating insecure deserialization vulnerabilities
 */
public class VulnerableDeserialization {
    
    // Unsafe deserialization (CWE-502)
    public static Object deserialize(byte[] data) throws Exception {
        ByteArrayInputStream bis = new ByteArrayInputStream(data);
        ObjectInputStream ois = new ObjectInputStream(bis);
        // Vulnerable: deserializing untrusted data
        return ois.readObject();
    }
    
    // Unsafe deserialization from file (CWE-502)
    public static Object loadObject(String filename) throws Exception {
        FileInputStream fis = new FileInputStream(filename);
        ObjectInputStream ois = new ObjectInputStream(fis);
        // Vulnerable: no integrity check
        return ois.readObject();
    }
    
    // XMLDecoder deserialization (CWE-502)
    public static Object deserializeXML(InputStream input) {
        XMLDecoder decoder = new XMLDecoder(input);
        // Vulnerable: XMLDecoder can execute arbitrary code
        return decoder.readObject();
    }
    
    // Unsafe YAML deserialization (if SnakeYAML is used)
    public static Object deserializeYAML(String yaml) {
        // Vulnerable: would allow arbitrary code execution with SnakeYAML
        org.yaml.snakeyaml.Yaml yamlParser = new org.yaml.snakeyaml.Yaml();
        return yamlParser.load(yaml);
    }
    
    // Custom vulnerable serialization
    public static class UnsafeSerializable implements Serializable {
        private static final long serialVersionUID = 1L;
        private String command;
        
        // Vulnerable: executes command on deserialization
        private void readObject(ObjectInputStream in) throws Exception {
            in.defaultReadObject();
            Runtime.getRuntime().exec(command); // Dangerous!
        }
        
        public void setCommand(String command) {
            this.command = command;
        }
    }
    
    // Object injection via serialization
    public static void processSerializedData(byte[] data) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        Object obj = ois.readObject(); // Vulnerable: no type checking
        
        if (obj instanceof Runnable) {
            ((Runnable) obj).run(); // Vulnerable: executing deserialized code
        }
    }
}
