package com.example;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for the App class.
 */
public class AppTest {
    
    @Test
    public void testGetGreeting() {
        App app = new App();
        assertEquals("Hello, World!", app.getGreeting());
    }
    
    @Test
    public void testGreetingNotNull() {
        App app = new App();
        assertNotNull(app.getGreeting());
    }
}
