// SSD Project for Continuous Threat Monitoring
// Course: CS4612 - 01
// Team Members: Cameron Cummings, Ethan Byrd, Matthew Fincher

// Import required libraries and modules
import java.util.*;
import java.nio.file.*;
import java.io.*;

public class ContinuousMonitor {

    // Define the path to the log file as a constant string
    private static final String LOG_FILE = "log.txt";

    // Entry point for the program
    public static void main(String[] args) throws InterruptedException {
        // Infinite loop to continuously monitor threats
        while (true) {
            update();
            // Introduce a delay of 5 seconds between each cycle of threat checks
            Thread.sleep(5000);
        }
    }    

    // Function to check the log file for various threats
    public static void update() {
        System.out.println("Checking for threats...");

        try {
            // Read all lines from the specified log file and store them in a list
            List<String> logs = Files.readAllLines(Paths.get(LOG_FILE));

            // Check for various threat patterns in the logs and print messages if detected
            if (checkBuffer(logs) == 0) {
                System.out.println("Buffer attack detected!");
            }
            if (checkLibc(logs) == 0) {
                System.out.println("Libc attack detected!");
            }
            if (checkStringFormat(logs) == 0) {
                System.out.println("String format attack detected!");
            }
            if (checkHeap(logs) == 0) {
                System.out.println("Heap attack detected!");
            }
            if (checkShellshock(logs) == 0) {
                System.out.println("Shellshock attack detected!");
            }
            if (checkRaceCondition(logs) == 0) {
                System.out.println("Race condition vulnerability detected!");
            }
            if (checkWebAttack(logs) == 0) {
                System.out.println("Web attack detected!");
            }
            if (checkSQL(logs) == 0) {
                System.out.println("SQL injection detected!");
            }

        } catch (IOException e) {
            // Handle any exceptions encountered when reading the log file
            System.out.println("Error reading log file: " + e.getMessage());
        }
    }

    // Check for buffer overflow attack patterns in the logs
    public static int checkBuffer(List<String> logs) {
        for(String log : logs) {
            if(log.contains("BUFFER_ATTACK_PATTERN")) {
                return 0; // Attack detected
            }
        }
        return 1; // No attack detected
    }

    // Check for libc attack patterns in the logs
    public static int checkLibc(List<String> logs) {
        for(String log : logs) {
            if(log.contains("LIBC_ATTACK_PATTERN")) {
                return 0;
            }
        }
        return 1;
    }

    // Check for string format attack patterns in the logs
    public static int checkStringFormat(List<String> logs) {
        for(String log : logs) {
            if(log.contains("STRING_FORMAT_ATTACK_PATTERN")) {
                return 0;
            }
        }
        return 1;
    }

    // Check for heap overflow attack patterns in the logs
    public static int checkHeap(List<String> logs) {
        for(String log : logs) {
            if(log.contains("HEAP_ATTACK_PATTERN")) {
                return 0;
            }
        }
        return 1;
    }

    // Check for Shellshock vulnerability patterns in the logs
    public static int checkShellshock(List<String> logs) {
        for(String log : logs) {
            if(log.contains("SHELLSHOCK_ATTACK_PATTERN")) {
                return 0;
            }
        }
        return 1;
    }

    // Check for race condition vulnerability patterns in the logs
    public static int checkRaceCondition(List<String> logs) {
        for(String log : logs) {
            if(log.contains("RACE_CONDITION_PATTERN")) {
                return 0;
            }
        }
        return 1;
    }

    // Check for web-based attack patterns in the logs
    public static int checkWebAttack(List<String> logs) {
        for(String log : logs) {
            if(log.contains("WEB_ATTACK_PATTERN")) {
                return 0;
            }
        }
        return 1;
    }

    // Check for SQL injection attack patterns in the logs
    public static int checkSQL(List<String> logs) {
        for(String log : logs) {
            if(log.contains("SQL_INJECTION_PATTERN")) {
                return 0;
            }
        }
        return 1;
    }
}
