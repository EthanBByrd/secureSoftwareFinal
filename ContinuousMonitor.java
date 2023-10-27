// SSD Project for Continuous Threat Monitoring
// Course: CS4612 - 01
// Team Members: Cameron Cummings, Ethan Byrd, Matthew Fincher

// Import required libraries and modules
import java.util.*;
import java.nio.file.*;
import java.io.*;

public class ContinuousMonitor {

    // Define the path to the log file as a constant string
    //private static final String LOG_FILE = "log.txt";

    // Entry point for the program
    public static void main(String[] args) throws InterruptedException {
        Scanner scan = new Scanner(System.in);
        // Infinite loop to continuously monitor threats
        while (true) {
            switch (randomInput()) {
                case 0: //allows the user to simulate putting in a string to a website/application (as if one was typing a username or password)
                    System.out.println("Please enter text: ");
                    update(scan.nextLine(), null);
                    break;
                case 1: //allows the user to simulate adding a file they would like to input into website/application (via its path)
                    System.out.println("Enter the name of the file you would like to add: ");
                    update(null, scan.nextLine());
                    break;
                default: //breaks out of current iteration of while loop in case of bug that returns something other than 0 or 1
                    continue;
            }

            // Introduce a delay of 5 seconds between each cycle of threat checks
            Thread.sleep(5000);
        }
    }    

    // Function to check the log file for various threats
    public static void update(String inputString, String fileName) {
        try {
            boolean checkFile = false;
            List<String> logs = new ArrayList<String>(){};
            //chooses to run through try/catch based on input of string vs. file
            if(inputString == null) {
                checkFile = true;
                //Read all lines from the specified log file and store them in a list
                logs = Files.readAllLines(Paths.get(fileName));
                //List<String> logs = Files.readAllLines(Paths.get(LOG_FILE));
            } else {
                checkFile = false;
            }
            System.out.println("Checking for threats...");
        
            if(checkFile) {
                // Check for various threat patterns in the logs and print messages if detected
                for (String line : logs) {
                    if (checkBuffer(line) == 1) {
                    System.out.println("Buffer attack detected!");
                    }
                    if (checkLibc(line) == 1) {
                        System.out.println("Libc attack detected!");
                    }
                    if (checkStringFormat(line) == 1) {
                        System.out.println("String format attack detected!");
                    }
                    if (checkHeap(line) == 1) {
                        System.out.println("Heap attack detected!");
                    }
                    if (checkShellshock(line) == 1) {
                        System.out.println("Shellshock attack detected!");
                    }
                    if (checkRaceCondition(line) == 1) {
                        System.out.println("Race condition vulnerability detected!");
                    }
                    if (checkWebAttack(line) == 1) {
                        System.out.println("Web attack detected!");
                    }
                    if (checkSQL(line) == 1) {
                        System.out.println("SQL injection detected!");
                    }
                }
                
            } else {
                // Check for various threat patterns in the logs and print messages if detected
                if (checkBuffer(logs) == 1) {
                    System.out.println("Buffer attack detected!");
                }
                if (checkLibc(logs) == 1) {
                    System.out.println("Libc attack detected!");
                }
                if (checkStringFormat(logs) == 1) {
                    System.out.println("String format attack detected!");
                }
                if (checkHeap(logs) == 1) {
                    System.out.println("Heap attack detected!");
                }
                if (checkShellshock(logs) == 1) {
                    System.out.println("Shellshock attack detected!");
                }
                if (checkRaceCondition(logs) == 1) {
                    System.out.println("Race condition vulnerability detected!");
                }
                if (checkWebAttack(logs) == 1) {
                    System.out.println("Web attack detected!");
                }
                if (checkSQL(logs) == 1) {
                    System.out.println("SQL injection detected!");
                }
            }
            

        } catch (IOException e) {
            // Handle any exceptions encountered when reading the log file
            System.out.println("Error reading log file: " + e.getMessage());
        }
    }

    // Check for buffer overflow attack patterns in the logs
    public static int checkBuffer(List<String> logs) {
        if(log.contains("BUFFER_ATTACK_PATTERN")) {
            return 1; // Attack detected
        }
        return 0; // No attack detected
    }

    // Check for libc attack patterns in the logs
    public static int checkLibc(String string) {
        if(log.contains("LIBC_ATTACK_PATTERN")) {
            return 1;
        }
        return 0;
    }

    // Check for string format attack patterns in the logs
    public static int checkStringFormat(String string) {
        if(log.contains("STRING_FORMAT_ATTACK_PATTERN")) {
            return 1;
        }
        return 0;
    }

    // Check for heap overflow attack patterns in the logs
    public static int checkHeap(String string) {
        if(log.contains("HEAP_ATTACK_PATTERN")) {
            return 1;
        }
        return 0;
    }

    // Check for Shellshock vulnerability patterns in the logs
    public static int checkShellshock(String string) {
        if(log.contains("SHELLSHOCK_ATTACK_PATTERN")) {
            return 1;
        }
        return 0;
    }

    // Check for race condition vulnerability patterns in the logs
    public static int checkRaceCondition(String string) {
        if(log.contains("RACE_CONDITION_PATTERN")) {
            return 1;
        }
        return 0;
    }

    // Check for web-based attack patterns in the logs
    public static int checkWebAttack(String string) {
        if(log.contains("WEB_ATTACK_PATTERN")) {
            return 1;
        }
        return 0;
    }

    // Check for SQL injection attack patterns in the logs
    public static int checkSQL(String string) {
        if(log.contains("SQL_INJECTION_PATTERN")) {
             return 1;
        }
        return 0;
    }

    //returns a random int between 0-1 to simulate the user inputting something into a website/application
    //returns 0 for string (i.e. user and pass)
    //returns 1 for a file
    public static int randomInput() {
        Random rand = new Random();
        return (rand.nextInt(11) % 2);
    }
}
