// SSD Project for Continuous Threat Monitoring
// Course: CS4612 - 01
// Team Members: Cameron Cummings, Ethan Byrd, Matthew Fincher

// Import required libraries and modules
import java.util.*;
import java.nio.file.*;
import java.io.*;

public class ContinuousMonitor {

    // Define the name of the log file as a constant string
    private static final String LOG_FILE = "log.txt";

    // Define the name of the patterns to look for, for each type of attack, including a suspicious activity file for each
    private static final String patternsFile = "AttackPatterns.txt";
    private static final String bufferAlerts = "BufferAlerts.txt";
    private static final String bufferSuspicious = "BufferSuspicious.txt";
    private static final String libcAlerts = "LibcAlerts.txt";
    private static final String libcSuspicious = "LibcSuspicious.txt";
    private static final String heapAlerts = "HeapAlerts.txt";
    private static final String heapSuspicious = "HeapSuspicious.txt";
    private static final String raceAlerts = "RaceAlerts.txt";
    private static final String raceSuspicious = "RaceSuspicious.txt";
    private static final String shellshockAlerts = "ShellshockAlerts.txt";
    private static final String shellshockSuspicious = "ShellshockSuspicious.txt";
    private static final String SQLAlerts = "SQLAlerts.txt";
    private static final String SQLSuspicious = "SQLSuspicious.txt";
    private static final String stringFormatAlerts = "StringFormatAlerts.txt";
    private static final String stringFormatSuspicious = "StringFormatSuspicious.txt";
    private static final String webAlerts = "WebAlerts.txt";
    private static final String webSuspicious = "WebSuspicious.txt";

    // Entry point for the program
    public static void main(String[] args) throws InterruptedException {
        try (Scanner scan = new Scanner(System.in)) {
            // Infinite loop to continuously monitor threats; change from true to listening for some input?
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
    }    

    // Function to check the input for various threats
    public static void update(String inputString, String fileName) {
        try {
            boolean checkFile = false;
            FileWriter myWriter = new FileWriter("log.txt");
            List<String> file = new ArrayList<String>(){};
            List<String> patterns = Files.readAllLines(Paths.get(patternsFile));
            
            //chooses to run through try/catch based on input of string vs. file
            if(inputString == null) {
                checkFile = true;
                //Read all lines from the specified file and store them in a list
                file = Files.readAllLines(Paths.get(fileName));
            } else {
                checkFile = false;
            }
            System.out.println("Checking for threats...");
        
            if(checkFile) {
                // Check for various threat patterns in the file and print messages if detected
                for (String line : file) {
                    if (checkAttacks(line, patterns) == 1) {
                        System.out.println("Suspicious activity detected...");
                        myWriter.append("****Attack detected on line:\n" + line + "\n");
                    }
                }
            } else {
                // Check for various threat patterns in the patterns file and print messages if detected
                if (checkAttacks(inputString, patterns) == 1) {
                    System.out.println("Suspicious activity detected...");
                }
                
            }
        } catch (IOException e) {
            // Handle any exceptions encountered when reading the files
            System.out.println("Error reading file: " + e.getMessage());
        }
    }

    // Check for buffer overflow attack patterns in the patterns file
    public static int checkAttacks(String string, List<String> pattern) {
        if(pattern.contains(string)) {
            
            return 1; // Attack detected
        }
        return 0; // No attack detected
    }

    /*
    // Check for libc attack patterns in the patterns file
    public static int checkLibc(String string, List<String> pattern) {
        if(pattern.contains(string)) {
            return 1;
        }
        return 0;
    }

    // Check for string format attack patterns in the patterns file
    public static int checkStringFormat(String string, List<String> pattern) {
        if(pattern.contains(string)) {
            return 1;
        }
        return 0;
    }

    // Check for heap overflow attack patterns in the patterns file
    public static int checkHeap(String string, List<String> pattern) {
        if(pattern.contains(string)) {
            return 1;
        }
        return 0;
    }

    // Check for Shellshock vulnerability patterns in the patterns file
    public static int checkShellshock(String string, List<String> pattern) {
        if(pattern.contains(string)) {
            return 1;
        }
        return 0;
    }

    // Check for race condition vulnerability patterns in the patterns file
    public static int checkRaceCondition(String string, List<String> pattern) {
        if(pattern.contains(string)) {
            return 1;
        }
        return 0;
    }

    // Check for web-based attack patterns in the patterns file
    public static int checkWebAttack(String string, List<String> pattern) {
        if(pattern.contains(string)) {
            return 1;
        }
        return 0;
    }

    // Check for SQL injection attack patterns in the patterns file
    public static int checkSQL(String string, List<String> pattern) {
        if(pattern.contains(string)) {
             return 1;
        }
        return 0;
    }
    */

    //returns a random int between 0-1 to simulate the user inputting something into a website/application
    //returns 0 for string (i.e. user and pass)
    //returns 1 for a file
    public static int randomInput() {
        Random rand = new Random();
        return (rand.nextInt(11) % 2);
    }
}
