// SSD Project for Continuous Threat Monitoring
// Course: CS4612 - 01
// Team Members: Cameron Cummings, Ethan Byrd, Matthew Fincher

// Import required libraries and modules
import java.util.*;
import java.nio.file.*;
import java.io.*;

public class ContinuousMonitor {
    // Define the name of the patterns to look for, for each type of attack, including a suspicious activity file for each
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
            //writer to write results into a log file
            FileWriter myWriter = new FileWriter("log.txt");

            //creates a list of strings from the file that is input (used for text files)
            List<String> file = new ArrayList<String>(){};

            //creates string lists for each of the possible attacks, two for each; one for actual alerts and one for suspicious acitivity
            //in our case, we are focusing more on the time completed rather than the memory used, since it is on a fairly small scale
            List<String> bufferAlertList = Files.readAllLines(Paths.get(bufferAlerts));
            List<String> bufferSuspiciousList = Files.readAllLines(Paths.get(bufferSuspicious));
            List<String> heapAlertList = Files.readAllLines(Paths.get(heapAlerts));
            List<String> heapSuspiciousList = Files.readAllLines(Paths.get(heapSuspicious));
            List<String> libcAlertList = Files.readAllLines(Paths.get(libcAlerts));
            List<String> libcSuspiciousList = Files.readAllLines(Paths.get(libcSuspicious));
            List<String> raceAlertList = Files.readAllLines(Paths.get(raceAlerts));
            List<String> raceSuspiciousList = Files.readAllLines(Paths.get(raceSuspicious));
            List<String> shellshockAlertList = Files.readAllLines(Paths.get(shellshockAlerts));
            List<String> shellshockSuspiciousList = Files.readAllLines(Paths.get(shellshockSuspicious));
            List<String> SQLAlertList = Files.readAllLines(Paths.get(SQLAlerts));
            List<String> SQLSuspiciousList = Files.readAllLines(Paths.get(SQLSuspicious));
            List<String> stringFormatAlertList = Files.readAllLines(Paths.get(stringFormatAlerts));
            List<String> stringFormatSuspiciousList = Files.readAllLines(Paths.get(stringFormatSuspicious));
            List<String> webAlertList = Files.readAllLines(Paths.get(webAlerts));
            List<String> webSuspiciousList = Files.readAllLines(Paths.get(webSuspicious));
            
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
                    int result = 0;
                    //check each attack method; int for result
                    //alert == 1; suspicious == 2;

                    //checks against buffer attacks, and writes to log
                    result = checkBuffer(line, bufferAlertList, bufferSuspiciousList);
                    writeAlert(myWriter, result, line);

                    //checks against heap attacks, and writes to log
                    result = checkHeap(line, heapAlertList, heapSuspiciousList);
                    writeAlert(myWriter, result, line);

                    //checks against libc attacks, and writes to log
                    result = checkLibc(line, libcAlertList, libcSuspiciousList);
                    writeAlert(myWriter, result, line);

                    //checks against race condition attacks, and writes to log
                    result = checkRaceCondition(line, raceAlertList, raceSuspiciousList);
                    writeAlert(myWriter, result, line);

                    //checks against SQL attacks, and writes to log
                    result = checkSQL(line, SQLAlertList, SQLSuspiciousList);
                    writeAlert(myWriter, result, line);

                    //checks against shellshock attacks, and writes to log
                    result = checkShellshock(line, shellshockAlertList, shellshockSuspiciousList);
                    writeAlert(myWriter, result, line);

                    //checks against string format attacks, and writes to log
                    result = checkStringFormat(line, stringFormatAlertList, stringFormatSuspiciousList);
                    writeAlert(myWriter, result, line);

                    //checks against web attacks, and writes to log
                    result = checkWebAttack(line, webAlertList, webSuspiciousList);
                    writeAlert(myWriter, result, line);
                }
            } else {
                // Check for various threat patterns in the input string and print messages if detected
                
                int result = 0;
                //check each attack method; int for result
                //alert == 1; suspicious == 2;

                //checks against buffer attacks, and writes to log
                System.out.println("Checking for buffer attacks...");
                result = checkBuffer(inputString, bufferAlertList, bufferSuspiciousList);
                writeAlert(myWriter, result, inputString);

                //checks against heap attacks, and writes to log
                System.out.println("Checking for heap attacks...");
                result = checkHeap(inputString, heapAlertList, heapSuspiciousList);
                writeAlert(myWriter, result, inputString);

                //checks against libc attacks, and writes to log
                System.out.println("Checking for libc attacks...");
                result = checkLibc(inputString, libcAlertList, libcSuspiciousList);
                writeAlert(myWriter, result, inputString);

                //checks against race condition attacks, and writes to log
                System.out.println("Checking for race condition attacks...");
                result = checkRaceCondition(inputString, raceAlertList, raceSuspiciousList);
                writeAlert(myWriter, result, inputString);

                //checks against SQL attacks, and writes to log
                System.out.println("Checking for SQL attacks...");
                result = checkSQL(inputString, SQLAlertList, SQLSuspiciousList);
                writeAlert(myWriter, result, inputString);

                //checks against shellshock attacks, and writes to log
                System.out.println("Checking for shellshock attacks...");
                result = checkShellshock(inputString, shellshockAlertList, shellshockSuspiciousList);
                writeAlert(myWriter, result, inputString);

                //checks against string format attacks, and writes to log
                System.out.println("Checking for string format attacks...");
                result = checkStringFormat(inputString, stringFormatAlertList, stringFormatSuspiciousList);
                writeAlert(myWriter, result, inputString);

                //checks against web attacks, and writes to log
                System.out.println("Checking for web attacks...");
                result = checkWebAttack(inputString, webAlertList, webSuspiciousList);
                writeAlert(myWriter, result, inputString);
            }
        } catch (IOException e) {
            // Handle any exceptions encountered when reading the files
            System.out.println("Error reading file: " + e.getMessage());
        }
    }

    public static void writeAlert(FileWriter myWriter, int result, String line) {
        try {
            if (result == 1) {
            System.out.println("Suspicious activity detected...");
            myWriter.append("**Possible attack detected on line:\n" + line + "\n");
            } else if(result == 2) {
                System.out.println("Suspicious activity detected...");
                myWriter.append("****Attack detected on line:\n" + line + "\n");
            } else {
                System.out.println("Line Clean");
                myWriter.append("Clean\n");
            }
        } catch (Exception e) {
            System.out.println("Error reading file: " + e.getMessage());
        }
    }

    // Check for buffer overflow attack patterns in the patterns file; returns 2 for suspicious activity, 1 for attack alert, and 0 for clean
    public static int checkBuffer(String string, List<String> alertStrings, List<String> suspiciousStrings) {
        int toReturn = 0;
        for (String line : suspiciousStrings) {
            if(string.contains(line)) {
                toReturn = 2;
            }
        }
        for (String line : alertStrings) {
            if(string.contains(line)) {
                toReturn = 1;
            }
        }
        return toReturn;
    }

    // Check for libc attack patterns in the patterns file; returns 2 for suspicious activity, 1 for attack alert, and 0 for clean
    public static int checkLibc(String string, List<String> alertStrings, List<String> suspiciousStrings) {
        int toReturn = 0;
        for (String line : suspiciousStrings) {
            if(string.contains(line)) {
                toReturn = 2;
            }
        }
        for (String line : alertStrings) {
            if(string.contains(line)) {
                toReturn = 1;
            }
        }
        return toReturn;
    }

    // Check for string format attack patterns in the patterns file; returns 2 for suspicious activity, 1 for attack alert, and 0 for clean
    public static int checkStringFormat(String string, List<String> alertStrings, List<String> suspiciousStrings) {
        int toReturn = 0;
        for (String line : suspiciousStrings) {
            if(string.contains(line)) {
                toReturn = 2;
            }
        }
        for (String line : alertStrings) {
            if(string.contains(line)) {
                toReturn = 1;
            }
        }
        return toReturn;
    }

    // Check for heap overflow attack patterns in the patterns file; returns 2 for suspicious activity, 1 for attack alert, and 0 for clean
    public static int checkHeap(String string, List<String> alertStrings, List<String> suspiciousStrings) {
        int toReturn = 0;
        for (String line : suspiciousStrings) {
            if(string.contains(line)) {
                toReturn = 2;
            }
        }
        for (String line : alertStrings) {
            if(string.contains(line)) {
                toReturn = 1;
            }
        }
        return toReturn;
    }

    // Check for Shellshock vulnerability patterns in the patterns file; returns 2 for suspicious activity, 1 for attack alert, and 0 for clean
    public static int checkShellshock(String string, List<String> alertStrings, List<String> suspiciousStrings) {
        int toReturn = 0;
        for (String line : suspiciousStrings) {
            if(string.contains(line)) {
                toReturn = 2;
            }
        }
        for (String line : alertStrings) {
            if(string.contains(line)) {
                toReturn = 1;
            }
        }
        return toReturn;
    }

    // Check for race condition vulnerability patterns in the patterns file; returns 2 for suspicious activity, 1 for attack alert, and 0 for clean
    public static int checkRaceCondition(String string, List<String> alertStrings, List<String> suspiciousStrings) {
        int toReturn = 0;
        for (String line : suspiciousStrings) {
            if(string.contains(line)) {
                toReturn = 2;
            }
        }
        for (String line : alertStrings) {
            if(string.contains(line)) {
                toReturn = 1;
            }
        }
        return toReturn;
    }

    // Check for web-based attack patterns in the patterns file; returns 2 for suspicious activity, 1 for attack alert, and 0 for clean
    public static int checkWebAttack(String string, List<String> alertStrings, List<String> suspiciousStrings) {
        int toReturn = 0;
        for (String line : suspiciousStrings) {
            if(string.contains(line)) {
                toReturn = 2;
            }
        }
        for (String line : alertStrings) {
            if(string.contains(line)) {
                toReturn = 1;
            }
        }
        return toReturn;
    }

    // Check for SQL injection attack patterns in the patterns file; returns 2 for suspicious activity, 1 for attack alert, and 0 for clean
    public static int checkSQL(String string, List<String> alertStrings, List<String> suspiciousStrings) {
        int toReturn = 0;
        for (String line : suspiciousStrings) {
            if(string.contains(line)) {
                toReturn = 2;
            }
        }
        for (String line : alertStrings) {
            if(string.contains(line)) {
                toReturn = 1;
            }
        }
        return toReturn;
    }

    //returns a random int between 0-1 to simulate the user inputting something into a website/application
    //returns 0 for string (i.e. user and pass)
    //returns 1 for a file
    public static int randomInput() {
        Random rand = new Random();
        return (rand.nextInt(11) % 2);
    }
}