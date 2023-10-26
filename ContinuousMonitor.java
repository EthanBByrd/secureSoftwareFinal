//SSD Project
//CS4612 - 01
//Cameron Cummings, Ethan Byrd, Matthew Fincher

import java.util.*;
import java.nio.file.*;
import java.io.*;

public class ContinuousMonitor {

    private static final String LOG_FILE = "log.txt";

    public static void main(String[] args) throws InterruptedException {
        while (true) {
            update();
            Thread.sleep(5000); // 5-second delay between each check.
        }
    }    

    public static void update() {
        System.out.println("Checking for threats...");

        try {
            List<String> logs = Files.readAllLines(Paths.get(LOG_FILE));

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
            System.out.println("Error reading log file: " + e.getMessage());
        }
    }

    // Using the logs, we perform checks based on "fake" patterns. 

    public static int checkBuffer(List<String> logs) {
        return logs.contains("BUFFER_ATTACK_PATTERN") ? 0 : 1;
    }

    public static int checkLibc(List<String> logs) {
        return logs.contains("LIBC_ATTACK_PATTERN") ? 0 : 1;
    }

    public static int checkStringFormat(List<String> logs) {
        return logs.contains("STRING_FORMAT_ATTACK_PATTERN") ? 0 : 1;
    }

    public static int checkHeap(List<String> logs) {
        return logs.contains("HEAP_ATTACK_PATTERN") ? 0 : 1;
    }

    public static int checkShellshock(List<String> logs) {
        return logs.contains("SHELLSHOCK_ATTACK_PATTERN") ? 0 : 1;
    }

    public static int checkRaceCondition(List<String> logs) {
        return logs.contains("RACE_CONDITION_PATTERN") ? 0 : 1;
    }

    public static int checkWebAttack(List<String> logs) {
        return logs.contains("WEB_ATTACK_PATTERN") ? 0 : 1;
    }

    public static int checkSQL(List<String> logs) {
        return logs.contains("SQL_INJECTION_PATTERN") ? 0 : 1;
    }
}
