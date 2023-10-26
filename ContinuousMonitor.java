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

    public static int checkBuffer(List<String> logs) {
        for(String log : logs) {
            if(log.contains("BUFFER_ATTACK_PATTERN")) {
                return 0;
            }
        }
        return 1;
    }

    public static int checkLibc(List<String> logs) {
        for(String log : logs) {
            if(log.contains("LIBC_ATTACK_PATTERN")) {
                return 0;
            }
        }
        return 1;
    }

    public static int checkStringFormat(List<String> logs) {
        for(String log : logs) {
            if(log.contains("STRING_FORMAT_ATTACK_PATTERN")) {
                return 0;
            }
        }
        return 1;
    }

    public static int checkHeap(List<String> logs) {
        for(String log : logs) {
            if(log.contains("HEAP_ATTACK_PATTERN")) {
                return 0;
            }
        }
        return 1;
    }

    public static int checkShellshock(List<String> logs) {
        for(String log : logs) {
            if(log.contains("SHELLSHOCK_ATTACK_PATTERN")) {
                return 0;
            }
        }
        return 1;
    }

    public static int checkRaceCondition(List<String> logs) {
        for(String log : logs) {
            if(log.contains("RACE_CONDITION_PATTERN")) {
                return 0;
            }
        }
        return 1;
    }

    public static int checkWebAttack(List<String> logs) {
        for(String log : logs) {
            if(log.contains("WEB_ATTACK_PATTERN")) {
                return 0;
            }
        }
        return 1;
    }

    public static int checkSQL(List<String> logs) {
        for(String log : logs) {
            if(log.contains("SQL_INJECTION_PATTERN")) {
                return 0;
            }
        }
        return 1;
    }
}
