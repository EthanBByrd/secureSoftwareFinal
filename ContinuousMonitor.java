//SSD Project
//CS4612 - 01
//Cameron Cummings, Ethan Byrd, Matthew Fincher

import java.util.*;
import java.lang.*;

public class ContinuousMonitor {
    public static void main(String[] args) {
        //while loop to continuously update/monitor the software
        while(true) {
            update();
        }
    }    

    public static void update() {
        boolean foundWarning = false;
        


        if(foundWarning) {
            System.out.println("Suspicious activity detected, cancelling request.");

        }

    }

    //checks for basic buffer attacks
    public static boolean checkBuffer() {
        boolean alert = false;
        
        //check for attack/vulnerabilities here

        return alert;
    }

    //checks for basic libc attacks
    public static boolean checkLibc() {
        boolean alert = false;
        
        //check for attack/vulnerabilities here

        return alert;
    }

    //check for string format attacks
    public static boolean checkStringFormat() {
        boolean alert = false;
        
        //check for attack/vulnerabilities here

        return alert;
    }

    //check for heap attacks 
    public static boolean checkHeap() {
        boolean alert = false;
        
        //check for attack/vulnerabilities here

        return alert;
    }

    //check for shellshock attacks
    public static boolean checkShellshock() {
        boolean alert = false;
        
        //check for attack/vulnerabilities here

        return alert;
    }

    //check for race condition vulnerabilities
    public static boolean checkRaceCondition() {
        boolean alert = false;
        
        //check for attack/vulnerabilities here

        return alert;
    }

    //check for basic web attacks
    public static boolean checkWebAttack() {
        boolean alert = false;
        
        //check for attack/vulnerabilities here

        return alert;
    }

    //check for SQL injection attacks
    public static boolean checkSQL() {
        boolean alert = false;
        
        //check for attack/vulnerabilities here

        return alert;
    }
}