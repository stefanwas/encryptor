package com.stefan.tools;

import java.io.*;

public class FileUtils {
    public static String readKeyFromFile(String path) {
        try (BufferedReader reader = new BufferedReader(new FileReader(new File(path)))) {
            String key = reader.readLine();
            return key;
        } catch (IOException e) {
            throw new RuntimeException("Failed to read key from file: " + path, e);
        }
    }

    public static void writeKeyToFile(String key, String path) {
        try (FileWriter writer =  new FileWriter(new File(path))) {
            writer.write(key);
            writer.flush();
        } catch (IOException e) {
            throw new RuntimeException("Failed to write key to file: " + path, e);
        }
    }
}
