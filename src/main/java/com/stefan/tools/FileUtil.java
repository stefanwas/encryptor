package com.stefan.tools;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;

import static java.nio.file.StandardOpenOption.CREATE;

public class FileUtil {

    public static void saveToFile(String content, File file) throws IOException {
        Files.write(file.toPath(), content.getBytes(Charset.forName("UTF-8")), CREATE);
    }

    public static String readFromFile(File file) throws IOException {
        String content = String.join("", Files.readAllLines(file.toPath()));
        return content;
    }
}
