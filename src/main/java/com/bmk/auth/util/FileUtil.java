package com.bmk.auth.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;

public class FileUtil {

    private static final Logger logger = LoggerFactory.getLogger(FileUtil.class);

    public static String readFile(String fileName) throws IOException {
        logger.info("Read file", fileName);
        BufferedReader reader = new BufferedReader(new FileReader(new File(fileName)));

        String fileData="", st;

        while((st=reader.readLine())!=null) {
            fileData = fileData + (st);
        }

        logger.info("File read success");
        return fileData;
    }

    public static void writeFile(String fileName, InputStream inputStream) throws IOException {
        logger.info("Writing to file", fileName);
        DataInputStream dis = new DataInputStream(inputStream);
        byte[] buffer = new byte[new DataInputStream(inputStream).available()];
        dis.read(buffer);
        File targetFile = new File(fileName);
        OutputStream outputStream = new FileOutputStream(targetFile);
        outputStream.write(buffer);
        inputStream.close();
        dis.close();
        outputStream.close();
        logger.info("File write successfull");
    }
}