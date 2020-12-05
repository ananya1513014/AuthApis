package com.bmk.auth.util;

public class StringUtil {

    public static boolean equals(String str1, String str2) {
        return str1==null&&str2==null?true:str1==null||str2==null?false:str1.equals(str2);
    }

    public static boolean contains(String str1, String str2) {
        if(str1==null&&str2==null)
            return true;
        if(str1==null||str2==null)
            return false;
        return str1.contains(str2);
    }
}
