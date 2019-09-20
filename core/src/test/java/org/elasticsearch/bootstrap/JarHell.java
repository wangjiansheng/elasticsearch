package org.elasticsearch.bootstrap;

import java.net.URL;
import java.util.Set;

/**
 * Created by wangjs on 2019-09-20.
 */
public class JarHell {
    private JarHell() {}
    public static void checkJarHell() throws Exception {}
    public static void checkJarHell(Set<URL> urls) throws Exception {}
    public static void checkVersionFormat(String targetVersion) {}
    public static void checkJavaVersion(String resource, String targetVersion) {}
     public static URL[] parseClassPath(String classPath) {
        return  new URL[]{};
    }
//    public static Set<URL> parseClassPath(String classPath) {
//        return  new HashSet<>();
//    }
  public static URL[] parseClassPath() {return new URL[]{};}
}
