package cn.chenforcode.common.util;

import cn.hutool.log.Log;
import cn.hutool.log.LogFactory;

import java.io.File;
import java.util.List;

public class CommonUtil {
    private static final Log log = LogFactory.get(CommonUtil.class);
    public static void getAllFile(List<String> list, String path) {
        File file = new File(path);
        boolean exists = file.exists();
        if (exists) {
            if (file.isFile() && file.getName().endsWith(".jar")) {
                list.add(file.getPath());
            } else if (file.isDirectory()) {
                File[] files = file.listFiles();
                for (File f : files) {
                    getAllFile(list, f.getPath());
                }
            }
        } else {
            log.info("path is not exist");
        }
    }
}
