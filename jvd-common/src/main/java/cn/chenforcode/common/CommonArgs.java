package cn.chenforcode.common;

import lombok.Data;

import java.util.List;

@Data
public class CommonArgs {
    //公用参数
    private String processPath;
    private String vuln;

    //SQL + XSS参数
    private String mainClass;
    private List<String> entryPoints;
    private String alias = "false";

    //deseri参数
    private String deseriKind;
    private String taint;
    //为true，默认处理本机jdk+传入其他jar
    private String processJDK;
    //为true，默认排除本机jdk，只会分析其他jar
    private String excludeJDK;
    //如果该选项为true，代表默认处理本机jdk
    private String onlyJDK;
    //如果该选项为true，那么将只搜索，不分析
    private String search = "false";

    //np参数，默认的jre路径是run_env/NPV/jre1.6.0_45
    private String jre;

    //npv的参数和其它几个漏洞的方式不太一样，需要把当前的commonArgs重新转换成为args数组形式
    public String[] commonArgsToNPVArgs() {
        String[] npArgs = new String[6];
        npArgs[0] = "-apppath";
        npArgs[1] = this.processPath;
        npArgs[2] = "-mainclass";
        npArgs[3] = this.mainClass;
        npArgs[4] = "-jre";
        npArgs[5] = this.jre;
        return npArgs;
    }
}
