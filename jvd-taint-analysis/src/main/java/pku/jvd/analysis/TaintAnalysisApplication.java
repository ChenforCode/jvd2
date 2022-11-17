package pku.jvd.analysis;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class TaintAnalysisApplication {
    public static void main(String[] args) {
        SpringApplication.run(TaintAnalysisApplication.class, args);
    }
}
