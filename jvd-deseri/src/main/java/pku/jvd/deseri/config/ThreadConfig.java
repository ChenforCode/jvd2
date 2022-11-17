package pku.jvd.deseri.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.*;

@Configuration
public class ThreadConfig {

    @Bean
    public ExecutorService getThreadPool() {
        ExecutorService executorService = new ThreadPoolExecutor(5,
                9,
                2,
                TimeUnit.MINUTES,
                new ArrayBlockingQueue<>(10, true),
                Executors.defaultThreadFactory(),
                new ThreadPoolExecutor.AbortPolicy());
        return executorService;
    }
}
