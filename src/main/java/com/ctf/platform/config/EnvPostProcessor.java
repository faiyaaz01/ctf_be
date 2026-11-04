package com.ctf.platform.config;

import io.github.cdimascio.dotenv.Dotenv;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;

import java.io.File;
import java.util.HashMap;
import java.util.Map;

/**
 * Automatically loads .env file variables into Spring Environment
 * if a .env file exists in the project root or current working directory.
 */
public class EnvPostProcessor implements EnvironmentPostProcessor {

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
        File envFile = new File(".env");
        if (envFile.exists()) {
            Dotenv dotenv = Dotenv.configure().ignoreIfMissing().load();
            Map<String, Object> envMap = new HashMap<>();
            dotenv.entries().forEach(entry -> envMap.put(entry.getKey(), entry.getValue()));
            environment.getPropertySources().addFirst(new MapPropertySource("dotenvProperties", envMap));
        }
    }
}
