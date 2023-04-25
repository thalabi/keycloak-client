package com.kerneldc.keycloakclient.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class CorsConfig implements WebMvcConfigurer {

    @Value("${application.security.corsFilter.corsUrlsToAllow}")
    private String[] corsUrlsToAllow;

    @Value("${application.security.corsFilter.corsMaxAgeInSecs:3600}")
    private long corsMaxAgeInSecs;

    // configure application
    @Override
    public void addCorsMappings(CorsRegistry corsRegistry) {
    	configCorsRegistry(corsRegistry);
    }
        
    private void configCorsRegistry(CorsRegistry corsRegistry) {
		corsRegistry.addMapping("/**").allowedOrigins(corsUrlsToAllow).maxAge(corsMaxAgeInSecs)
		.allowedMethods("GET", "HEAD", "POST", "DELETE") // by default GET, HEAD, and POST are allowed
		//.allowedHeaders("Content-Disposition").exposedHeaders("Content-Disposition")
		.allowedHeaders("*").exposedHeaders("*")
		;
    }
}
