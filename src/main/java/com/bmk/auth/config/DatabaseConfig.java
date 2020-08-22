package com.bmk.auth.config;

import com.bmk.auth.util.Constants;
import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.cloud.aws.core.region.RegionProvider;
import org.springframework.cloud.aws.core.region.StaticRegionProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.sql.DataSource;

@Configuration

public class DatabaseConfig {
    @Bean
    public DataSource awsDataSource() {
        DataSourceBuilder dataSourceBuilder = DataSourceBuilder.create();
        dataSourceBuilder.url(System.getenv(Constants.DB_URL_PARAM_KEY));
        dataSourceBuilder.username(System.getenv(Constants.DB_USER_PARAM_KEY));
        dataSourceBuilder.password(System.getenv(Constants.DB_PASSWORD_PARAM_KEY));
        return dataSourceBuilder.build();
    }

    @Bean
    public RegionProvider regionProvider() {
        return new StaticRegionProvider(System.getenv(Constants.DB_REGION_PARAM_KEY));
    }
}