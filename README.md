# SpringSecurityDemo
SpringBoot3 + Spring Security6 实现默认地址/login

![image](https://github.com/user-attachments/assets/d9017ea7-4d3d-4236-9994-947c12e95d2a)




Spring Security 核心技术过滤器。一个web请求会经过一系列的过滤器进行认证授权。
主要是用默认的/login请求，继承UsernamePasswordAuthenticationFilter，来实现用户名和密码登录。


### 核心流程

* UsernamePasswordAuthenticationFilter
* ProviderManager
* DaoAuthenticationProvider
* UserDetailService
* 验证通过，返回Authentication认证
* 最终在认证成功回调中，返回token

### 主要配置

配置Web请求自定义过滤器JwtAuthenticationFilter
配置自定义过滤器JwtAuthenticationFilter的AuthenticationManager
配置AuthenticationManager中的Provider（DaoAuthenticationProvider）

web请求将按照核心流程，进行用户名和密码的认证

```
@Bean
    public AuthenticationManager authenticationManager() throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/login").permitAll()
                        .anyRequest().authenticated()
                )
                .authenticationProvider(authenticationProvider())
                .addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }



    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() throws Exception {
        JwtAuthenticationFilter filter = new JwtAuthenticationFilter();
        filter.setAuthenticationManager(authenticationManager());
        return filter;
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder);
        return authProvider;
    }
```