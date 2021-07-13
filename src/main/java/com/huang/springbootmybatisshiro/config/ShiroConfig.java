package com.huang.springbootmybatisshiro.config;

import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.servlet.Filter;
import java.util.LinkedHashMap;

/**
 * @Author: Zhiyu
 * @Date: 2021/7/13 10:40
 * @Description: shiro 的配置
 * 完成下面三件事
 * 1.创建 ShiroFilterFactoryBean
 * 2.DefaultWebSecurityManager
 * 3.创建Realm并关联
 */
@Configuration
public class ShiroConfig {
    @Bean(name = "customRealm")
    public CustomRealm customRealm() {
        return new CustomRealm();
    }

    @Bean(name = "securityManager")
    public SecurityManager securityManager(CustomRealm customRealm) {
        DefaultWebSecurityManager manager = new DefaultWebSecurityManager();
        manager.setRealm(customRealm);
        return manager;
    }


    /**
     * 过滤器配置
     *
     * @param securityManager
     * @return
     */
    @Bean
    public ShiroFilterFactoryBean shiroFilterFactoryBean(SecurityManager securityManager) {
        ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
        shiroFilterFactoryBean.setSecurityManager(securityManager);
        /**
         *    Shiro内置过滤器，可以实现权限相关的拦截器
         *    常用的过滤器：
         *       anon: 无需认证（登录）可以访问
         *       authc: 必须认证才可以访问
         *       user: 如果使用rememberMe的功能可以直接访问
         *       perms： 该资源必须得到资源权限才可以访问
         *       roles: 该资源必须得到角色权限才可以访问
         */
        // 1. 权限相关的拦截器（什么路径需要什么权限）
        LinkedHashMap<String, String> filterMap = new LinkedHashMap<>();
        filterMap.put("/delete", "roles[root]"); //roles[root] 意思是访问/delete 需要角色 root
        // roles[admin,root]意思是访问/add 需要角色 admin或者root。
        // 如果不配置 RoleFilter，解决多角色and关系，则roles[admin,root]意思就是访问/add 需要 admin和root两个角色同时。
        filterMap.put("/add", "roles[admin,root]");
        // anon，意识是/test、/login / 无需认证（登录）可以访问
        filterMap.put("/test", "anon");
        filterMap.put("/login", "anon");
        filterMap.put("/", "anon");
        // authc 其余的访问都必须认证才可以访问，
        filterMap.put("/*", "authc");
        shiroFilterFactoryBean.setFilterChainDefinitionMap(filterMap);// 添加shiro 权限过滤器




        // 2. 配置自定义 or 角色 认证，把自定义过滤器配置进去即可
        LinkedHashMap<String, Filter> filters = new LinkedHashMap<>();
        filters.put("roles", new RoleFilter());
        shiroFilterFactoryBean.setFilters(filters);

        // 3. 修改默认的登录页面和未授权页面
        // 即访问需要登录有页面时会跳转到 /toLogin 请求
        // 即访问需要不够权限的时候页面时会跳转到 /toLogin 请求
        shiroFilterFactoryBean.setLoginUrl("/unauthorized");// 修改调整的登录页面
        shiroFilterFactoryBean.setUnauthorizedUrl("/unauthorized");// 设置未授权提示页面
        return shiroFilterFactoryBean;
    }
}
