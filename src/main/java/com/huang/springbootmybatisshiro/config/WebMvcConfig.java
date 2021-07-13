package com.huang.springbootmybatisshiro.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * @Author: Zhiyu
 * @Date: 2021/7/12 16:37
 * @Description:
 */
@Configuration
public class WebMvcConfig implements WebMvcConfigurer {

    // 这里配置一些无逻辑处理的页面请求
    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        /**
         * registry.addViewController("/add").setViewName("add");
         * 的意识等价于 在controller 层的
         *     @RequestMapping("/add")
         *     public String add() {
         *         return "add"; // 跳转到 add.html 页面
         *     }
         *
         *
         *  所以registry.addViewController("/add").setViewName("add");
         *  意思是：访问 /add 就会跳转到 add.html 页面
         *  下面的以此类推
         *
         */
        registry.addViewController("/add").setViewName("add");
        registry.addViewController("/delete").setViewName("delete");
        registry.addViewController("/query").setViewName("query");
        registry.addViewController("/toLogin").setViewName("login");
        registry.addViewController("/").setViewName("login");
        registry.addViewController("/unauthorized").setViewName("unauthorized");
        registry.addViewController("/index").setViewName("index");
        registry.addViewController("/test").setViewName("test");
    }
}
