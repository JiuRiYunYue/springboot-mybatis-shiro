package com.huang.springbootmybatisshiro;

import com.huang.springbootmybatisshiro.entity.User;
import com.huang.springbootmybatisshiro.service.UserService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class SpringbootMybatisShiroApplicationTests {

    @Autowired
    UserService userService;
    @Test
    void contextLoads() {
        User rootA = userService.queryByUsername("rootA");
        System.out.println("=====================================");
        System.out.println("rootA = " + rootA);
    }

}
