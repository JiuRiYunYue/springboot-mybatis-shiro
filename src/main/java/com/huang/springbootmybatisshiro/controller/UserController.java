package com.huang.springbootmybatisshiro.controller;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.subject.Subject;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PostMapping;

/**
 * @Author: Zhiyu
 * @Date: 2021/7/13 11:21
 * @Description:
 */
@Controller
public class UserController {
    /**
     * 使用 shiro 编写认证(登录)逻辑
     * 1. 获取 Subject
     * 2. 封装用户数据
     * 3. 执行登录方法
     */
    @PostMapping("/login")
    public String login(String username, String password, Model model) {
        System.out.println("username = " + username);
        System.out.println("password = " + password);


        // 1.获取 Subject
        Subject subject = SecurityUtils.getSubject();
        // 2. 封装用户数据
        UsernamePasswordToken token = new UsernamePasswordToken(username, password);
        String msg = "登录成功";
        try {
            // 3. 执行登录方法, 到 CustomRealm 类的doGetAuthenticationInfo中去执行认证逻辑
            subject.login(token);
        } catch (UnknownAccountException uae) {
            msg = "未知账户";
        } catch (IncorrectCredentialsException ice) {
            msg = "密码不正确";
        } catch (LockedAccountException lae) {
            msg = "账户已锁定";
        } catch (ExcessiveAttemptsException eae) {
            msg = "用户名或密码错误次数过多";
        } catch (AuthenticationException ae) {
            msg = "用户名或密码不正确！";
        }
        model.addAttribute("msg", msg);
        if (subject.isAuthenticated()) {
            // 登录成功，跳转到 index.html
            return "redirect:/index";
        } else {
            token.clear();
            return "login";
        }
    }
}
