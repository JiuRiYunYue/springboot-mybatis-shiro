package com.huang.springbootmybatisshiro.config;

import com.huang.springbootmybatisshiro.entity.User;
import com.huang.springbootmybatisshiro.service.UserService;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * @Author: Zhiyu
 * @Date: 2021/7/13 10:40
 * @Description: 主要用于用户数据和shiro的交互工作
 */
public class CustomRealm extends AuthorizingRealm {

    @Autowired
    UserService userService;

    /**
     * 授权：给当前用户授权，以便能访问
     *
     * @param principals
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        // principal 就是下面的方法 doGetAuthenticationInfo 中的return new SimpleAuthenticationInfo(user, user.getPassword(), "") 中的第一个参数 user 赋值的
        User principal = (User) principals.getPrimaryPrincipal();
        System.out.println("principal = " + principal);
        // 给资源进行授权
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        // 授权该用户的本身角色的权限
        info.addRole(principal.getRole().getName());

        return info;
    }

    /**
     * 认证：能不能登录等认证
     *
     * @param authenticationToken
     * @return
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        System.out.println("-------------进入了认证逻辑---------------");

        // token 中存储着 subject.login(token) 中传过来的数据
        UsernamePasswordToken token = (UsernamePasswordToken) authenticationToken;
        String username = token.getUsername();
        // 这里假设，数据库中的 username 字段是唯一字段，可以作为唯一标识，实际开发中可以适当修改，换汤不换药
        // 根据 username 去数据库查询用户信息

        // 数据库查询回来的数据
        User user = userService.queryByUsername(username);
        if (user == null) {
            // 用户名不存在
            // return null;  shiro 底层会抛出UnknowAccountException
            throw new UnknownAccountException();
        }

        // 第一个参数 user: 代表传值,及保存用户的信息，后面会用到
        // 第二个参数 填真正的密码，shiro 会帮我们做密码验证，无需我们自己做密码验证逻辑
        return new SimpleAuthenticationInfo(user, user.getPassword(), "");
    }
}
