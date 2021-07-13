package com.huang.springbootmybatisshiro.config;

import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authz.RolesAuthorizationFilter;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;

/**
 * @Author: Zhiyu
 * @Date: 2021/7/13 11:08
 * @Description: 重写Shiro自带角色权限过滤器
 * shiro自带的方法同一权限只能分配一个角色，默认所个角色的时候是 and 关系，不是 or 关系
 * 所以重写 重写Shiro自带角色权限过滤器 解决多角色 的时候是 or 关系
 */
public class RoleFilter extends RolesAuthorizationFilter {
    @Override
    public boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue)
            throws IOException {

        final Subject subject = getSubject(request, response);
        final String[] rolesArray = (String[]) mappedValue;

        if (rolesArray == null || rolesArray.length == 0) {
            // 无指定角色时，无需检查，允许访问
            return true;
        }

        for (String roleName : rolesArray) {
            if (subject.hasRole(roleName)) {
                return true;
            }
        }

        return false;
    }
}