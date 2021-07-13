> 初衷：我在网上想找整合springboot+mybatis+shiro并且多角色认证的博客，发现找了好久也没有找到想到的，现在自己会了，就打算写个博客分享出去,希望能帮到你。
> 原创不易，请点赞支持！

>
>该项目不会将过多基础，直接实战，比较使用于有一点基础的， 并且想整合springboot+mybatis+shiro的朋友们。

[TOC]



## 1、了解需求

### 1.1、了解页面

==登录页面如下==

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210713124216307.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80MzczMjY5OQ==,size_16,color_FFFFFF,t_70#pic_center)


==首页页面如下==

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210713124255181.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80MzczMjY5OQ==,size_16,color_FFFFFF,t_70#pic_center)



==分别点击添加、删除、查询、测试超链接，展示的内容如下==
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210713124326379.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80MzczMjY5OQ==,size_16,color_FFFFFF,t_70#pic_center)



### 1.2、需求

+ 首页页面必须登录成功之后才能访问
+ 所有用户、游客等都可访问登录页面、测试页面，无需登录
+ 拥有 root 角色的用户可以访问所有页面，包括添加页面、删除页面、查询页面、测试页面等
+ 拥有admin 角色的用户可以访问添加页面，查询页面、测试页面，除了删除页面不能访问
+ 拥有 user 角色的用户可以访问 查询页面、测试页面，除了添加页面、删除页面不能访问

## 2、准备数据库环境

新建一个`test`数据库,创建两个表（role、user）并插入数据，sql 如下

```sql
/*
 Navicat Premium Data Transfer

 Source Server         : LocalHost
 Source Server Type    : MySQL
 Source Server Version : 50731
 Source Host           : localhost:3306
 Source Schema         : test

 Target Server Type    : MySQL
 Target Server Version : 50731
 File Encoding         : 65001

 Date: 12/07/2021 21:08:51
*/

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for role
-- ----------------------------
DROP TABLE IF EXISTS `role`;
CREATE TABLE `role`  (
  `id` int(2) NOT NULL AUTO_INCREMENT,
  `name` varchar(100) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `remark` varchar(255) CHARACTER SET utf8 COLLATE utf8_unicode_ci NULL DEFAULT NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 4 CHARACTER SET = utf8 COLLATE = utf8_unicode_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of role
-- ----------------------------
INSERT INTO `role` VALUES (1, 'root', '超级管理员');
INSERT INTO `role` VALUES (2, 'admin', '管理员');
INSERT INTO `role` VALUES (3, 'user', '普通用户');

-- ----------------------------
-- Table structure for user
-- ----------------------------
DROP TABLE IF EXISTS `user`;
CREATE TABLE `user`  (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `username` varchar(100) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `password` varchar(255) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `role_id` int(3) NOT NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 5 CHARACTER SET = utf8 COLLATE = utf8_unicode_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of user
-- ----------------------------
INSERT INTO `user` VALUES (1, 'rootA', '123456', 1);
INSERT INTO `user` VALUES (2, 'adminA', '123456', 2);
INSERT INTO `user` VALUES (3, 'userA', '123456', 3);
INSERT INTO `user` VALUES (4, 'userB', '123456', 3);

SET FOREIGN_KEY_CHECKS = 1;
```

role 表数据如下：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210713124357352.png#pic_center)


user 表数据如下：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210713124426278.png#pic_center)





## 3、编写代码

### 3.1、新建SpringBoot 工程项目

![在这里插入图片描述](https://img-blog.csdnimg.cn/2021071312450297.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80MzczMjY5OQ==,size_16,color_FFFFFF,t_70#pic_center)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210713124523647.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80MzczMjY5OQ==,size_16,color_FFFFFF,t_70#pic_center)



### 3.2、添加如下依赖

> 全部依赖如下

```xml
<!-- thymeleaf -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-thymeleaf</artifactId>
</dependency>
<!-- web -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
</dependency>
<!-- mysql-->
<dependency>
    <groupId>mysql</groupId>
    <artifactId>mysql-connector-java</artifactId>
</dependency>
<!--mybatis-->
<dependency>
    <groupId>org.mybatis.spring.boot</groupId>
    <artifactId>mybatis-spring-boot-starter</artifactId>
    <version>2.2.0</version>
</dependency>
<!-- Spring对Shiro支持 -->
<dependency>
    <groupId>org.apache.shiro</groupId>
    <artifactId>shiro-spring</artifactId>
    <version>1.7.1</version>
</dependency>
<!--test单元测试-->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-test</artifactId>
    <scope>test</scope>
</dependency>

<dependency>
    <groupId>org.projectlombok</groupId>
    <artifactId>lombok</artifactId>
    <version>1.16.14</version>
</dependency>
```

### 3.3、编写代码连接数据库并测试

#### 3.3.1、配置数据库信息 

> 把 application.properties 文件修改成 application.yml，并添加如下内容 

```yaml
spring:
  datasource:
    username: root 
    password: 123456 
    url: jdbc:mysql://localhost:3306/test
# 打印sql语句
logging:
  level:
    com:
      huang:
        shiro1:
          mapper: debug

```

#### 3.3.2、编写实体类 entity

> 新建一个entity 包，分别添加下面两个实体类

User.java

```java
package com.huang.springbootmybatisshiro.entity;
import lombok.Data;
import java.io.Serializable;
/**
 * (User)实体类
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class User implements Serializable {
    private static final long serialVersionUID = 227751358530931042L;

    private Integer id;

    private String username;

    private String password;

    private Integer roleId;

    private Role role;
}
```



Role.java

```java
package com.huang.springbootmybatisshiro.entity;
import lombok.Data;
import java.io.Serializable;
/**
 * (Role)实体类
 */
@Data
public class Role implements Serializable {
    private static final long serialVersionUID = -76407922564857637L;

    private Integer id;

    private String name;

    private String remark;

}
```

#### 3.3.3、mapper

> 新建一个 mapper 包，分别创建下面两个文件

UserMapper.java

```java
public interface UserMapper {

    /**
     * 根据 Username 查询单条数据
     *
     * @param username
     * @return
     */
    User queryByUsername(@Param("username") String username);

}
```



UserMapper.xml

```xml
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.huang.springbootmybatisshiro.mapper.UserMapper">

    <resultMap type="com.huang.springbootmybatisshiro.entity.User" id="UserMap">
        <result property="id" column="id" jdbcType="INTEGER"/>
        <result property="username" column="username" jdbcType="VARCHAR"/>
        <result property="password" column="password" jdbcType="VARCHAR"/>
        <result property="roleId" column="role_id" jdbcType="INTEGER"/>
    </resultMap>

    <resultMap id="UserMapWithRole" type="com.huang.springbootmybatisshiro.entity.User" extends="UserMap">
        <collection property="role" ofType="com.huang.springbootmybatisshiro.entity.Role">
            <id property="id" column="rid"></id>
            <result property="name" column="rname"></result>
            <result property="remark" column="rremark"></result>
        </collection>
    </resultMap>


    <select id="queryByUsername" resultMap="UserMapWithRole">
        select
        u.*,r.id rid,r.name rname,r.remark rremark
        from test.user u,test.role r
        where u.role_id=r.id
        <if test="username != null and username != ''">
            and username = #{username}
        </if>
    </select>

</mapper>
```



==注意：==

> UserMapper.xml 和UserMapper.java 文件写在同一目录下，需在pom.xml文件添加如下内容

```xml
<build>
    <resources>
        <resource>
            <directory>src/main/java</directory>
            <includes>
                <include>**/*.xml</include>
            </includes>
        </resource>
        <resource>
            <directory>src/main/resources</directory>
        </resource>
    </resources>

    <plugins>
        <plugin>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-maven-plugin</artifactId>
        </plugin>
    </plugins>
</build>
```

> 并且在启动类中添加注解@mapperscan 全局扫描 mapper 文件

```java
@SpringBootApplication
@MapperScan(basePackages = "com.huang.springbootmybatisshiro.mapper")
public class SpringbootMybatisShiroApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringbootMybatisShiroApplication.class, args);
    }
}
```

#### 3.3.4、service

> 新建一个包service，并添加 Userservice.java 文件如下

```java
@Service
public class UserService {

    @Autowired
    UserMapper userMapper;

    public User queryByUsername(String username) {
        return userMapper.queryByUsername(username);
    }
}
```

3.3.4 测试是否可以正常获取数据库信息

```java
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
```

> 如果输入如下数据则成功，就可以进行下一步了

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210713124558688.png#pic_center)

### 3.4、编写页面

在resources目录下新建文件夹templates（有就不用了），在templates 下添加如下页面

+ add.html 添加页面
+ delete.html 删除页面
+ index.html 首页页面
+ login.html 登录页面
+ query.html 查询页面
+ test.html 测试页面
+ unauthorized.html 未授权页面

> add.html

```html
<!DOCTYPE html >
<html lang="en" xmlns:th="http://www.thymeleaf.org">
<head>
    <meta charset="UTF-8">
    <title>add</title>
</head>
<body>
<h1>添加页面</h1>
</body>
</html>
```

> delete.html

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>update</title>
</head>
<body>
<h1>删除页面</h1>
</body>
</html>
```

> index.html

```html
<!DOCTYPE html >
<html lang="en" xmlns:th="http://www.thymeleaf.org">
<head>
    <meta charset="UTF-8">
    <title>首页</title>
</head>
<body>
<h1>首页</h1>
进入用户添加页面： <a href="add">添加页面</a><br/>
进入用户删除页面： <a href="delete">删除页面</a><br/>
进入用户查询页面： <a href="query">查询页面</a><br/>
进入用户测试页面： <a href="test">测试页面</a><br/>
</body>
</html>
```

> login.html

```html
<!DOCTYPE html>
<html lang="en" xmlns:th="http://www.thymeleaf.org">
<head>
    <meta charset="UTF-8">
    <title>login</title>
</head>
<body>
<h1>登录页面</h1>
<h3 th:text="${msg}" style="color: red"></h3>
<form action="login" method="post">
    用户名：<input type="text" name="username"><br>
    密码：<input type="text" name="password"><br>
    <input type="submit" value="submit">
</form>
</body>
</html>
```

> query.html

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>query</title>
</head>
<body>
<h1>查询页面</h1>
</body>
</html>
```

> test.html

```html
<!DOCTYPE html >
<html lang="en" xmlns:th="http://www.thymeleaf.org">
<head>
    <meta charset="UTF-8">
    <title>测试页面</title>
</head>
<body>
<h1>测试页面</h1>
</body>
</html>
```

> unauthorized.html。当访问不够权限的页面时会跳转到该页面

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>unauthorized</title>
</head>
<body>
<h1>你未授权，请联系管理员</h1>
</body>
</html>
```

### 3.5、编写 shiro 的有关配置

新建一个config 包，添加以下文件

> CustomRealm.java

```java
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
```

> ShiroConfig.java

```java
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
```



> RoleFilter.java

```java
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
```

### 3.6、编写Controller层代码

> 新建一个controller包，添加 UserController.java 文件，内容如下

```java
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
```

7、编写 WebMvcConfig, 配置无逻辑的访问页面跳转

> 在config 包下新建 WebMvcConfig.java ，代码如下

```java
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
```

> 启动项目进行测试

## 4、测试

> User 表数据如下

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210713124634244.png#pic_center)
#### 4.0、游客访问

> 游客直接在浏览器输入下面的地址

+ `http://localhost:8080/add`
+ `http://localhost:8080/delete` 

+ `http://localhost:8080/query`

都是下面会跳转到登录页面

除了访问`http://localhost:8080/test` 可以正确跳转
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021071312470373.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80MzczMjY5OQ==,size_16,color_FFFFFF,t_70#pic_center)

#### 4.1、测试无用户登录

访问 `http://localhost:8080/`, 输入如下信息

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210713124749163.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80MzczMjY5OQ==,size_16,color_FFFFFF,t_70#pic_center)



点击提交，然后显示的页面如下

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210713124811429.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80MzczMjY5OQ==,size_16,color_FFFFFF,t_70#pic_center)

#### 4.2、测试密码不正确登录

访问 `http://localhost:8080/`, 输入如下信息
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210713124834690.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80MzczMjY5OQ==,size_16,color_FFFFFF,t_70#pic_center)



点击提交，然后显示的页面如下
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210713124902637.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80MzczMjY5OQ==,size_16,color_FFFFFF,t_70#pic_center)

#### 4.3、测试 rootA用户正确登录

访问 `http://localhost:8080/`, 输入如下信息
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210713124945325.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80MzczMjY5OQ==,size_16,color_FFFFFF,t_70#pic_center)

点击提交，然后显示的页面如下

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210713125014703.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80MzczMjY5OQ==,size_16,color_FFFFFF,t_70#pic_center)



分别点击添加、删除、查询、测试页面，分别显示的页面如下

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210713125112872.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80MzczMjY5OQ==,size_16,color_FFFFFF,t_70#pic_center)


> 结果：可以看到全部页面都可以正常访问。



#### 4.4、测试adminA用户正确登录

访问 `http://localhost:8080/`, 输入如下信息
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210713125136888.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80MzczMjY5OQ==,size_16,color_FFFFFF,t_70#pic_center)



点击提交，然后显示的页面如下

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210713125014703.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80MzczMjY5OQ==,size_16,color_FFFFFF,t_70#pic_center)



分别点击添加、删除、查询、测试页面，分别显示的页面如下

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210713125212564.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80MzczMjY5OQ==,size_16,color_FFFFFF,t_70#pic_center)

> 结果：拥有admin 角色的用户可以访问添加页面，查询页面、测试页面，除了删除页面不能访问



#### 4.5、测试userA用户正确登录

访问 `http://localhost:8080/`, 输入如下信息

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210713125241923.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80MzczMjY5OQ==,size_16,color_FFFFFF,t_70#pic_center)



点击提交，然后显示的页面如下

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210713125014703.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80MzczMjY5OQ==,size_16,color_FFFFFF,t_70#pic_center)

分别点击添加、删除、查询、测试页面，分别显示的页面如下
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210713125302892.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80MzczMjY5OQ==,size_16,color_FFFFFF,t_70#pic_center)


> 结果：拥有 user 角色的用户可以访问 查询页面、测试页面，除了添加页面、删除页面不能访问

## 5、结语

+ 该项目不会将过多基础，直接实战，比较使用有一点基础的。
+ 该项目中没有使用密码加密，如果多人浏览并反馈需要，我可以再写篇密码加密认证的
+ 都是原创，希望看到这的能够点个赞支持一些。