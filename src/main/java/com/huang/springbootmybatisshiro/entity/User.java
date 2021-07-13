package com.huang.springbootmybatisshiro.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

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
