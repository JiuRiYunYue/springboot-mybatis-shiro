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
