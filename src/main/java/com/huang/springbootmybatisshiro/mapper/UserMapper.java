package com.huang.springbootmybatisshiro.mapper;

import com.huang.springbootmybatisshiro.entity.User;
import org.apache.ibatis.annotations.Param;

/**
 * @Author: Zhiyu
 * @Date: 2021/7/12 21:43
 * @Description:
 */
public interface UserMapper {

    /**
     * 根据 Username 查询单条数据
     *
     * @param username
     * @return
     */
    User queryByUsername(@Param("username") String username);

}
