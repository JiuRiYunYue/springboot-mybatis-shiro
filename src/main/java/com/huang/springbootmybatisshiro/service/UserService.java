package com.huang.springbootmybatisshiro.service;

import com.huang.springbootmybatisshiro.entity.User;
import com.huang.springbootmybatisshiro.mapper.UserMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * @Author: Zhiyu
 * @Date: 2021/7/12 21:59
 * @Description:
 */
@Service
public class UserService {

    @Autowired
    UserMapper userMapper;

    public User queryByUsername(String username) {
        return userMapper.queryByUsername(username);
    }
}
