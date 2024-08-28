package com.acoldbottle.oauth_jwt.repository;

import com.acoldbottle.oauth_jwt.domain.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserEntity, Long> {

    UserEntity findByUsername(String username);

}
