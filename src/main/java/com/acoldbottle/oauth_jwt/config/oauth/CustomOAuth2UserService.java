package com.acoldbottle.oauth_jwt.config.oauth;

import com.acoldbottle.oauth_jwt.config.oauth.dto.CustomOAuth2User;
import com.acoldbottle.oauth_jwt.config.oauth.dto.UserDTO;
import com.acoldbottle.oauth_jwt.config.oauth.response.GoogleResponse;
import com.acoldbottle.oauth_jwt.config.oauth.response.NaverResponse;
import com.acoldbottle.oauth_jwt.config.oauth.response.OAuth2Response;
import com.acoldbottle.oauth_jwt.domain.UserEntity;
import com.acoldbottle.oauth_jwt.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    public CustomOAuth2UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        OAuth2User oAuth2User = super.loadUser(userRequest);
        log.info("oAuth2User={}", oAuth2User);

        String registrationId = userRequest.getClientRegistration().getRegistrationId();

        OAuth2Response oAuth2Response = null;
        if (registrationId.equals("naver")) {
            oAuth2Response = new NaverResponse(oAuth2User.getAttributes());
        } else if (registrationId.equals("google")) {
            oAuth2Response = new GoogleResponse(oAuth2User.getAttributes());
        } else {

            return null;
        }

        String username = oAuth2Response.getProvider() + "-" + oAuth2Response.getProviderId();
        UserEntity existUser = userRepository.findByUsername(username);
        if (existUser == null) {
            UserEntity userEntity = new UserEntity();
            userEntity.setUsername(username);
            userEntity.setEmail(oAuth2Response.getEmail());
            userEntity.setName(oAuth2Response.getName());
            userEntity.setEmail(oAuth2Response.getEmail());

            userRepository.save(userEntity);

            UserDTO userDTO = new UserDTO();
            userDTO.setUsername(username);
            userDTO.setName(oAuth2Response.getName());
            userDTO.setRole("USER");

            return new CustomOAuth2User(userDTO);
        } else {
            existUser.setEmail(oAuth2Response.getEmail());
            existUser.setName(oAuth2User.getName());

            userRepository.save(existUser);

            UserDTO userDTO = new UserDTO();
            userDTO.setUsername(username);
            userDTO.setName(oAuth2Response.getName());
            userDTO.setRole("USER");

            return new CustomOAuth2User(userDTO);
        }
    }
}
