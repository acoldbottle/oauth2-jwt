package com.acoldbottle.oauth_jwt.config.oauth.response;

public interface OAuth2Response {

    String getProvider();

    String getProviderId();

    String getEmail();

    String getName();

    /**
     *      String getProvider();  --> 제공자(google,naver,facebook,,,)
     *
     *     String getProviderId(); --> 제공자에서 발급해주는 아이디(번호)
     *
     *     String getEmail();   --> 사용자 이메일
     *
     *     String getName();    --> 사용자 실명(설정한 이름)
     */
}
