package me.rightsflow.auth.controller;

import me.rightsflow.auth.service.JwkService;
import com.nimbusds.jose.jwk.JWKSet;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.UnsupportedEncodingException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequiredArgsConstructor
public class JwksController {

    private final JwkService jwkService;

    @GetMapping("/.well-known/jwks.json")
    public Map<String, Object> keys() {
        JWKSet jwkSet = jwkService.getJWKSet();
        return jwkSet.toJSONObject();
    }


    @GetMapping("/api/test")
    public Map<String, Object> test() {
        HashMap<String, Object> map = new HashMap<>();
        map.put("result", "test");
        return map;
    }

    @GetMapping("/.well-known/base64encode")
    public Map<String, Object> base64Encode(@RequestParam String str) {

        String result = null;
        if (str != null) {
            try {
                result = Base64.getEncoder().encodeToString(str.getBytes("utf-8"));
            } catch (UnsupportedEncodingException e) {
                result = e.getMessage();
            }
        }
        HashMap<String, Object> map = new HashMap<>();
        map.put("result", result);
        return map;
    }
}
