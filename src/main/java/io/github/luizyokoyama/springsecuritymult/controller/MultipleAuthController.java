package io.github.luizyokoyama.springsecuritymult.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MultipleAuthController {

    @GetMapping("/api/ping")
    public String getPing() {
        return "Meu teste de Autenticação: \n            AUTENTICAÇÃO OK\n\n";
    }
}