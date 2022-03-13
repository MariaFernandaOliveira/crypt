package com.criptografando.Crypt.controller;

import com.criptografando.Crypt.model.UserModel;
import com.criptografando.Crypt.repository.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.lang.management.OperatingSystemMXBean;
import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/api/user")
public class UserController {

    private final UserRepository userRepository;
    private final PasswordEncoder encoder;


    public UserController(UserRepository userRepository, PasswordEncoder encoder) {
        this.userRepository = userRepository;
        this.encoder = encoder;
    }
    @GetMapping("/listAll")
    public ResponseEntity<List<UserModel>> listAll(){
        return ResponseEntity.ok(userRepository.findAll());
    }

    @PostMapping("/save")
    public ResponseEntity<UserModel> save(@RequestBody UserModel userModel){
        userModel.setPassword(encoder.encode(userModel.getPassword()));
        return ResponseEntity.ok(userRepository.save(userModel));
    }

    @GetMapping("/validationPassword")
    public ResponseEntity<Boolean> passwordValidation(@RequestParam String login, @RequestParam String password){

        Optional<UserModel> optionalUserModel = userRepository.findByLogin(login);
        if (optionalUserModel.isEmpty()){
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(false);
        }

        UserModel userModel = optionalUserModel.get();
        boolean valid = encoder.matches(password, userModel.getPassword());

        HttpStatus status = (valid)? HttpStatus.OK: HttpStatus.UNAUTHORIZED;
        return ResponseEntity.status(status).body(valid);
    }
}


