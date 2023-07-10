package com.spring.jpa.postgresql.controller;

import com.spring.jpa.postgresql.model.Game;
import com.spring.jpa.postgresql.repository.GameRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@CrossOrigin(origins = "http://localhost:8080")
@RestController
@RequestMapping("/game")
public class GameController {
    @Autowired
    GameRepository gameRepository;

    @GetMapping("/{id}")
    public ResponseEntity<Game> getGameById(@PathVariable("id") long id){
        Optional<Game> gameData = gameRepository.findById(id);
        if (gameData.isPresent()) {
            return new ResponseEntity<>(gameData.get(), HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }
}
