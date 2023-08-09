package com.spring.jpa.postgresql.controller;

import com.spring.jpa.postgresql.model.Game;
import com.spring.jpa.postgresql.repository.GameRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@CrossOrigin(origins = {"http://localhost:8081", "http://localhost:8080"})
@RestController
public class GameController {
    @Autowired
    GameRepository gameRepository;

    @GetMapping("/game/{id}")
    @CrossOrigin(origins = "*")
    public ResponseEntity<Game> getGameById(@PathVariable("id") long id){
        Optional<Game> gameData = gameRepository.findById(id);
        if (gameData.isPresent()) {
            return new ResponseEntity<>(gameData.get(), HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }

    @GetMapping("/games")
    @CrossOrigin(origins = "*")
    public ResponseEntity<List<Game>> getAllGames(){
        try {
            List<Game> games = new ArrayList<Game>();
            gameRepository.findAll().forEach(games::add);
            if (games.isEmpty()) {
                return new ResponseEntity<>(HttpStatus.NO_CONTENT);
            }
            return new ResponseEntity<>(games, HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>(null, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}
