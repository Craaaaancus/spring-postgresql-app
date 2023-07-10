package com.spring.jpa.postgresql.repository;

import com.spring.jpa.postgresql.model.Game;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface GameRepository extends JpaRepository<Game, Long> {
    List<Game> findByTitle(String title);
}
