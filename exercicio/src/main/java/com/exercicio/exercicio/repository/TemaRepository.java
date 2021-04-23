package com.exercicio.exercicio.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.exercicio.exercicio.model.Tema;

public interface TemaRepository extends JpaRepository<Tema, Long>{
	
	public List<Tema> findAllByDescricaoContainingIgnoreCase(String descricao);

}
