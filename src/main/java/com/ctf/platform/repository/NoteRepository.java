package com.ctf.platform.repository;

import com.ctf.platform.model.Note;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface NoteRepository extends MongoRepository<Note, String> {
    List<Note> findByUserIdOrderByPinnedDescUpdatedAtDesc(String userId);
    List<Note> findByUserIdAndCategoryOrderByUpdatedAtDesc(String userId, String category);
}
