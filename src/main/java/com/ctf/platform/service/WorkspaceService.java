package com.ctf.platform.service;

import com.ctf.platform.model.FlagCandidate;
import com.ctf.platform.model.Note;
import com.ctf.platform.model.User;
import com.ctf.platform.repository.FlagCandidateRepository;
import com.ctf.platform.repository.NoteRepository;
import com.ctf.platform.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class WorkspaceService {

    private final NoteRepository noteRepository;
    private final FlagCandidateRepository flagCandidateRepository;
    private final UserRepository userRepository;

    private String getUserId(String username) {
        return userRepository.findByUsername(username)
                .map(User::getId)
                .orElseThrow(() -> new RuntimeException("User not found: " + username));
    }

    // ── NOTES ────────────────────────────────────────────────────────
    public List<Note> getNotes(String username) {
        return noteRepository.findByUserIdOrderByPinnedDescUpdatedAtDesc(getUserId(username));
    }

    public Note saveNote(String username, Note note) {
        String uid = getUserId(username);
        note.setUserId(uid);
        return noteRepository.save(note);
    }

    public void deleteNote(String username, String noteId) {
        String uid = getUserId(username);
        noteRepository.findById(noteId).ifPresent(n -> {
            if (uid.equals(n.getUserId())) {
                noteRepository.deleteById(noteId);
            }
        });
    }

    // ── FLAG CANDIDATES (FLAG HUNTER) ────────────────────────────────
    public List<FlagCandidate> getFlagCandidates(String username) {
        return flagCandidateRepository.findByUserIdOrderByUpdatedAtDesc(getUserId(username));
    }

    public FlagCandidate addOrUpdateFlagCandidate(String username, FlagCandidate candidate) {
        String uid = getUserId(username);
        candidate.setUserId(uid);

        return flagCandidateRepository.findByUserIdAndValue(uid, candidate.getValue())
                .map(existing -> {
                    if (!existing.getSources().contains(candidate.getSourceTool())) {
                        existing.getSources().add(candidate.getSourceTool());
                    }
                    return flagCandidateRepository.save(existing);
                })
                .orElseGet(() -> {
                    if (candidate.getSources().isEmpty() && candidate.getSourceTool() != null) {
                        candidate.getSources().add(candidate.getSourceTool());
                    }
                    return flagCandidateRepository.save(candidate);
                });
    }

    public void clearFlags(String username) {
        flagCandidateRepository.deleteByUserId(getUserId(username));
    }
}
