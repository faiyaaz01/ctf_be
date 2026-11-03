package com.ctf.platform.controller;

import com.ctf.platform.model.FlagCandidate;
import com.ctf.platform.model.Note;
import com.ctf.platform.service.WorkspaceService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/workspace")
@RequiredArgsConstructor
public class WorkspaceController {

    private final WorkspaceService workspaceService;

    // ── NOTES API ──────────────────────────────────────────────────
    @GetMapping("/notes")
    public ResponseEntity<List<Note>> getNotes(@AuthenticationPrincipal UserDetails user) {
        return ResponseEntity.ok(workspaceService.getNotes(user.getUsername()));
    }

    @PostMapping("/notes")
    public ResponseEntity<Note> saveNote(
            @AuthenticationPrincipal UserDetails user,
            @RequestBody Note note) {
        return ResponseEntity.ok(workspaceService.saveNote(user.getUsername(), note));
    }

    @DeleteMapping("/notes/{id}")
    public ResponseEntity<?> deleteNote(
            @AuthenticationPrincipal UserDetails user,
            @PathVariable String id) {
        workspaceService.deleteNote(user.getUsername(), id);
        return ResponseEntity.ok(Map.of("message", "Note deleted successfully"));
    }

    // ── FLAG HUNTER API ────────────────────────────────────────────
    @GetMapping("/flags")
    public ResponseEntity<List<FlagCandidate>> getFlags(@AuthenticationPrincipal UserDetails user) {
        return ResponseEntity.ok(workspaceService.getFlagCandidates(user.getUsername()));
    }

    @PostMapping("/flags")
    public ResponseEntity<FlagCandidate> addFlag(
            @AuthenticationPrincipal UserDetails user,
            @RequestBody FlagCandidate candidate) {
        return ResponseEntity.ok(workspaceService.addOrUpdateFlagCandidate(user.getUsername(), candidate));
    }

    @DeleteMapping("/flags")
    public ResponseEntity<?> clearFlags(@AuthenticationPrincipal UserDetails user) {
        workspaceService.clearFlags(user.getUsername());
        return ResponseEntity.ok(Map.of("message", "Flag candidates cleared"));
    }
}
