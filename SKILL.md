# RustFlow Development Skill

Use this skill when modifying code in the RustFlow repository.

## Coding Style

Keep the code clean, simple, and idiomatic Rust.

Prefer:

- Small, focused changes.
- Existing project patterns and abstractions over introducing new ones.
- Clear names over explanatory comments.
- Simple implementations over unnecessary abstractions.

Do not add comments that merely describe what the code does.

Avoid unrelated refactoring unless it is necessary for the requested change.

## Editing Workflow

After making any code changes:

1. Run:

   ```bash
   make fmt
   ```

2. Check the resulting diff. Formatting may modify files beyond the exact lines edited; make sure all changes are intentional.

3. Run Clippy and verify that the change introduces no Clippy warnings or errors.

   Prefer the repository's existing Makefile target if one exists. Otherwise use the appropriate Cargo command, such as:

   ```bash
   cargo clippy --all-targets --all-features -- -D warnings
   ```

4. If Clippy reports an issue:
   - Fix the underlying issue rather than suppressing the lint.
   - Run `make fmt` again after the fix.
   - Run Clippy again.

5. Run relevant tests for the changed code when available.

## Before Finishing

Before considering a task complete:

- `make fmt` has been run after the final edit.
- There are no Clippy issues.
- Relevant tests pass.
- No unnecessary comments were introduced.
- No unrelated code was changed.
- Review the final diff for accidental or overly broad changes.

If a verification command cannot be run or fails for a reason unrelated to the change, report that explicitly rather than claiming the change is verified.
