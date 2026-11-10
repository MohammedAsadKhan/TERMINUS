# TERMINUS contributor instructions

Apply these instructions to all changes in this repository. They capture the instructor's feedback on the October 2 prototype submission and the course's source code delivery instructions.

## Source headers and comments

- Each new maintained code file needs a header with its file name, author, revision date, package version, and specific purpose. When editing a file, check its header and keep the date, version, and purpose accurate. Use the version in `pyproject.toml` and identify the contributor or Team LARP accurately. Git records individual authorship.
- Match the comment syntax and placement of nearby source files. Preserve required first lines such as shebangs and encoding declarations. Edit the source for generated assets and regenerate the output as needed. Preserve the native syntax of formats that do not allow comments, including JSON and lockfiles.
- Explain non-obvious behavior where it matters. Document why checks run in a particular order, what authorization or data boundary a check protects, and how recovery handles ambiguous outcomes. Keep comments current and avoid restating obvious code.

## Design and verification

- Check changes against the latest approved class SRS and SDD. The current baseline is SRS v2.0. Use [the implementation map](docs/IMPLEMENTATION_MAP.md) to find the responsible module and requirement. If a change affects behavior, architecture, entry points, or a requirement's status, update the affected documentation and identify any corresponding SDD or test description updates needed for the class copies.
- Keep claims tied to evidence. Record which results came from fixtures, simulations, a clean local install, or the live lab. Leave gaps open until the corresponding acceptance check passes.
- Run checks appropriate to the change and report the results. For final code delivery, run the backend suite, console build, and release static analysis. Check `git diff --check` and record any remaining findings.

## Final code delivery

- Keep the [installation manual](docs/INSTALLATION.md) and [grader walkthrough](docs/GRADING_GUIDE.md) current when dependencies, startup commands, console entry points, or verification steps change.
- Include the installation manual as Word and PDF alongside the source in `COSC_3370_LARP_Team_Project_Source_Code.zip`. Package the locked dependencies' manifests and the prebuilt console. Exclude local credentials, databases, virtual environments, and installed dependencies.
- Extract the finished ZIP into a fresh folder and follow the manual. Verify dependency installation, startup, health, console assets, local sign-in, and shutdown. Record the commit and the results before calling the delivery ready.
