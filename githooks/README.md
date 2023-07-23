# How to setup Hooks

1 - Create a new file named `.git/hooks/pre-commit` or `.git/hooks/pre-push`.

```bash
touch .git/hooks/pre-commit
touch .git/hooks/pre-push
```

2 - This file will be at the directory `.git/hooks/pre-commit{push}`.
3 - Make the file executable: `chmod +x .git/hooks/pre-commit{push}`.
4 - Copy the contents from `githooks/pre-commit{push}` to those files.

```bash
cp githooks/pre-commit .git/hooks/pre-commit
cp githooks/pre-push .git/hooks/pre-push
```
