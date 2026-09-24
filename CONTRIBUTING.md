# Contributing to CleanIP

Thanks for considering a contribution! 🎉

## Quick Start

```bash
git clone https://github.com/khademdev/cleanip.git
cd cleanip
make build
```

## Ways to Contribute

- 🐛 **Report bugs** — open an issue
- 💡 **Suggest features** — use the feature template
- 📝 **Improve docs** — fix typos, clarify wording
- 🌍 **Translate** — add a language to the UI
- 🧪 **Test** — try new presets, report edge cases
- 💻 **Code** — submit a pull request

## Pull Request Workflow

1. **Fork** the repository
2. **Create a branch**: `git checkout -b feat/your-feature`
3. **Make your changes**
4. **Verify locally**:
   ```bash
   gofmt -l .
   go vet ./...
   go build -trimpath -ldflags="-s -w" -o /tmp/cleanip .
   ```
5. **Test the UI** in both languages (fa / en) and on mobile (700px / 480px / 360px)
6. **Open a PR** with a clear description

## Code Style

### Go
- `gofmt` defaults
- Prefer standard library over third-party packages
- Keep functions small and focused
- Handle errors explicitly

### HTML / CSS / JavaScript
- Everything self-contained (no external CDNs except Vazirmatn)
- Every user-facing string needs a key in **both** `I18N.fa` and `I18N.en`
- Keep the mobile layout working

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add Shadowsocks 2022 support
fix: prevent panic on empty config
docs: clarify ECH setup in README
style: gofmt all files
refactor: extract SNI resolver
test: add parseURI table tests
chore: bump Go version to 1.22
```

## Good First Issues

Look for issues labeled [`good first issue`](../../labels/good%20first%20issue) — these are beginner-friendly and a great place to start.

## Need Help?

Open an issue with the `question` label, or reach out to the maintainer.

---

**Maintainer:** Meysam Khademshams ([@khademdev](https://github.com/khademdev))
